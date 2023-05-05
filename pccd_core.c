/*
 * $Id: pccd_core.c 1332395 2023-04-26 17:08:22Z gchandraseka $
 *
 * pccd_core.c
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */
/* */
#include <limits.h>
#include <string.h>
#include <sysexits.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <netdb.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include <jnx/aux_types.h>
#include <jnx/libpcep.h>

#include <isc/eventlib.h>
#include <jnx/logging.h>
#include <jnx/jtimers.h>
#include <jnx/bits.h>
#include <jnx/patricia.h>

#define PROTO_UNIX
#include <jnx/librpd/shared.h>
#include <jnx/librpd/lspinfo.h>
#include <jnx/librpd/librpd.h>
#include <jnx/librpd/jnx.h>
#include <jnx/librpd/ipc_rpd.h>
#include <jnx/ns_subagent.h>
#include <jnx/mirror_data_node.h>
#include <arpa/inet.h> /* This needs to be AFTER librpd.h */

#include "pccd_stats.h"
#include "pccd_core.h"
#include "pccd_core_flowspec.h"
#include "pccd_mib.h"
#include "pccd_xmalloc.h"
#include "pccd_config.h"
#include "pccd_config_public.h"
#include "pccd_log.h"
#include "pccd_trace.h"
#include "pccd_rpd_ipc.h"
#include "pccd_ret_code.h"
#include "pccd_rpd.h"
#include "pccd_util.h"
#include "pccd_ro.h"
#include "pccd_core_util.h"
#include "pccd_ret_code.h"
#include "pccd_linux_defines.h"
#include "pccd_radix.h"
#include "pccd_mirror.h"


#define PCEP_DEF_TCP_PORT           4189
#define PCEP_DEFAULT_KEEPALIVE      30
#define PCEP_MAX_PCE_RECONNECTS     3 /* Used to help to determine main PCE */
#define PCEP_MAX_DELEG_RETRY        5
#define PCEP_DEF_KEEPALIVE_MIN      1
#define PCEP_DEF_KEEPALIVE_MAX      0
#define PCEP_DEF_DEADTIMER_MAX      0
#define PCEP_NEW_MAIN_SWITCH_TIMER  60
#define MAX_SUM_OF_SIZES_IN_SRV6_SID_STRUCTURE 128
#define PCCD_PLATFORM_MAX_ERO_COUNT 128
/*
 * MAX Groups processed including delete association object is 8
 */
#define PCCD_MAX_DISJOINT_ASSOC_GROUPS 8

#define MAX_METRIC_VALUE 4294967295.0

/* End of PCErr enhancements */

#define PCCD_MAX_LSPS_IN_REPORT 10
#define ONE_MINUTE 60

#define PCEP_SR_SRPAG_ASSOCIATION_MAX_COUNT 1

/**
 * Need to remove below initialisation of pcc_fs_id once speaker id is
 * included in the key.  This is done so that pcc created fs id won't collide
 * with controller created fs id immediately at the beginning although we are
 * checking fs id existence in db after generating one
 */
static uint32_t  pcc_fs_id = 1000;

static time_t            pccd_last_primary_switch;
static evContext         pccd_core_ev_ctx;
static struct pcep      *pccd_pcep;

SLIST_HEAD(pce_cfg_head, pce_cfg_core);
static struct pce_cfg_head           pce_cfg_head;
static patroot                       *pccd_lsp_vector_root_id;

struct pccd_core_rate {
    time_t            *buffer;         /**< ring buffer to store timestamps */
    unsigned          limit;           /**< rate limit set in config */
    unsigned          index;           /**< index of messages ring */
};

struct pccd_core_provisioned_lsps {
    unsigned limit;                   /**< max limit set in config */
    unsigned counter;                 /**< counter for provisioned lsps */
};

static struct pccd_core_rate pccd_message_rate;
static struct pccd_core_rate pccd_update_rate;
static struct pccd_core_provisioned_lsps pccd_provisioned_lsps;

static bool main_pce_locked = 0;
bool rfc8231_compliant = true;
bool multipath_enabled = true;
bool disjoint_association_enabled = false;
bool tls_enable = false;
static bool propagate_maxsegment_list_field = false;

extern uint8_t maximum_srmpls_segment_list_depth;
extern bool propagate_lsp_max_segmentlist_depth;

/* Given POINTER, the address of the given MEMBER in a STRUCT object, returns
   the STRUCT object. */
#define CONTAINER_OF(POINTER, STRUCT, MEMBER) \
        ((STRUCT *) (void *) ((char *) (POINTER) - offsetof(STRUCT, MEMBER)))

/* Forward declarations */

#define PCE_IS_STATEFUL(pce) (\
        (pce)->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL || \
        (pce)->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE)

void
pccd_core_set_rfc8231_compliance (bool val) {
    rfc8231_compliant = val;
}

static void
pccd_core_delegation_setup_timedout(evContext ctx, void *uap, struct timespec due,
                              struct timespec inter);

static void
pccd_core_delegation_retry_timedout(evContext ctx, void *uap, struct timespec due,
                              struct timespec inter);


static int
pccd_core_report_lsp(struct pce_cfg_core *pce,
                     const struct pccd_rpd_lsp_info *rpd_lsp, bool last,
                     bool send_symb_name, uint32_t srp_id,
                     LeafType leaftype, bool fragment);

static int
pccd_core_report_deleted_p2mp_lsp(struct pce_cfg_core *pce,
    const struct pccd_p2mp_lsp_info *p2mp_lsp, uint32_t srp_id);

static void
pccd_core_pce_clear_lsp_delegations(struct pce_cfg_core *pce);

extern boolean pccd_nsr_master(void);
extern int get_conn_fd(struct pcep_conn *conn);
extern uint8_t pcep_get_local_msd (struct pcep_conn *conn);
extern uint16_t pcep_get_remote_max_segment_list (struct pcep_conn *conn);

const char *
pccd_core_get_msg_trigger_string (u_int32_t msg_trigger_reason);

static void
pccd_core_update_pcreport_reason (const struct pccd_rpd_lsp_info *rpd_lsp);

static bool
pccd_send_error_with_srp (struct pcep_conn *conn, uint32_t srp_id,
                          uint8_t err_type, uint8_t err_value);

static bool
pccd_core_delete_all_provisioned_lsps_for_pce (struct pce_cfg_core *pce);

/* NSR Begin */
static void
pccd_core_lsp_cleanup_timer_cb(evContext ctx UNUSED, void *uap,
                                    struct timespec due UNUSED,
                                    struct timespec inter UNUSED);

void
pccd_core_return_control(const struct pccd_rpd_lsp_info *rpd_lsp);

void
pccd_core_rpd_extctrl_lcs_info_cleanup (rpd_extctrl_lsp_config_status_info_t *lcs_info,
                                        unsigned int start_index, unsigned int last_index);
/* NSR End */

void
pccd_set_multipath_capability (bool value)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;
    struct pcep_connect_parameters *params = NULL;

    TRACE_FUNCTION_ENTRY();
    if (multipath_enabled == value) {
        TRACE_CORE("No change in CLI configuration parameters");
        return;
    }
    if (multipath_enabled) {
        TRACE_CORE("Disabling multipath capability for all sessions");
    } else {
        TRACE_CORE("Enabling multipath capability for all sessions");
    }
    multipath_enabled = value;

    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        params = &pce->pc_params;
        params->local.proposition.multipath_capability = value;
        pce->pc_pce.pce_opts.pco_multipath_capability = value;
        if (!multipath_enabled) {
            params->local.proposition.max_segment_list = 1;
            pce->pc_pce.pce_opts.pco_num_multipaths = 1;
        } else {
            params->local.proposition.max_segment_list = PCCD_PLATFORM_MAX_ERO_COUNT;
            pce->pc_pce.pce_opts.pco_num_multipaths = PCCD_PLATFORM_MAX_ERO_COUNT;
        }
        pccd_core_reload_pce(&pce->pc_pce);
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_set_maxsegment_list_propagation (bool value)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;

    TRACE_FUNCTION_ENTRY();
    if (propagate_maxsegment_list_field == value) {
        TRACE_CORE("No change in CLI configuration parameters");
        return;
    }
    if (propagate_maxsegment_list_field) {
        TRACE_CORE("Disabling propagate max-segments for all sessions");
    } else {
        TRACE_CORE("Enabling propagate max-segments for all sessions");
    }
    propagate_maxsegment_list_field = value;

    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        pccd_core_reload_pce(&pce->pc_pce);
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_set_disjoint_assoc_capability (bool value)
{
    struct pce_cfg_core            *pce = NULL;
    struct pce_cfg_core            *tmp = NULL;
    struct pcep_connect_parameters *params = NULL;

    TRACE_FUNCTION_ENTRY();
    if (disjoint_association_enabled == value) {
        TRACE_CORE("No change in Disjoint Association CLI configuration parameters");
        TRACE_FUNCTION_RETURN();
    }
    if (disjoint_association_enabled) {
        TRACE_CORE("Disabling disjoint association capability for all sessions");
    } else {
        TRACE_CORE("Enabling disjoint association capability for all sessions");
    }
    disjoint_association_enabled = value;

    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        params = &pce->pc_params;
        params->local.proposition.disjoint_assoc_capability = value;
        pce->pc_pce.pce_opts.pco_disjoint_assoc_capability = value;
        pccd_core_reload_pce(&pce->pc_pce);
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_set_tls_enable (bool value)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;
    struct pcep_connect_parameters *params = NULL;

    TRACE_FUNCTION_ENTRY();
    if (tls_enable == value) {
        TRACE_CORE("PCEPS: No change in CLI configuration parameters");
        return;
    }
    if (tls_enable) {
       TRACE_CORE("PCEPS: Disabling TLS for all sessions");
    } else {
        TRACE_CORE("PCEPS: Enabling TLS for all sessions");
    }
    tls_enable = value;

    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        TRACE_CORE("PCEPS: Iterating through all sessions");
        params = &pce->pc_params;
        params->local.tls_enable = value;
        pccd_core_reload_pce(&pce->pc_pce);
    }
    TRACE_FUNCTION_EXIT();
}

/* Check if particular bit is set in value field */
bool
is_bit_set(unsigned value, unsigned bit_index)
{
    return (value & (1 << bit_index)) != 0;
}

/**
 * pccd_core_find_next_srp
 *
 * Finds next SRP object index if mulitple LSP create/update
 * request comes in a single message
 *
 * @param[in] objs   : PCEP object array
 *            i      : Current index location in object array
 *            count  : Total PCEP objects count in this PCEP message
 *
 * @return  Next SRP object location,
 *          otherwise the last location in object array
 */
static unsigned
pccd_core_find_next_srp (const struct pcep_object *objs, unsigned i, size_t count)
{
    while ((i < count) && (objs[i].type != PCEP_OBJ_SRP)) {
        i++;
        if (i >= count) {
            return i;
        }
    }

    return i;
}

static bool
pccd_ro_validate_entry(const ro_entry *entry)
{
    bool ro_entry_valid = false;

    switch (entry->type & 0x7f) {
       case RO_TYPE_IPV4:
           ro_entry_valid = TRUE;
           break;

       case RO_TYPE_UNNUM:
           ro_entry_valid = TRUE;
           break;

       case RO_LABEL:
           ro_entry_valid = TRUE;
           break;

       default:
           break;
    }
    return ro_entry_valid;
}

/* NSR Begin */
/**
 * Free memory occupied for info
 */
void
pccd_core_rpd_extctrl_lcs_info_cleanup (rpd_extctrl_lsp_config_status_info_t *lcs_info,
                                        unsigned int start_index, unsigned int last_index)
{
    unsigned int i = 0;
    rpd_extctrl_lsp_config_status_info_t *info = NULL;

    for (i = start_index; i <= last_index; i++) {
        info = &lcs_info[i];
        pccd_rpd_extctrl_lcs_info_cleanup(info);
    }
}
/* NSR End */

/* Clear delegation_timeout timer */
static void
pccd_core_pce_clear_delegation_cleanup_timer(struct pce_cfg_core *pce)
{
    TRACE_FUNCTION_ENTRY();
    if (evTestID(pce->pc_delegation_cleanup_tid)) {
        evClearTimer(pccd_core_ev_ctx, pce->pc_delegation_cleanup_tid);
        evInitID(&pce->pc_delegation_cleanup_tid);
    }
    TRACE_FUNCTION_EXIT();
}

/**
 * pccd_core_pce_set_delegation_timeout callback function. Return LSP control to RPD
*/
static void
pccd_core_pce_delegation_cleanup_timer_cb(evContext ctx UNUSED, void *uap,
                                          struct timespec due UNUSED,
                                          struct timespec inter UNUSED)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    pce = uap;
    pccd_core_pce_clear_delegation_cleanup_timer(pce);
    if (pce->pc_main == true) {
        TRACE_CORE("PCE '%s' is returning control to RPD", pce->pc_pce.pce_id);
        pccd_core_pce_clear_lsp_delegations(pce);
        if (!pccd_rpd_lsp_return_control_all()) {
            LOGGING_WAR("Failed to return external controller status for "
                "all LSPs");
        }
    }
    TRACE_FUNCTION_EXIT();
}

/* Start delegation_cleanup_timeout timer */
void
pccd_core_pce_set_delegation_cleanup_timer(struct pce_cfg_core *pce)
{
    TRACE_FUNCTION_ENTRY();

    /* NSR Begin */
    if (!pccd_nsr_master())
        TRACE_FUNCTION_RETURN();

    if (!pccd_core_pce_ismain(pce))
        TRACE_FUNCTION_RETURN();
    /* NSR End */

    if (!evTestID(pce->pc_delegation_cleanup_tid)) {
        if (pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout > 0) {
            if (evSetTimer(pccd_core_ev_ctx, pccd_core_pce_delegation_cleanup_timer_cb,
                           pce, evAddTime(evNowTime(),
                           evConsTime(pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout, 0)),
                           evConsTime(0,0), &pce->pc_delegation_cleanup_tid) == -1) {
                LOGGING_ERR("evSetTimer failed");
                exit(EX_SOFTWARE);
            }
            TRACE_CORE("Delegation cleanup timer set %d [s]",
                pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout);
        } else {
            /*
             * Zero delegation-cleanup-timer means PCC needs to take
             * the control from PCE immediately.
             */
            if (pce->pc_main == true) {
                TRACE_CORE("PCE '%s' is returning control to RPD", pce->pc_pce.pce_id);
                pccd_core_pce_clear_lsp_delegations(pce);
                if (!pccd_rpd_lsp_return_control_all()) {
                    LOGGING_WAR("Failed to return external controller status for "
                                "all LSPs");
                }
            }
        }
    }
    TRACE_FUNCTION_EXIT();
}

/**
 * Clear the delegation_tid timer associated with the lsp
 * @param lsp[in] LSP to delete the delegation_tid from.
 */
static void
pccd_core_clear_lsp_delegation_tid(struct lsp_vector *lsp)
{
    INSIST_ERR(lsp != NULL);

    if (!pccd_nsr_master())
        return;

    lsp->lv_want_to_delegate = false;
    lsp->lv_ack_delegated = false;
    lsp->lv_delegation_failed = 0;
    if (evTestID(lsp->lv_delegation_setup_tid)) {
        evClearTimer(pccd_core_ev_ctx, lsp->lv_delegation_setup_tid);
        evInitID(&lsp->lv_delegation_setup_tid);
        TRACE_CORE("Stopped delegation setup timer for LSP id: %u",
                   lsp->lv_lsp_id);
    }
}

/**
 * Clear the lsp delegation retry timer associated with the lsp
 */
static void
pccd_core_clear_lsp_delegation_retry_tid(struct lsp_vector *lsp)
{
    INSIST_ERR(lsp != NULL);

    lsp->lv_retry_delegation = false;

    if (evTestID(lsp->lv_lsp_delegation_retry_tid)) {
        evClearTimer(pccd_core_ev_ctx, lsp->lv_lsp_delegation_retry_tid);
        evInitID(&lsp->lv_lsp_delegation_retry_tid);
        TRACE_CORE("Stopped delegation retry timer for LSP id: %u",
                   lsp->lv_lsp_id);
    }
}

/**
 * Clear the msg_fragment_tid timer associated with the p2mp lsp
 * @param p2mp_lsp[in] P2mp LSP to delete the msg_fragment_tid from.
 */
void
pccd_core_p2mp_lsp_clear_frag_tid(struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    /* Clear lsp fragmentation timer */
    if (evTestID(p2mp_lsp->msg_fragment_tid)) {
        evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
        evInitID(&p2mp_lsp->msg_fragment_tid);
        TRACE_CORE("Stopped lsp fragmentation timer for P2mp LSP: %s",
                                                                           p2mp_lsp->p2mp_name);
    }
}

/* NSR Begin */
void
pccd_core_provisioned_lsps_decrease_counter(void)
{
    if (pccd_provisioned_lsps.counter > 0) {
        pccd_provisioned_lsps.counter--;
        TRACE_CORE("Provisioned LSPs counter decreased: %d", pccd_provisioned_lsps.counter);
    }
}

void
pccd_core_provisioned_lsps_increase_counter(void)
{
    pccd_provisioned_lsps.counter++;
    TRACE_CORE("Provisioned LSPs counter increased: %d", pccd_provisioned_lsps.counter);
}

/**
 * start lsp cleanup timer for PCE initiated lsp
 * @param pce[in] pce controller from which this lsp is initiated
 * @param lsp[in] pce initiated lsp
 */
static void
pccd_core_start_lsp_cleanup_tid (struct pce_cfg_core *pce, struct lsp_vector *lsp)
{
    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(pce != NULL);
    INSIST_ERR(lsp != NULL);
    struct pccd_rpd_lsp_info *rpd_lsp = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    if (!pccd_nsr_master()) {
        TRACE_FUNCTION_RETURN();
    }

    if (lsp->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
        p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);
    } else {
        rpd_lsp = pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);
    }

    if ((NULL == p2mp_lsp) && (NULL == rpd_lsp)) {
        TRACE_FUNCTION_RETURN();
    }

    if (!evTestID(lsp->lv_lsp_cleanup_tid)) {
        /* Start lsp cleanup timer */
        if (evSetTimer(pccd_core_ev_ctx, pccd_core_lsp_cleanup_timer_cb,
                       lsp, evAddTime(evNowTime(),
                       evConsTime((time_t)pce->pc_pce.pce_lsp_cleanup_timer, 0)),
                       evConsTime(0,0), &lsp->lv_lsp_cleanup_tid) == -1) {
            LOGGING_ERR("evSetTimer failed");
            exit(EX_SOFTWARE);
        }

        if (p2mp_lsp) {
            TRACE_CORE("Cleanup timer set for P2MP LSP '%s' with value %d [s]",
                       p2mp_lsp->p2mp_name, pce->pc_pce.pce_lsp_cleanup_timer);
        } else {
            TRACE_CORE("Cleanup timer set for LSP with lsp_name '%s' path_name '%s' \
                with value %d [s]", rpd_lsp->lsp_name, rpd_lsp->path_name,
                pce->pc_pce.pce_lsp_cleanup_timer);
        }
    }

    TRACE_FUNCTION_RETURN();
}
/* NSR End */

static void
pccd_core_clear_lsp_cleanup_tid (struct lsp_vector *lsp)
{
    const struct pccd_rpd_lsp_info *rpd_lsp = NULL;

    INSIST_ERR(lsp != NULL);

    rpd_lsp = pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);

    if (evTestID(lsp->lv_lsp_cleanup_tid)) {
        TRACE_CORE("Cleared lsp cleanup timer for lsp with lsp_name: '%s',path_name: %s ",
			rpd_lsp ? rpd_lsp->lsp_name : "", rpd_lsp ? rpd_lsp->path_name : "");
        evClearTimer(pccd_core_ev_ctx, lsp->lv_lsp_cleanup_tid);
        evInitID(&lsp->lv_lsp_cleanup_tid);
    }
}

void
pccd_core_delete_lsp(struct lsp_vector *lsp)
{
    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(lsp != NULL);

    pccd_core_clear_lsp_delegation_tid(lsp);
    pccd_core_clear_lsp_cleanup_tid(lsp);
    pccd_core_clear_lsp_delegation_retry_tid(lsp);

    /* NSR Begin */
    /* remove all fs replication entries mapped to this lsp */
    pccd_repl_clear_fs_mapped_to_lsp(lsp);
    /* NSR End */
    
    /* Delete flowspec associated with lsp */
    pccd_core_send_lsp_fs_delete(lsp, 0, false);
    pccd_core_delete_flowspec_info(lsp, 0, false);
    TRACE_CORE("Deleted all Flowspecs");

    if (patricia_node_in_tree(&lsp->lv_patricia_id)) {
        patricia_delete(pccd_lsp_vector_root_id, &lsp->lv_patricia_id);
    }

    INSIST_ERR(lsp->lv_pce != NULL);
    SLIST_REMOVE(&lsp->lv_pce->pc_lsps, lsp, lsp_vector, lv_pce_lsps);
    lsp->lv_pce->pc_lsps_count--;
    free(lsp);
    TRACE_FUNCTION_EXIT();
}

static const char*
pccd_core_get_pce_state_str(pce_state_t state);

static void
pccd_core_p2mp_lsp_cleanup(struct lsp_vector *lsp, uint32_t srp_id)
{
    struct pccd_rpd_lsp_info *rpd_lsp= NULL;
    struct pccd_rpd_lsp_info *tmp_lsp = NULL;
    struct pccd_rpd_lsp_info *last_del = NULL;
    struct pccd_rpd_lsp_info *last_rep = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);

    if (!p2mp_lsp) {            
        return;
    }
    
    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
        if (!rpd_lsp->is_orphan) {
            if ((NULL == last_del) && (NULL == last_rep)) {
                last_rep = rpd_lsp;
            } else {
                pccd_core_report_lsp(lsp->lv_pce, rpd_lsp, true,
                                        lsp->lv_pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                        OLD_LEAVE_MUST_UNCHAGED, true);
            }
            continue;
        } 
        
        /* Delete LSP from RPD */
        TRACE_CORE("Deleting LSP id: %d lsp_name %s path %s"
                                    " from RPD type: %d", lsp->lv_lsp_id,
                                    rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->type);

        if (pccd_rpd_delete_lsp(rpd_lsp) == true) {

            struct pce_cfg_core *pce = NULL;
            struct pce_cfg_core *tmp= NULL;

            if ((NULL == last_del) && (NULL == last_rep)) {
                last_del = rpd_lsp;
                continue;
            }                                                    
            /* Succesfully deleted */
            /* Send report to all PCEs that are STATEFUL and has not delegated this LSP */
            SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
                if ((lsp->lv_ack_delegated == false) ||
                        (lsp->lv_ack_delegated == true && (lsp->lv_pce != pce))) {
                    if (PCE_IS_STATEFUL(pce)) {
                        if (pce->pc_state > PCE_STATE_CONNECTED) {
                            pccd_core_report_lsp(pce, rpd_lsp, true,
                                                    pce->pc_state >= PCE_STATE_SYNC, 
                                                    (lsp->lv_pce != pce) ? SRP_ID_RESV1 : srp_id,
                                                    OLD_LEAVES_TO_REMOVE, 
                                                    (lsp->lv_pce != pce) ? false : true);
                        } else {
                            TRACE_CORE("PCE '%s' is currently in state %s, can't send"
                                       " PCRpt messages", pce->pc_pce.pce_id,
                                       pccd_core_get_pce_state_str(pce->pc_state));
                        }
                    }
                }
            }
            pccd_core_provisioned_lsps_decrease_counter();
        }
    }

    if (last_del) {
        /* Succesfully deleted */
        struct pce_cfg_core *pce = NULL;
        struct pce_cfg_core *tmp= NULL;
        /* Send report to all PCEs that are STATEFUL and has not delegated this LSP */
        SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
            if ((lsp->lv_ack_delegated == false) ||
                    (lsp->lv_ack_delegated == true && (lsp->lv_pce != pce))) {
                if (PCE_IS_STATEFUL(pce)) {
                    if (pce->pc_state > PCE_STATE_CONNECTED) {
                        pccd_core_report_lsp(pce, last_del, true,
                                                pce->pc_state >= PCE_STATE_SYNC, SRP_ID_RESV1,
                                                OLD_LEAVES_TO_REMOVE, false);
                    } else {
                        TRACE_CORE("PCE '%s' is currently in state %s, can't send"
                                   " PCRpt messages", pce->pc_pce.pce_id,
                                   pccd_core_get_pce_state_str(pce->pc_state));
                    }
                }
            }
        }
        pccd_core_provisioned_lsps_decrease_counter();
    } else if (last_rep) {
        pccd_core_report_lsp(lsp->lv_pce, last_rep, true,
                                lsp->lv_pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                OLD_LEAVE_MUST_UNCHAGED, false);
    }
}

static void
pccd_core_lsp_cleanup_timer_cb(evContext ctx UNUSED, void *uap,
                                    struct timespec due UNUSED,
                                    struct timespec inter UNUSED)
{
    struct lsp_vector *lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    lsp = uap;
    /* Clear lsp cleanup timer */
    pccd_core_clear_lsp_cleanup_tid(lsp);

    if (lsp->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV) {    
        const struct pccd_rpd_lsp_info *rpd_lsp =
                pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);
        INSIST_ERR(rpd_lsp != NULL);

        if (rpd_lsp) {
            /* Delete LSP from RPD */
            TRACE_CORE("Deleting LSP id: %d lsp_name %s path %s"
                " from RPD type: %d", lsp->lv_lsp_id,
                rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->type);

            if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                /* Succesfully deleted */
                struct pce_cfg_core *pce = NULL;
                struct pce_cfg_core *tmp= NULL;
                /* Send report to all PCEs that are STATEFUL and has not delegated this LSP */
                SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
                    if ((lsp->lv_ack_delegated == false) ||
                            (lsp->lv_ack_delegated == true && (lsp->lv_pce != pce))) {
                        if (PCE_IS_STATEFUL(pce)) {
                            if (pce->pc_state > PCE_STATE_CONNECTED) {
                                pccd_core_report_deleted_lsp(pce, rpd_lsp, SRP_ID_RESV1);
                            } else {
                                TRACE_CORE("PCE '%s' is currently in state %s, can't send"
                                           " PCRpt messages", pce->pc_pce.pce_id,
                                           pccd_core_get_pce_state_str(pce->pc_state));
                            }
                        }
                    }
                }
                pccd_core_delete_lsp(lsp);
                pccd_core_provisioned_lsps_decrease_counter();
                TRACE_FUNCTION_EXIT();
            } else {
                /* Error deleting created LSP */
                TRACE_FUNCTION_EXIT();
            }
        }
    } else {    
        bool frag_tmr_running = false;        
        struct pccd_rpd_lsp_info *rpd_lsp= NULL;
        struct pccd_rpd_lsp_info *tmp_lsp = NULL;
        struct pccd_rpd_lsp_info *last = NULL;
        struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);

        if (!p2mp_lsp) {            
            TRACE_FUNCTION_EXIT();
            return;
        }

        /* Clear lsp fragmentation timer */
        if (evTestID(p2mp_lsp->msg_fragment_tid)) {
            frag_tmr_running = true;
            evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
            evInitID(&p2mp_lsp->msg_fragment_tid);
        }

        SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
            if ((!frag_tmr_running) && (!rpd_lsp->is_orphan)) {
                continue;
            } 
            
            /* Delete LSP from RPD */
            TRACE_CORE("Deleting LSP id: %d lsp_name %s path %s"
                                        " from RPD type: %d", lsp->lv_lsp_id,
                                        rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->type);

            if (pccd_rpd_delete_lsp(rpd_lsp) == true) {

                struct pce_cfg_core *pce = NULL;
                struct pce_cfg_core *tmp= NULL;

                if (NULL == last) {
                    last = rpd_lsp;
                    continue;
                }                                                    
                /* Succesfully deleted */
                /* Send report to all PCEs that are STATEFUL and has not delegated this LSP */
                SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
                    if ((lsp->lv_ack_delegated == false) ||
                            (lsp->lv_ack_delegated == true && (lsp->lv_pce != pce))) {
                        if (PCE_IS_STATEFUL(pce)) {
                            if (pce->pc_state > PCE_STATE_CONNECTED) {
                                pccd_core_report_lsp(pce, rpd_lsp, true,
                                                        pce->pc_state >= PCE_STATE_SYNC, SRP_ID_RESV1,
                                                        OLD_LEAVES_TO_REMOVE, true);
                            } else {
                                TRACE_CORE("PCE '%s' is currently in state %s, can't send"
                                           " PCRpt messages", pce->pc_pce.pce_id,
                                           pccd_core_get_pce_state_str(pce->pc_state));
                            }
                        }
                    }
                }
                pccd_core_provisioned_lsps_decrease_counter();
            }
        }

        if (last) {
            /* Succesfully deleted */
            struct pce_cfg_core *pce = NULL;
            struct pce_cfg_core *tmp= NULL;
            /* Send report to all PCEs that are STATEFUL and has not delegated this LSP */
            SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
                if ((lsp->lv_ack_delegated == false) ||
                        (lsp->lv_ack_delegated == true && (lsp->lv_pce != pce))) {
                    if (PCE_IS_STATEFUL(pce)) {
                        if (pce->pc_state > PCE_STATE_CONNECTED) {
                            pccd_core_report_lsp(pce, last, true,
                                                    pce->pc_state >= PCE_STATE_SYNC, SRP_ID_RESV1,
                                                    OLD_LEAVES_TO_REMOVE, false);
                        } else {
                            TRACE_CORE("PCE '%s' is currently in state %s, can't send"
                                       " PCRpt messages", pce->pc_pce.pce_id,
                                       pccd_core_get_pce_state_str(pce->pc_state));
                        }
                    }
                }
            }
            pccd_core_provisioned_lsps_decrease_counter();
        }
    }
    
    TRACE_FUNCTION_EXIT();
}

static int
pccd_core_report_deleted_provisioned_p2mp_lsp(struct pce_cfg_core *pce,
                                         struct lsp_vector *lsp_vec,
                                         const struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    daemon_trace_file_options_t *dtfo = NULL;
    struct pce_cfg_core *pce_tmp = NULL;
    struct pce_cfg_core *temp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    INSIST_ERR(lsp_vec != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    SLIST_FOREACH_SAFE(pce_tmp, &pce_cfg_head, pc_next, temp) {
        if (pce_tmp != pce) {
            if (PCE_IS_STATEFUL(pce_tmp)) {
                if (pce_tmp->pc_state > PCE_STATE_CONNECTED) {
                    pccd_core_report_deleted_p2mp_lsp(pce_tmp, p2mp_lsp, SRP_ID_RESV1);
                } else {
                    TRACE_PCEP(dtfo, "PCE '%s' is currently in state %s, can't send"
                               " PCRpt messages", pce_tmp->pc_pce.pce_id,
                               pccd_core_get_pce_state_str(pce_tmp->pc_state));
                }
            }
        }
    }

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_report_deleted_provisioned_lsp(struct pce_cfg_core *pce,
                                         struct lsp_vector *lsp_vec,
                                         const struct pccd_rpd_lsp_info *rpd_lsp);


void
pccd_core_handle_name_conflict(struct pccd_p2mp_lsp_info *p2mp_lsp,
                                          struct pccd_rpd_lsp_info *rpd_lsp, bool is_p2mp,
                                          bool report_lsp)
{
    if ((is_p2mp) && (p2mp_lsp)) {
        /* Delete LSP from RPD */
        struct pccd_rpd_lsp_info *del_lsp= NULL;
        struct pccd_rpd_lsp_info *tmp = NULL;
        struct lsp_vector *lsp_vec = NULL;

        SLIST_FOREACH_SAFE(del_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
            if (pccd_rpd_delete_lsp(del_lsp) == true) {
                /* Succesfully deleted */
                TRACE_CORE("LSP with lsp_name '%s' path_name %s is deleted from RPD",
                del_lsp->lsp_name, del_lsp->path_name);
                pccd_core_provisioned_lsps_decrease_counter();
            } else {
                /* Error deleting created LSP */
                LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
                del_lsp->lsp_name, del_lsp->path_name);
            }
        }   
        
        lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
        if (!lsp_vec) {
            LOGGING_ERR("Could not delete LSP '%s': not found",
                                            p2mp_lsp->p2mp_name);
            return;
        }
        
        /* Report deleted LSP to other PCEs */
        pccd_core_report_deleted_provisioned_p2mp_lsp(lsp_vec->lv_pce, lsp_vec, p2mp_lsp);
        
        /* Report deleted LSP to the provisioning LSP. Reflect
         * SRP */
        pccd_core_report_deleted_p2mp_lsp(lsp_vec->lv_pce, p2mp_lsp, lsp_vec->srp_id);
    } else if ((!is_p2mp) && (rpd_lsp)) {

        if (rpd_lsp->name_tree_key.type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {

            /**
              * Send delete LSP to spring-te as lsp-name + sub-type is key in
              * PCCD - spring-te communication.
              * If delete is not sent, both locally created and PCE provisioned
              * LSP will be present in spring-te
              */
            if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                /* Succesfully deleted */
                TRACE_CORE("LSP with lsp_name '%s' path_name '%s' is deleted from RPD",
                rpd_lsp->lsp_name, rpd_lsp->path_name);
                /* Delete the local cached copy of LSP information */
                pccd_core_provisioned_lsps_decrease_counter();
            } else {
                /* Error deleting created LSP */
                LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
                rpd_lsp->lsp_name, rpd_lsp->path_name);
            }
        } else {
            /**
              * RSVP LSPs are deleted by default when locally created LSPs
              * are configured with same name. TAG will delete the PCE-Init LSP
              * without sending a delete message to PCCD.
              * Error (Attempt to delete local LSP - errno:5) 
              * is sent by TAG if delete is sent by PCCD, as name is the only key in
              * PCCD - TAG communication
              */
              pccd_core_provisioned_lsps_decrease_counter();
        }

        if (report_lsp) {
            struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
            if (!lsp_vec) {
                LOGGING_ERR("Could not delete LSP with lsp_name '%s' path_name '%s' not found",
                                                 rpd_lsp->lsp_name, rpd_lsp->path_name);
                return;
            }
        
            /* Report deleted LSP to other PCEs */
            pccd_core_report_deleted_provisioned_lsp(lsp_vec->lv_pce, lsp_vec, rpd_lsp);
            /* Report deleted LSP to the provisioning LSP. Reflect
            * SRP */
            pccd_core_report_deleted_lsp(lsp_vec->lv_pce, rpd_lsp, lsp_vec->srp_id);
        }
    }

    return;
}

/* Start lsp_cleanup_timeout timer */
static void
pccd_core_pce_set_lsp_cleanup_timer(struct pce_cfg_core *pce)
{
    TRACE_FUNCTION_ENTRY();

    /* NSR Begin */
    if (!pccd_nsr_master())
        TRACE_FUNCTION_RETURN();
    /* NSR End */

    if (pce->pc_pce.pce_lsp_provisioning || pce->pc_pce.pce_p2mp_lsp_init_capability) {
        struct lsp_vector *lsp = NULL;
        struct lsp_vector *tmp = NULL;
        SLIST_FOREACH_SAFE(lsp, &pce->pc_lsps, lv_pce_lsps, tmp) {
            if (lsp->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
                const struct pccd_rpd_lsp_info *rpd_lsp =
                        pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);

                INSIST_ERR(rpd_lsp != NULL);

                /* we are only interested in provisioned lsps */
                if (rpd_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED) {
                    continue;
                }

                if (pce->pc_pce.pce_lsp_cleanup_timer) {
                    /* Stop any pre existing cleanup timer */
                    pccd_core_clear_lsp_cleanup_tid(lsp);
                    
                    /* Start lsp cleanup timer */
                    if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                        /* NSR Begin */
                        pccd_core_start_lsp_cleanup_tid(pce, lsp);
                        /* NSR End */
                    }
                } else {
                    /* Zero time for lsp cleanup, delete provisioned LSPs from RPD */
                    if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                        /* Report deleted LSP to other PCEs */
                        pccd_core_report_deleted_provisioned_lsp(pce, lsp, rpd_lsp);
                        /* Succesfully deleted */
                        pccd_core_delete_lsp(lsp);
                        pccd_core_provisioned_lsps_decrease_counter();
                        TRACE_FUNCTION_EXIT();
                    } else {
                        /* Error deleting created LSP */
                        TRACE_FUNCTION_EXIT();
                    }
                }
            } else {
                struct pccd_rpd_lsp_info *rpd_lsp= NULL;
                struct pccd_rpd_lsp_info *tmp_lsp = NULL;
                struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);

                if (!p2mp_lsp) {
                    continue;
                }
                /* we are only interested in provisioned lsps */
                if (p2mp_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED) {
                    continue;
                }

                if (pce->pc_pce.pce_lsp_cleanup_timer) {
                    /* Stop any pre existing cleanup timer */
                    pccd_core_clear_lsp_cleanup_tid(lsp);
                    
                    /* Start lsp cleanup timer */
                    if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                        /* NSR Begin */
                        pccd_core_start_lsp_cleanup_tid(pce, lsp);
                        /* NSR End */
                        /* set orphan flag in all branches */
                        SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
                            rpd_lsp->is_orphan = true;
                        }
                    }
                } else {
                    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
                        /* Zero time for lsp cleanup, delete provisioned LSPs from RPD */
                        if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                            pccd_core_provisioned_lsps_decrease_counter();
                        }
                    }
                    /* Report deleted LSP to other PCEs */
                    pccd_core_report_deleted_provisioned_p2mp_lsp(pce, lsp, p2mp_lsp);
                }
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}


/* Clear set_new_main_pce timer */
static void
pccd_core_clear_new_main_pce_timer(struct pce_cfg_core *pce)
{
    daemon_trace_file_options_t *dtfo;
    dtfo = pccd_core_pce_get_traceoptions(pce);

    TRACE_PCEP(dtfo, "Clearing set new main PCE timer");
    if (evTestID(pce->pc_set_new_main_pce_tid)) {
        evClearTimer(pccd_core_ev_ctx, pce->pc_set_new_main_pce_tid);
        evInitID(&pce->pc_set_new_main_pce_tid);
    }
}

/**
 * pccd_core_set_new_main_pce callback function. Set new main PCE
*/
static void
pccd_core_set_new_main_pce_timer_cb(evContext ctx UNUSED, void *uap,
                                          struct timespec due UNUSED,
                                          struct timespec inter UNUSED)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *new_pce = NULL;
    struct pce_cfg_core *main_pce = NULL;

    INSIST_ERR(uap != NULL);

    pce = uap;
    main_pce = pccd_core_get_main_pce();

    TRACE_CORE("Timeout for setting new main PCE");
    main_pce_locked = 0;
    pccd_core_clear_new_main_pce_timer(pce);
    if (main_pce && main_pce->pc_state < PCE_STATE_CONNECTED) {
        new_pce = pccd_core_select_new_main_pce(pce);
        INSIST_ERR(new_pce != NULL);
        if (new_pce->pc_state >= PCE_STATE_CONNECTED) {
            TRACE_CORE("Old main PCE: '%s', switching to new PCE: '%s'",
                       main_pce->pc_pce.pce_id, new_pce->pc_pce.pce_id);
            if (pccd_core_set_new_main_pce (new_pce)) {
                LOGGING_ERR("Unable to set new main pce");
            }
        } else {
            TRACE_CORE("new PCE state is not yet connected hence ignoring",
                        new_pce->pc_pce.pce_id);

        }
    } else {
        TRACE_CORE("Main PCE: '%s' already connected", main_pce->pc_pce.pce_id);
    }
}

/* Start set_new_main_pce timer */
static void
pccd_core_set_new_main_pce_timer(struct pce_cfg_core *pce)
{
    int count = 0;
    unsigned int switchover_time = 0;
    struct pce_cfg_core *pce_list = NULL;

    daemon_trace_file_options_t *dtfo;
    dtfo = pccd_core_pce_get_traceoptions(pce);

    if (!pce->pc_main) {
        TRACE_PCEP(dtfo, "%s is not main PCE hence not scheduling main pce"
                   " timer",pce->pc_pce.pce_id);
        return;
    }

    if( pce->pc_reconnects != 0) {
        TRACE_PCEP(dtfo, "%s is non zero reconnects hence not scheduling main"
                   " pce timer", pce->pc_pce.pce_id);
        return;
    }

    SLIST_FOREACH(pce_list, &pce_cfg_head, pc_next) {
        count++;
    }


    /* Set timer for switching new main PCE only when there are more then 1 PCE
     * configured */
    if (count > 1 && ((pce->pc_state == PCE_STATE_SYNC)
                || (pce->pc_state == PCE_STATE_UP)
                      || (pce->pc_state == PCE_STATE_CONNECTED))) {

        if ((pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout/2) >
            PCEP_NEW_MAIN_SWITCH_TIMER) {
            switchover_time = PCEP_NEW_MAIN_SWITCH_TIMER;
        } else {
            switchover_time = pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout/2;
        }
        if (!evTestID(pce->pc_set_new_main_pce_tid) &&
                pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout > 0) {
            TRACE_PCEP(dtfo, "Setting new main PCE timer to: %d seconds",
                       pce->pc_pce.pce_opts.pco_delegation_cleanup_timeout / 2);
            if (evSetTimer(pccd_core_ev_ctx, pccd_core_set_new_main_pce_timer_cb,
                           pce, evAddTime(evNowTime(),
                           evConsTime(switchover_time, 0)),
                           evConsTime(0,0), &pce->pc_set_new_main_pce_tid) == -1) {
                LOGGING_ERR("evSetTimer failed");
                exit(EX_SOFTWARE);
            }
            main_pce_locked = 1;
        }
    }
}

static bool
check_rate_limit(struct pccd_core_rate *rate, time_t ts)
{
    unsigned long max;
    long i;

    i = rate->index;
    for (max = 0; max <= rate->limit; max++) {
        if ((ts - rate->buffer[i]) > ONE_MINUTE) {
            return false;
        }
        i--;
        if (i < 0) {
            i = (rate->limit);
        }
    }
    return true;
}

static bool
pccd_add_rate(struct pccd_core_rate *rate)
{
    time_t ts = time(NULL);

    if (rate->limit == 0) {
        return false;
    }
    rate->buffer[rate->index] = ts;
    if (check_rate_limit(rate, ts) == true) {
        return true;
    }
    rate->index++;
    if (rate->index > rate->limit) {
        rate->index = 0;
    }
    return false;
}

static bool
pccd_add_msg_rate(void)
{
    if (pccd_add_rate(&pccd_message_rate) == true) {
        TRACE_CORE("Reached message rate limit");
        return true;
    } else {
        return false;
    }
}

static bool
pccd_add_upd_rate(void)
{
    if (pccd_add_rate(&pccd_update_rate) == true) {
        TRACE_CORE("Reached update rate limit");
        return true;
    } else {
        return false;
    }
}

static void
pccd_init_rates(struct pccd_core_rate *rate, unsigned limit)
{
    if (limit > 0) {
        rate->buffer = xcalloc (limit + 1, sizeof(time_t));
    } else {
        rate->buffer = NULL;
    }
    rate->limit = limit;
    rate->index = 0;
}

void
pccd_alloc_msg_rate_buffer(unsigned limit)
{
    pccd_init_rates(&pccd_message_rate, limit);
}

void
pccd_alloc_upd_rate_buffer(unsigned limit)
{
    pccd_init_rates(&pccd_update_rate, limit);
}

void
pccd_set_max_provisioned_lsps(unsigned limit)
{
    pccd_provisioned_lsps.limit = limit;
}

/* pccd_pce_connect is used in schedule_reconnect, and schedule reconnect
 * uses pccd_core_connect if the connection needs to be reset. */
static void
pccd_core_pce_connect(struct pce_cfg_core *pce);

/* End of forward declarations */
static void
pccd_core_pce_clear_lsp_retry_delegations(struct pce_cfg_core *pce)
{
    struct lsp_vector *lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);

    TRACE_CORE("Clear LSP retry-delegations for PCE: %s, LSP count: %u", 
	       pce->pc_pce.pce_id, pce->pc_lsps_count);

    SLIST_FOREACH(lsp, &pce->pc_lsps, lv_pce_lsps) {
        pccd_core_clear_lsp_delegation_retry_tid(lsp);
    }

    TRACE_FUNCTION_RETURN();
}

static void
pccd_core_pce_clear_lsp_delegations(struct pce_cfg_core *pce)
{
    struct lsp_vector *lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);

    TRACE_CORE("Clear LSP delegations for PCE: %s, LSP count: %u", 
	       pce->pc_pce.pce_id, pce->pc_lsps_count);

    SLIST_FOREACH(lsp, &pce->pc_lsps, lv_pce_lsps) {
        pccd_core_clear_lsp_delegation_tid(lsp);
    }

    TRACE_FUNCTION_RETURN();
}

void
pccd_core_lsp_transfer(struct pce_cfg_core *src, struct pce_cfg_core *dst,
                       struct lsp_vector *vec)
{
    INSIST_ERR(src != NULL);
    INSIST_ERR(dst != NULL);
    INSIST_ERR(vec != NULL);

    SLIST_REMOVE(&src->pc_lsps, vec, lsp_vector, lv_pce_lsps);
    SLIST_INSERT_HEAD(&dst->pc_lsps, vec, lv_pce_lsps);
    src->pc_lsps_count--;
    dst->pc_lsps_count++;

    vec->lv_pce = dst;

    pccd_core_lsp_transfer_all_fs(src, dst, vec);
    pccd_core_clear_lsp_delegation_tid(vec);
    pccd_core_clear_lsp_delegation_retry_tid(vec);
}

static void
pccd_core_lsps_transfer(struct pce_cfg_core *src, struct pce_cfg_core *dst)
{
    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(src != NULL);
    INSIST_ERR(dst != NULL);
    const struct pccd_rpd_lsp_info *rpd_lsp = NULL;
    struct lsp_vector *vec = NULL;
    struct lsp_vector *tmp = NULL;

    SLIST_FOREACH_SAFE(vec, &src->pc_lsps, lv_pce_lsps, tmp) {
        rpd_lsp = pccd_rpd_get_lsp_by_id(vec->lv_lsp_id);
        if (rpd_lsp && (rpd_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED))
            pccd_core_lsp_transfer(src, dst, vec);
    }

    TRACE_FUNCTION_RETURN();
}

/**
 * Convert (c) state to string representation of the state.
 * @param[in] state state id to convert to string
 * @return string representation of the state provided
 * @return "<UNKNOWN>" if the (c) state was invalid/unkown
 */
static const char*
pccd_core_get_pce_state_str(pce_state_t state)
{
    INSIST_ERR(state <= PCE_STATE_UP);

    switch (state) {
    case PCE_STATE_DELETED:
        return "PCE_STATE_DELETED";
    case PCE_STATE_NEW:
        return "PCE_STATE_NEW";
    case PCE_STATE_RECONNECT:
        return "PCE_STATE_RECONNECT";
    case PCE_STATE_CONNECTING:
        return "PCE_STATE_CONNECTING";
    case PCE_STATE_CONNECTED:
        return "PCE_STATE_CONNECTED";
    case PCE_STATE_SYNC:
        return "PCE_STATE_SYNC";
    case PCE_STATE_UP:
        return "PCE_STATE_UP";
    }
    LOGGING_ERR("Unknown internal pce state: %d", state);
    abort();
}

/**
 * Change the state of the (c) pce to (c) new state
 * @param[in] pce to change state to
 * @param[in] new_state of the pce
 */
static void
pccd_core_pce_transition_state(struct pce_cfg_core *pce, pce_state_t new_state)
{
    daemon_trace_file_options_t *dtfo = NULL;

    INSIST_ERR(pce != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    if ((new_state == PCE_STATE_SYNC) || (new_state == PCE_STATE_UP ||
            (pce->pc_state == PCE_STATE_UP))) {
        LOGGING_INFO("Changing state of pce '%s' from %s to %s",
                     pce->pc_pce.pce_id,
                     pccd_core_get_pce_state_str(pce->pc_state),
                     pccd_core_get_pce_state_str(new_state));
    }
    TRACE_PCEP(dtfo, "Changing state of pce '%s' from %s to %s", pce->pc_pce.pce_id,
               pccd_core_get_pce_state_str(pce->pc_state),
               pccd_core_get_pce_state_str(new_state));

    if (pce->pc_pce.peer_table)
    {
        pce->pc_pce.sess_table->pcePcepSessStateLastChange = pccd_snmp_get_current_utime();
        if (PCE_STATE_UP == new_state)
        {
            pce->pc_pce.peer_table->pcePcepPeerSessionExists = TRUE;
            pce->pc_pce.peer_table->pcePcepPeerNumSessSetupOK++;
            pce->pc_pce.peer_table->pcePcepPeerSessionUpTime = pccd_snmp_get_current_utime();
            pce->pc_pce.sess_table->pc_conn = pce->pc_conn;
            pccd_snmp_copy_sess_table_statistics(pce);
        }
        else
        {
            if (PCE_STATE_UP == pce->pc_state) {
                pce->pc_pce.peer_table->pcePcepPeerSessionExists = FALSE;
                pce->pc_pce.peer_table->pcePcepPeerSessionFailUpTime = pccd_snmp_get_current_utime();
                pce->pc_pce.sess_table->pcePcepSessDiscontinuityTime = pccd_snmp_get_current_utime();
            }
            pccd_snmp_reset_sess_table(pce);
        }
    }
    pce->pc_state = new_state;
}

/**
 * Disconnect from (c) pce and change pce's state to appropriate value.
 * @param[in] pce to disconnect from
 */
static void
pccd_core_pce_disconnect(struct pce_cfg_core *pce)
{
    INSIST_ERR(pce != NULL);

    /* NSR Begin */
    if (!pccd_nsr_master()) {
        return;
    }
    /* NSR End */

    pccd_core_pce_clear_lsp_retry_delegations(pce);

    /*
     * Cache the keepalive statictics for debugging purposes.
     * Clear these statistics when the session comes up.
     */
    if (pce->pc_conn != NULL) {
        pce->pc_pce.peer_table->pcePcepPeerNumKeepaliveRcvd +=
            pcep_get_keepalives_recv(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumKeepaliveSent +=
            pcep_get_keepalives_sent(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumCorruptRcvd +=
            pcep_get_corrupted_message_count(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumUnknownRcvd +=
            pcep_get_unknown_message_count(pce->pc_conn);

        pce->pc_statistics.pcep_statistics.keepalive_recv = 
            pcep_get_keepalives_recv(pce->pc_conn); 
        pce->pc_statistics.pcep_statistics.keepalive_sent =
            pcep_get_keepalives_sent(pce->pc_conn);
    }

    if (pce->pc_state > PCE_STATE_RECONNECT) {
        INSIST_ERR(pce->pc_conn != NULL);
        pccd_snmp_reset_sess_table(pce);
        pcep_disconnect(pce->pc_conn);
    }
    pccd_core_pce_set_delegation_cleanup_timer(pce);
    pccd_core_pce_set_lsp_cleanup_timer(pce);
    pce->pc_statistics.pcep_connection_active = 0; /* Time when connection started to be active */
    pce->pc_statistics.pcep_connection_down = time(NULL); /* Time when connection started to be down */
    pce->pc_conn = NULL;
    if (evTestID(pce->pc_reconnect_timer)) {
        INSIST_ERR(evClearTimer(pccd_core_ev_ctx, pce->pc_reconnect_timer)==0);
        evInitID(&pce->pc_reconnect_timer);
    }
    pccd_core_pce_transition_state(pce, PCE_STATE_NEW);
}

static void
pccd_core_pce_reconnect_cb(evContext ctx UNUSED, void *uap,
                           struct timespec due UNUSED,
                           struct timespec inter UNUSED)
{
    struct pce_cfg_core *pce = uap;
    INSIST_ERR(uap != NULL);

    evInitID(&pce->pc_reconnect_timer);
    pccd_core_pce_connect(pce);
}

/**
 * Switches the main PCE status to the new PCE.  If needed requests control
 * from RPD for all LSPs, or returns control for all LSPs.
 * @param old_pce[in,out] old pce, with "main" status
 * @param new_pce[in,out] new pce, to which the "main" status should be
 *                        transfered
 * @return -1 if the function call fails (old==new, or if old pce is not main).
 *         Returns 0 upon success.
 */
static int
pccd_core_switch_main_pces(struct pce_cfg_core *old_pce,
                           struct pce_cfg_core *new_pce)
{
    time_t ts;
    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(old_pce != NULL);
    INSIST_ERR(new_pce != NULL);

    if (new_pce == old_pce || old_pce->pc_main == false) {
        TRACE_FUNCTION_RETURN(-1);
    }

    TRACE_CORE("Chose new main PCE: '%s'", new_pce->pc_pce.pce_id);
    if (old_pce->pc_lsps_count > 0) {
        pccd_core_lsps_transfer(old_pce, new_pce);
        /* FIXME if PCE own just provisioned LSPs and LSP Cleanup == 0,
         * no LSP will be transferred to new PCE */
        //INSIST_ERR(new_pce->pc_lsps_count != 0);
    }

    if (new_pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE &&
            new_pce->pc_state >= PCE_STATE_SYNC) {
        if (!pccd_rpd_lsp_get_control_all()) {
            LOGGING_WAR("Failed to set external controller control for all "
                    "LSPs");
        }
        if (!pccd_rpd_get_all_lsps()) {
            LOGGING_WAR("Failed to request all LSPs");
        }
    }

    ts = time(NULL);
    old_pce->pc_statistics.primary_elapsed_previous +=
            ts - pccd_last_primary_switch;
    pccd_last_primary_switch = ts;
    old_pce->pc_main = false;
    new_pce->pc_main = true;

    //Start delegation cleanup timer if new PCE is down
    if (new_pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE &&
            new_pce->pc_state < PCE_STATE_SYNC) {
        pccd_core_pce_set_delegation_cleanup_timer(new_pce);
    }

    /* NSR Begin */
    pccd_repl_handle_update_active_pce(new_pce->pc_pce.pce_id);
    /* NSR End */

    TRACE_FUNCTION_RETURN(0);
}

static void
pccd_core_pce_schedule_reconnect(struct pce_cfg_core *pce)
{
    daemon_trace_file_options_t *dtfo = NULL;

    /* NSR Begin */
    /* do not attempt to establish PCEP session in backup RE */
    if (!pccd_nsr_master()) {
        return;
    }
    /* NSR End */

    INSIST_ERR(pce != NULL);
    INSIST_ERR(!evTestID(pce->pc_reconnect_timer));
    INSIST_ERR(pce->pc_state == PCE_STATE_NEW ||
               pce->pc_state == PCE_STATE_RECONNECT);

    pce->pc_reconnect_sec *= pce->pc_reconnect_sec;
    if (pce->pc_reconnect_sec == 0) {
        pce->pc_reconnect_sec = PCE_CFG_LOW_RECONNECT_SEC;
    } else if (pce->pc_reconnect_sec > PCE_CFG_MAX_RECONNECT_SEC){
        pce->pc_reconnect_sec = PCE_CFG_MAX_RECONNECT_SEC;
    }

    dtfo = pccd_core_pce_get_traceoptions(pce);

    TRACE_PCEP(dtfo, "Scheduling PCE reconnection in %d seconds",
               pce->pc_reconnect_sec);

    if (evSetTimer(pccd_core_ev_ctx, pccd_core_pce_reconnect_cb, pce,
                   evAddTime(evNowTime(), evConsTime(pce->pc_reconnect_sec, 0)),
                   evConsTime(0,0), &pce->pc_reconnect_timer) == -1 ) {
        LOGGING_ERR("evSetTimer failed");
        exit(EX_SOFTWARE);
    }
    pccd_core_pce_transition_state(pce, PCE_STATE_RECONNECT);
    pce->pc_reconnects++;

    if (pce->pc_pce.sess_table)
        pce->pc_pce.sess_table->pcePcepSessConnectRetry++;
}

/**
 * Find appropriate keepalive value in the range <min_keep:max_keep>, where
 * the resulting keepalive will be at least 2 times lower than selected
 * deadtimer. It is job of pccd_config_check to make sure DT/2 is in
 * keepalive range.
 * @param min_keep[in] Lower boundary for keepalive
 * @param max_keep[in] Upper boundary for keepalive
 * @param max_dead[int] Upper boundary for deadtimer
 * @return keepalive from range <min_keep;max_keep> that reflects the dead_max,
 *         or -1 if such number is impossible to find.
 */
static int
pccd_core_find_keepalive_for_deadtimer(unsigned min_keep, unsigned max_keep,
                                       unsigned dead_max)
{
    unsigned i = 0;

    INSIST_ERR(dead_max <= 255);
    if (min_keep == 0) {
        INSIST_ERR(dead_max == 0);
        INSIST_ERR(max_keep == 0);
        return 0;
    }

    if (dead_max == 0) {
        return 256;
    }

    i = dead_max / 4;
    if (max_keep == 0) {
        max_keep = 256;
    }

    for (; i <= max_keep && i * 2 <= dead_max; i++) {
        if (i >= min_keep && i <= max_keep) {
            return i;
        }
    }

    return -1;
}

/**
 * For given keepalive range <min_keep:max_keep> and maximum dead timer,
 * compute the proposal keepalive and proposal deadtimer.
 * If min-keep == 0, no keepalive should be used.
 * @param min_keep[in] Lower boundary of keepalive range
 * @param max_keep[in] Upper boundary of keepalive range
 * @param dead_max[in] Dead timer maximum value
 * @param prop_keep[out] Pointer to keepalive proposition value
 * @param prop_dead[out] Pointer to deadtimer proposition value
 */
static void
pccd_core_pick_timers(uint8_t min_keep, uint8_t max_keep, uint8_t dead_max,
                      uint8_t *prop_keep, uint8_t *prop_dead)
{
    uint8_t keep = PCEP_DEFAULT_KEEPALIVE;
    uint8_t dead = 0;
    
    INSIST_ERR(prop_keep != NULL);
    INSIST_ERR(prop_dead != NULL);


    if (min_keep == 0) {
        *prop_keep = 0;
        *prop_dead = 0;
        return;
    }

    if (keep < min_keep) {
        keep = min_keep;
    } else {
        if (max_keep != 0 && keep > max_keep) {
            keep = max_keep;
        }
    }
    dead = 4 * keep;

    if (4 * keep > dead_max) {
        dead = dead_max;
    }

    if(keep * 4 > dead) {
        if (dead_max < UCHAR_MAX) {
            int res = pccd_core_find_keepalive_for_deadtimer(min_keep, max_keep,
                                                             dead_max);
            INSIST_ERR(res > 0);
            keep = (uint8_t)res;
        } else {
            /*We don't care for the dead timer maximum value*/
            dead = keep * 4 > UCHAR_MAX ? UCHAR_MAX : keep * 4;
        }
    }

    *prop_keep = keep;
    *prop_dead = dead;
}

/* Connects to PCE. If the connection was unsuccesfull, schedules a
 * reconnection.
 */
static void
pccd_core_pce_connect(struct pce_cfg_core *pce)
{
    struct pcep_connect_parameters *params = &pce->pc_params;
    daemon_trace_file_options_t *dtfo = NULL;
    struct sockaddr_in addr, laddr;
    struct sockaddr_in6 addr6, laddr6;
    int caps = 0;
    char *auth_key = NULL;

    TRACE_FUNCTION_ENTRY();

    if (!pccd_nsr_master()) {
        return;
    }

    if (!pccd_rpd_is_up()) {
        pccd_core_pce_schedule_reconnect(pce);
        LOGGING_ERR("RPD is down. PCE sheduled to reconnect..");
        TRACE_FUNCTION_RETURN();
    }

    INSIST_ERR(pce->pc_state == PCE_STATE_NEW ||
               pce->pc_state == PCE_STATE_RECONNECT);

    memset(&params->constraints.local.keepalive, 0,
           sizeof(params->constraints.local.keepalive));
    memset(&params->constraints.remote.keepalive, 0,
           sizeof(params->constraints.remote.keepalive));

    params->local.sockaddress = NULL;
    params->local.socklen = 0;

    dtfo = pccd_core_pce_get_traceoptions(pce);

    if (pce->pc_pce.is_ipv6_session) {
        /* mark session as ipv6 in connect parameters */
        params->is_ipv6_session = true;

        memset(&addr6, 0, sizeof(addr6));
        memset(&laddr6, 0, sizeof(laddr6));
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(pce->pc_pce.pce_dest_port);
        addr6.sin6_addr = pce->pc_pce.pce_dest_addr.v6;
        params->remote.sockaddress = (struct sockaddr*)&addr6;
        params->remote.socklen = sizeof(addr6);

        if (memcmp(&pce->pc_pce.pce_local_addr.v6, &laddr6.sin6_addr,
                    sizeof(laddr6.sin6_addr))) {
            laddr6.sin6_family = AF_INET6;
            laddr6.sin6_addr = pce->pc_pce.pce_local_addr.v6;
            params->local.sockaddress = (struct sockaddr*)&laddr6;
            params->local.socklen = sizeof(laddr6);
        }
    } else {
        /* reset flag for ipv6 session in connect parameters */
        params->is_ipv6_session = false;

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(pce->pc_pce.pce_dest_port);
        addr.sin_addr = pce->pc_pce.pce_dest_addr.v4;
        params->remote.sockaddress = (struct sockaddr*)&addr;
        params->remote.socklen = sizeof(addr);
        memset(&laddr, 0, sizeof(laddr));

        if (memcmp(&pce->pc_pce.pce_local_addr.v4, &laddr.sin_addr,
                    sizeof(laddr.sin_addr))) {
            laddr.sin_family = AF_INET;
            laddr.sin_addr = pce->pc_pce.pce_local_addr.v4;
            params->local.sockaddress = (struct sockaddr*)&laddr;
            params->local.socklen = sizeof(laddr);
        }
    }

    params->constraints.local.keepalive.min_value =
            pce->pc_pce.pce_opts.pco_local_timers.plt_min_keepalive;
    params->constraints.local.keepalive.max_value =
            pce->pc_pce.pce_opts.pco_local_timers.plt_max_keepalive;
    pccd_core_pick_timers(params->constraints.local.keepalive.min_value,
                          params->constraints.local.keepalive.max_value,
                          UCHAR_MAX,
                          &params->local.proposal.keepalive,
                          &params->local.proposal.peer_deadtimer);

    params->constraints.local.max_deadtimer =
            pce->pc_pce.pce_opts.pco_local_timers.plt_max_deadtimer;

    params->constraints.remote.keepalive.min_value =
            pce->pc_pce.pce_opts.pco_remote_timers.prt_min_keepalive;
    params->constraints.remote.keepalive.max_value =
            pce->pc_pce.pce_opts.pco_remote_timers.prt_max_keepalive;
    pccd_core_pick_timers(params->constraints.remote.keepalive.min_value,
                          params->constraints.remote.keepalive.max_value,
                          params->constraints.local.max_deadtimer,
                          &params->remote.proposal.keepalive,
                          &params->remote.proposal.peer_deadtimer);

    switch (pce->pc_pce.pce_opts.pco_pce_type) {
    case PCE_TYPE_NONE:
        LOGGING_ERR("Non initialised PCE TYPE for pce: '%s', removing from "
                "PCCD's database", pce->pc_pce.pce_id);
        abort();
    case PCE_TYPE_STATELESS:
        caps = 0;
        TRACE_PCEP(dtfo, "Capabilities set to stateless");
        break;
    case PCE_TYPE_STATEFUL:
        caps = PCEP_CAP_STATEFUL;
        TRACE_PCEP(dtfo, "Capabilities set to stateful");
        break;
    case PCE_TYPE_STATEFULACTIVE:
        caps = PCEP_CAP_STATEFUL | PCEP_CAP_STATEFUL_ACTIVE;
        TRACE_PCEP(dtfo, "Capabilities set to active stateful");
        break;
    }
    //caps = (PCEP_CAP_SR_TE | caps);
    params->constraints.opt_caps = params->constraints.req_caps = caps;

    params->local.proposition.lsp_provisioning = pce->pc_pce.pce_opts.pco_lsp_provisioning;
    params->local.proposition.spring_capability = pce->pc_pce.pce_opts.pco_spring_capability;
    params->local.proposition.srv6_capability = pce->pc_pce.pce_opts.pco_srv6_capability;

    if (pce->pc_pce.pce_opts.pco_tls_wait_timer) {
	    params->tls_wait_timer = pce->pc_pce.pce_opts.pco_tls_wait_timer;
    }
    params->local.tls_enable = tls_enable;

    params->local.proposition.p2mp_lsp_report_capability =
        pce->pc_pce.pce_opts.pco_p2mp_lsp_report_capability;
    params->local.proposition.p2mp_lsp_update_capability =
        pce->pc_pce.pce_opts.pco_p2mp_lsp_update_capability;
    params->local.proposition.p2mp_lsp_init_capability =
        pce->pc_pce.pce_opts.pco_p2mp_lsp_init_capability;

    if( ASSOC_OBJ_RFC_COMPLAINT == assoc_obj_complaince ) {
        params->local.proposition.path_protection_association = true;
        params->local.proposition.srpag_association = pce->pc_pce.pce_opts.pco_spring_capability;
    } else {
        params->local.proposition.path_protection_association = false;
        params->local.proposition.srpag_association = false;
    }

    params->local.proposition.msd = maximum_srmpls_segment_list_depth;
    if (params->local.proposition.msd > PCCD_MAX_SID_DEPTH) {
        params->local.proposition.msd = PCCD_MAX_SID_DEPTH;
    }

    /** pcc advertising it is capable of flow spec */
    params->local.proposition.pce_flowspec_capability =
        pce->pc_pce.pce_opts.pco_flowspec_capability;

    /*
     * PCEP multipath capability
     */
    if (pce->pc_pce.pce_opts.pco_spring_capability ||
        pce->pc_pce.pce_opts.pco_srv6_capability) {
        params->local.proposition.multipath_capability = multipath_enabled;
    } else {
        params->local.proposition.multipath_capability = false;
    }

    params->local.proposition.disjoint_assoc_capability = disjoint_association_enabled;

    TRACE_PCEP(dtfo, "my_dead_max: %d, proposed dead timer: %d",
               params->constraints.local.max_deadtimer,
               params->local.proposal.peer_deadtimer);
    TRACE_PCEP(dtfo, "my keep: min: %d max: %d prop: %d",
               params->constraints.local.keepalive.min_value,
               params->constraints.local.keepalive.max_value,
               params->local.proposal.keepalive);
    TRACE_PCEP(dtfo, "peer keep: min: %d max: %d prop: %d",
               params->constraints.remote.keepalive.min_value,
               params->constraints.remote.keepalive.max_value,
               params->remote.proposal.keepalive);
    if (pce->pc_pce.pce_opts.pco_lsp_provisioning) {
        TRACE_PCEP(dtfo, "lsp cleanup timer: %d",
                   pce->pc_pce.pce_opts.pco_lsp_cleanup_timer);
    }

    TRACE_PCEP(dtfo, "max sid depth: %d",
            maximum_srmpls_segment_list_depth);

    if (strlen(pce->pc_pce.pce_opts.pco_auth_key))
	auth_key = pce->pc_pce.pce_opts.pco_auth_key;
    pce->pc_conn = pcep_connect(pccd_pcep, pce, &pce->pc_params, auth_key);
    if (!pce->pc_conn) {
        if (pce->pc_pce.peer_table) {
            pce->pc_pce.peer_table->pcePcepPeerSessionFailTime = pccd_snmp_get_current_utime();
            pce->pc_pce.peer_table->pcePcepPeerNumSessSetupFail++;
        }
        pccd_core_pce_schedule_reconnect(pce);
        TRACE_FUNCTION_RETURN();
    }

    if (pcep_set_max_unknown_messages(pce->pc_conn,
                                      pce->pc_pce.pce_opts.pco_max_unknown_messages)) {
        LOGGING_ERR("pcep_set_max_unknown_messages: could not allocate memory");
        exit(EX_SOFTWARE);
    }

    pcep_set_trace_mask (pce->pc_conn, PCEP_TRC_ALL);

    pcep_set_dump_mask (pce->pc_conn, PCEP_TRC_ALL);
    pccd_core_pce_transition_state(pce, PCE_STATE_CONNECTING);

    TRACE_PCEP(dtfo, "successful pcep_connect, waiting for libpcep connect callback");
    TRACE_FUNCTION_EXIT();
}

typedef enum {
    RSVP = 0,
    SEGMENT
} lsp_setup_t;

static int
pccd_core_fill_srp (struct pcep_obj_srp *srp, uint32_t srp_id, 
                                              uint8_t lst)
{
    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(srp != NULL);
    srp->remove = false;
    srp->srp_id = srp_id;
    srp->lsp_setup_type = lst;
    TRACE_CORE("Remove %d SRP ID: %u", srp->remove, srp->srp_id);
    TRACE_FUNCTION_RETURN(0);
}

static lsp_op_value_t
get_lsp_op_value (lsp_op_value_t rpd_state)
{
    switch (rpd_state) {
    case LSP_STATE_UP:
        return LSP_OP_UP;
    case LSP_STATE_DOWN:
        return LSP_OP_DOWN;
    case LSP_STATE_ACTIVE:
        return LSP_OP_ACTIVE;
    case LSP_STATE_CREATION_PENDING:
        return LSP_OP_GOING_UP;
    default:
        return LSP_OP_DOWN;
    }
}

static void
pccd_core_pce_disable_tlv_path_binding(struct pcep_obj_lsp *lsp,
                                       struct pce_cfg_core *pce)
{
    bool disable_tlv_path_bind;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(lsp != NULL);
    INSIST_ERR(pce != NULL);


    disable_tlv_path_bind = pce->pc_pce.pce_opts.pco_disable_tlv_path_binding;
    
    if (disable_tlv_path_bind) {
        for (int count = 0; count < MAX_PATH_BINDING_TLVS; count++) {
            if (lsp->path_binding[count].mpls_label_binding_value) {
                lsp->path_binding[count].mpls_label_binding_value = 0;
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}

static int
pccd_core_fill_report_lsp(struct pcep_obj_lsp *lsp,
                          const struct pccd_rpd_lsp_info *rpd_lsp,
                          bool delegate, bool sync_done, bool fragment,
                          const char symbolic_name[MAX_SYMB_NAME_SIZE])
{
    struct lsp_vector* lsp_vec = NULL;
    uint16_t lsp_id = 0;
    uint16_t tunnel_id = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(lsp != NULL);
    INSIST_ERR(rpd_lsp != NULL);
    /* Create LSP object for the PC State Report Message */
    lsp->pce_created = (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED);
    lsp->p2mp_branch = ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) == LSP_PATH_TYPE_P2MP);
    lsp->fragment = fragment;
    lsp->delegated = delegate;
    TRACE_CORE("delegated: %d", lsp->delegated);
    lsp->last_update = sync_done;
    TRACE_CORE("last_upd: %d", lsp->last_update);
    if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && 
        (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
        (NULL != rpd_lsp->p2mp_lsp)) {
        lsp->operational = pccd_rpd_get_p2mp_lsp_op_value(rpd_lsp->p2mp_lsp, rpd_lsp->lsp_id, true); 
        TRACE_CORE("p2mp operational: %d", lsp->operational);
    } else {
        lsp->operational = get_lsp_op_value(rpd_lsp->state); 
        TRACE_CORE("operational: %d", lsp->operational);
    }
    // FIXME: Get Administrative  from config
    lsp->administrative = true;
    TRACE_CORE("administrative %d", lsp->administrative);

    if (((rpd_lsp->msg_trigger_reason & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN) &&
          (!((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) 
           && (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED)))) ||
        ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != rpd_lsp->p2mp_lsp) &&
          (rpd_lsp->p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
           (rpd_lsp->p2mp_lsp->last_branch_del_pending == true))){
        /**
         * Case 1: In case of MBB, old instance pcRpt msg must have remove bit set
         * Case 2: For Externally Provisioned P2MP, while reporting last branch delete,
         *         lsp object must have remove bit set
         */
        lsp->remove = true;
        TRACE_CORE("remove: %d", lsp->remove);
    }
    lsp->plsp_id = rpd_lsp->id;
    TRACE_CORE("plsp_id: %d", lsp->plsp_id);
    strncpy(lsp->symbolic_name, symbolic_name, sizeof(lsp->symbolic_name));
    lsp->symbolic_name[sizeof(lsp->symbolic_name) - 1] = '\0';
    TRACE_CORE("symbolic_name: '%s'", lsp->symbolic_name);

    if (rpd_lsp->error_spec_obj) {
        TRACE_CORE("err_spec len: %u",
                   rpd_lsp->error_spec_obj_len);
        lsp->errspec_len = (uint8_t)rpd_lsp->error_spec_obj_len;
        memcpy(lsp->errspec,
               (uint8_t *) rpd_lsp->error_spec_obj,
               MIN(sizeof(lsp->errspec), lsp->errspec_len));
    }

    if ((rpd_lsp->binding_type != rpd_lsp->old_binding_type) ||
        (rpd_lsp->binding_value != rpd_lsp->old_binding_value)) {

        unsigned int count = 0;

        if (rpd_lsp->old_binding_value) {
            //Delete Old binding
            lsp->path_binding[count].binding_type = rpd_lsp->old_binding_type;
            lsp->path_binding[count].mpls_label_binding_value = rpd_lsp->old_binding_value;

            /* if binding_type is 0, then label value need to be
             * in 20 MSB.
             */
            if (0 == rpd_lsp->old_binding_type) {
                lsp->path_binding[count].mpls_label_binding_value = (lsp->path_binding[count].mpls_label_binding_value << 12);
            }

            lsp->path_binding[count].flag_r = true;     //Set R flag to true for removal of old binding
            count++;

            TRACE_CORE("old binding type: %u, old binding value: %u",
                    rpd_lsp->old_binding_type, rpd_lsp->old_binding_value);
        }

        if (rpd_lsp->binding_value) {
            //Add new binding
            lsp->path_binding[count].binding_type = rpd_lsp->binding_type;
            lsp->path_binding[count].mpls_label_binding_value = rpd_lsp->binding_value;

            /* if binding_type is 0, then label value need to be
             * in 20 MSB.
             */
            if (0 == rpd_lsp->binding_type) {
                lsp->path_binding[count].mpls_label_binding_value = (lsp->path_binding[count].mpls_label_binding_value << 12);
            }

            lsp->path_binding[count].flag_r = false;
            count++;

            TRACE_CORE("binding type: %u, binding value: %u", rpd_lsp->binding_type, rpd_lsp->binding_value);
        }
    } else if (sync_done && rpd_lsp->binding_value) {
        /* Binding SID must be reported during SYNC phase if present */
        lsp->path_binding[0].binding_type = rpd_lsp->binding_type;
        lsp->path_binding[0].mpls_label_binding_value = rpd_lsp->binding_value;

        /* if binding_type is 0, then label value need to be
         * in 20 MSB.
         */
        if (0 == rpd_lsp->binding_type) {
            lsp->path_binding[0].mpls_label_binding_value = (lsp->path_binding[0].mpls_label_binding_value << 12);
        }

        lsp->path_binding[0].flag_r = false;

        TRACE_CORE("Reporting BSID during sync phase, binding type: %u, binding value: %u",
                rpd_lsp->binding_type, rpd_lsp->binding_value);
    }

    /*either LSP is UP or down*/

    if (!rpd_lsp->lsp_id) {
	TRACE_CORE("LSP path is down lsp_id: %u", rpd_lsp->lsp_id);
    }

    if(!rpd_lsp->is_lsp_src_dst_addr_type_ipv6) {
        /*
         * Because LSP IDENTIFIERS TLV should be per path it is meaningful to
         * move it to LSPA object. Right now it is per LSP but PCCD can't send
         * two TLVS for both primary or secondary path.
         * How this will be distiguished???
         * PCCD is sending only primary LSP IDENTIFIERS TLV
         */

        struct in_addr srcaddr, dstaddr, extended_tunnel_id;
        srcaddr.s_addr = rpd_lsp->srcaddr.v4;
        dstaddr.s_addr = rpd_lsp->dstaddr.v4;
        extended_tunnel_id.s_addr = rpd_lsp->extended_tunnel_id.v4;
        TRACE_CORE("tunnel sender IP address: %s", inet_ntoa(srcaddr));
        TRACE_CORE("lsp_id: %u", rpd_lsp->lsp_id);
        TRACE_CORE("tunnel_id: %u", rpd_lsp->tunnel_id);
        TRACE_CORE("extended tunnel_id: %s", inet_ntoa(extended_tunnel_id));
        if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != rpd_lsp->p2mp_lsp)) {
            TRACE_CORE("p2mp tunnel id: %u", rpd_lsp->p2mp_lsp->p2mp_id);
        }else {
            TRACE_CORE("tunnel dest IP address: %s", inet_ntoa(dstaddr));
        }

        lsp_id = htons(rpd_lsp->lsp_id);
        tunnel_id = htons(rpd_lsp->tunnel_id);
        /* retrieve our internal lsp vector */
        lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        if (lsp_vec ==NULL) {
            LOGGING_ERR("Could not retrieve LSP in internal list");
            TRACE_FUNCTION_RETURN(-1);
        }

        if (lsp_vec->lv_pce->pc_pce.is_ipv6_session &&
            rpd_lsp->srcaddr.v4 == 0 &&
            rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
            /**
             * For IPv6 PCEP Sesison, If LSP is SR type and src address is zero or
             * not received from rpd then dont populate lsp_identifiers info to
             * send it out to PCE
             */
            lsp->lsp_identifiers_len = 0;
        } else {
            lsp->lsp_identifiers_len = 16; /* IPV4-LSP-IDENTIFIERS TLV length */
            memcpy(lsp->lsp_identifiers,     &rpd_lsp->srcaddr.v4, sizeof(uint32_t));
            memcpy(lsp->lsp_identifiers + 4, &lsp_id, sizeof(uint16_t));
            memcpy(lsp->lsp_identifiers + 6, &tunnel_id, sizeof(uint16_t));
            memcpy(lsp->lsp_identifiers + 8, &rpd_lsp->extended_tunnel_id.v4, sizeof(uint32_t));
            if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != rpd_lsp->p2mp_lsp)) {
                memcpy(lsp->lsp_identifiers + 12, &rpd_lsp->p2mp_lsp->p2mp_id, sizeof(uint32_t));
            }else {
                memcpy(lsp->lsp_identifiers + 12, &rpd_lsp->dstaddr.v4, sizeof(uint32_t));
            }
		}
    } else {
        struct in6_addr srcaddr_ipv6, dstaddr_ipv6, extended_tunnel_id_ipv6;
        char srcstr_ipv6[INET6_ADDRSTRLEN] = "";
        char dststr_ipv6[INET6_ADDRSTRLEN] = "";
        char extended_tunnel_id_str_ipv6[INET6_ADDRSTRLEN] = "";

        memcpy(&srcaddr_ipv6, rpd_lsp->srcaddr.v6, 16);
        memcpy(&dstaddr_ipv6, rpd_lsp->dstaddr.v6, 16);
        memcpy(&extended_tunnel_id_ipv6, rpd_lsp->extended_tunnel_id.v6, 16);

        inet_ntop(AF_INET6, &srcaddr_ipv6, srcstr_ipv6, sizeof(srcstr_ipv6));
        inet_ntop(AF_INET6, &dstaddr_ipv6, dststr_ipv6, sizeof(dststr_ipv6));
        inet_ntop(AF_INET6, &extended_tunnel_id_ipv6, extended_tunnel_id_str_ipv6, sizeof(extended_tunnel_id_str_ipv6));

        TRACE_CORE("tunnel sender IPv6 address: %s", srcstr_ipv6);
        TRACE_CORE("lsp_id: %u", rpd_lsp->lsp_id);
        TRACE_CORE("tunnel_id: %u", rpd_lsp->tunnel_id);
        TRACE_CORE("extended tunnel_id: %s", extended_tunnel_id_str_ipv6);
        if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != rpd_lsp->p2mp_lsp)) {
            TRACE_CORE("p2mp tunnel id: %u", rpd_lsp->p2mp_lsp->p2mp_id);
        }else {
            TRACE_CORE("tunnel dest IPv6 address: %s", dststr_ipv6);
        }

        lsp_id = htons(rpd_lsp->lsp_id);
        tunnel_id = htons(rpd_lsp->tunnel_id);

        lsp->lsp_identifiers_len = 52; /* IPV6-LSP-IDENTIFIERS TLV length */
        memcpy(lsp->lsp_identifiers,     &rpd_lsp->srcaddr.v6, 16);
        memcpy(lsp->lsp_identifiers + 16, &lsp_id, sizeof(uint16_t));
        memcpy(lsp->lsp_identifiers + 18, &tunnel_id, sizeof(uint16_t));
        memcpy(lsp->lsp_identifiers + 20, &rpd_lsp->extended_tunnel_id.v6, 16);
        if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != rpd_lsp->p2mp_lsp)) {
            memcpy(lsp->lsp_identifiers + 36, &rpd_lsp->p2mp_lsp->p2mp_id, sizeof(uint32_t));
        }else {
            memcpy(lsp->lsp_identifiers + 36, &rpd_lsp->dstaddr.v6, 16);
        }
    }

    TRACE_FUNCTION_RETURN(0);
}

void
pccd_core_store_lsp (struct pce_cfg_core *pce, uint32_t lsp_id,
                     uint32_t srp_id, bool created, uint8_t vec_type)
{
    daemon_trace_file_options_t *dtfo = NULL;
    struct lsp_vector *lsp_vec = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    dtfo = pccd_core_pce_get_traceoptions(pce);
    TRACE_PCEP(dtfo, "Storing LSP ID %lu", lsp_id);

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp_id);
    if (lsp_vec) {
        return;
    }

    lsp_vec = xmalloc(sizeof(*lsp_vec));
    memset(lsp_vec, 0, sizeof(*lsp_vec));
    lsp_vec->lv_lsp_id = lsp_id;
    lsp_vec->ack = false;
    if (created) {
        lsp_vec->lv_want_to_delegate = lsp_vec->lv_ack_delegated = true;
        // Remember SRP ID for the first create request.
        lsp_vec->srp_id = srp_id;
    } else {
        lsp_vec->lv_want_to_delegate = lsp_vec->lv_ack_delegated = false;
        lsp_vec->srp_id = SRP_ID_RESV1;
    }
    lsp_vec->lv_delegation_failed = 0;
    lsp_vec->lv_retry_delegation = false;
    lsp_vec->lv_type = vec_type;

    evInitID(&lsp_vec->lv_lsp_delegation_retry_tid);
    evInitID(&lsp_vec->lv_delegation_setup_tid);
    evInitID(&lsp_vec->lv_lsp_cleanup_tid);

    /*
     *  Add LSP to lsp_id tree
     */
    patricia_node_init(&lsp_vec->lv_patricia_id);
    assert( patricia_add(pccd_lsp_vector_root_id, &lsp_vec->lv_patricia_id));

    if (pce) {
        SLIST_INSERT_HEAD(&pce->pc_lsps, lsp_vec, lv_pce_lsps);
        pce->pc_lsps_count++;
        lsp_vec->lv_pce = pce;
    }

    SLIST_INIT(&lsp_vec->lv_flowspec_info_head);
    TRACE_FUNCTION_EXIT();
}

static void
pccd_core_delete_all_lsps(void)
{
    struct lsp_vector *lsp_vec = NULL;
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    PCCD_ALL_LSP_VECTOR(lsp_vec) {
        TRACE_CORE("Removing LSP ID %d from pce_cfg_core %p from list",
                   lsp_vec->lv_lsp_id, lsp_vec->lv_pce);
        pccd_core_delete_lsp(lsp_vec);
    }PCCD_ALL_LSP_VECTOR_END(lsp_vec);

    TRACE_CORE("Deleted all LSPs stored in pccd_core");
    INSIST_ERR(patricia_isempty(pccd_lsp_vector_root_id));
    pccd_provisioned_lsps.counter = 0;

    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        pce->pc_lsps.slh_first = NULL;
        pce->pc_lsps_count = 0;
    }
    TRACE_CORE("Removed references to deleted LSPs from all PCE "
            "structures");
    TRACE_FUNCTION_EXIT();
}

/*
 * Get the lsp_vector by using lsp id
*/
struct lsp_vector *
pccd_core_get_lsp_vec_by_lsp_id(uint32_t lsp_id)
{
    patnode_t *node;

    node = patricia_lookup(pccd_lsp_vector_root_id, &lsp_id);
    return (pccd_lsp_id_patnode_to_lv(node));

}

void
pccd_core_construct_rro_info(char *hops, uint32_t buffer_size, void *r_info)
{
    char addr[32];
    struct in_addr ip_addr;
    const RouteObj *obj = NULL;
    const uint8_t *beyond_byte = NULL;
    const ro_entry *ro = NULL;
    unsigned int len = 0;

    if (NULL == r_info){
        return;
    }

    obj = (const RouteObj *)r_info;
    len = ntohs(obj->hdr.obj_length) - sizeof(OBJ_HDR);  /* exclude OBJ_HDR */
    beyond_byte = (const uint8_t*)(obj->entry) + len;
    /*
     * point to the first entry
     */
    ro = (const ro_entry *) obj->entry;

    while ((const uint8_t *)ro < beyond_byte) {
        switch(ro->type & 0x7f) {
            case RO_TYPE_IPV4:{
       		const ro_entry_v4 *v4 = (const ro_entry_v4 *)ro;
		memset(addr, '\0', sizeof(addr));
		ip_addr.s_addr = v4->node;
		if (v4->flags) {
		    snprintf(addr, sizeof(addr), "%s(flag=0x%x) ",
			inet_ntoa(ip_addr),
			v4->flags);
		} else {
		    snprintf(addr, sizeof(addr), "%s", inet_ntoa(ip_addr));
		}
		strncat(hops, addr, (buffer_size - strlen(hops) - 1));
		break;
            }
            case RO_TYPE_IPV6:{
		break;
            }
            case RO_TYPE_UNNUM:{
		break;
            }
            case RO_LABEL:{
		char temp[64] = {0};
		const struct ro_entry_label *label = 
			(const struct ro_entry_label *)(const void *)ro;
		snprintf( temp, sizeof(temp), "(Label=%u) ", ntohl(label->label));
		strncat(hops, temp, (buffer_size - strlen(hops) - 1));
		break;
            }
       }
       ro = (const ro_entry*)(((const uint8_t *) ro) + ro->len);
    }

    return;
}

void
pccd_core_construct_ero_info(char *hops, uint32_t buffer_size, void *r_info)
{
    char addr[32];
    struct in_addr ip_addr;
    const RouteObj *obj = NULL;
    const uint8_t *beyond_byte = NULL;
    const ro_entry *ro = NULL;
    unsigned int len = 0;

    if (NULL == r_info){
        return;
    }

    obj = (const RouteObj *)r_info;
    len = ntohs(obj->hdr.obj_length) - sizeof(OBJ_HDR);  /* exclude OBJ_HDR */
    beyond_byte = (const uint8_t*)(obj->entry) + len;
    /*
     * point to the first entry
     */
    ro = (const ro_entry *) obj->entry;

    while ((const uint8_t *)ro < beyond_byte) {
        switch(ro->type & 0x7f) {
            case RO_TYPE_IPV4:{
       		const ro_entry_v4 *v4 = (const ro_entry_v4 *)ro;
		memset(addr, '\0', sizeof(addr));
		ip_addr.s_addr = v4->node;
		snprintf(addr, sizeof(addr), "%s", inet_ntoa(ip_addr));
		strncat(hops, addr, (buffer_size - strlen(hops) - 1));

		if(type_strict(v4->type)) {
		    strncat(hops, "(S) ", (buffer_size - strlen(hops) - 1));
		}
		else {
		    strncat(hops, "(L) ", (buffer_size - strlen(hops) - 1));
		}
		break;
            }
            case RO_TYPE_IPV6:{
		break;
            }
            case RO_TYPE_UNNUM:{
		break;
            }
       }
       ro = (const ro_entry*)(((const uint8_t *) ro) + ro->len);
    }

    return;
}

void
pccd_core_construct_sr_ro_info(char *hops, uint32_t buffer_size, void *r_info)
{
    char temp[32];
    char label_str[16] = {0};
    struct in_addr ip_addr;
    const rpd_sr_ero_list_t *sr_ero_list = NULL;

    if(NULL == r_info) {
	return;
    }

    sr_ero_list = (const rpd_sr_ero_list_t*)r_info;

    for (unsigned i = 0; i < sr_ero_list->rsel_n_eros; i++) {
        const rpd_sr_ero_t *sr_ero  = &sr_ero_list->rsel_ero[i];
        switch(sr_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                memcpy(&ip_addr.s_addr, &sr_ero->rse_nai.u.rsen_node_ipv4_addr, 
                                                        sizeof(ip_addr.s_addr));
		memset(temp, '\0', sizeof(temp));
		snprintf(temp, sizeof(temp), "%s ", inet_ntoa(ip_addr));
		strncat(hops, temp, (buffer_size - strlen(hops) - 1));
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                break;
#endif
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                memcpy(&ip_addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_local_addr, 
                                                        sizeof(ip_addr.s_addr));
		memset(temp, '\0', sizeof(temp));
		snprintf(temp, sizeof(temp), "%s", inet_ntoa(ip_addr));  /*Local addr*/
		strncat(hops, temp, (buffer_size - strlen(hops) - 1));

                memcpy(&ip_addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr, 
                                                        sizeof(ip_addr.s_addr));
		memset(temp, '\0', sizeof(temp));
		snprintf(temp, sizeof(temp), "->%s", inet_ntoa(ip_addr));  /*Remote addr*/
		strncat(hops, temp, (buffer_size - strlen(hops) - 1));                
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
                break;
#endif
            default:
                break;
        }
        switch(sr_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
		snprintf(label_str, sizeof(label_str), "_");
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
		snprintf(label_str, sizeof(label_str), "%u", htonl(sr_ero->rse_sid.u.rses_label_20));
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
		snprintf(label_str, sizeof(label_str), "%u", htonl(sr_ero->rse_sid.u.rses_label_32));
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
		snprintf(label_str, sizeof(label_str), "%u", htonl(sr_ero->rse_sid.u.rses_index));
                break;
            default:
                break;
        }
	memset(temp, '\0', sizeof(temp));
	snprintf(temp, sizeof(temp), "(Label=%s) ", label_str);
	strncat(hops, temp, (buffer_size - strlen(hops) - 1));
    }
}

void
pccd_core_construct_srv6_ro_info(char *hops, uint32_t buffer_size, void *r_info)
{
    char temp[INET6_ADDRSTRLEN+10];
    char sidstr_ipv6[INET6_ADDRSTRLEN] = "";
    const rpd_sr_ero_list_t *sr_ero_list = NULL;

    if(NULL == r_info) {
    return;
    }

    sr_ero_list = (const rpd_sr_ero_list_t*)r_info;

    for (unsigned i = 0; i < sr_ero_list->rsel_n_eros; i++) {
        const rpd_sr_ero_t *srv6_ero  = &sr_ero_list->rsel_ero[i];
        switch(srv6_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID: {
                char nodeidstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_node_ipv6_addr, nodeidstr_ipv6, sizeof(nodeidstr_ipv6));
                strncat(hops, nodeidstr_ipv6, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char buff[INET6_ADDRSTRLEN+2] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                strncat(hops, localipstr_ipv6, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                snprintf(buff, sizeof(buff), "->%s", remoteipstr_ipv6);
                strncat(hops, buff, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char buff[INET6_ADDRSTRLEN+2] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                strncat(hops, localipstr_ipv6, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                snprintf(buff, sizeof(buff), "->%s", remoteipstr_ipv6);
                strncat(hops, buff, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
            }
                break;
            default:
                break;
        }
        switch(srv6_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
        snprintf(sidstr_ipv6, sizeof(sidstr_ipv6), "_");
                break;
            case  RPD_SR_ERO_SID_TYPE_SRV6: {
                inet_ntop(AF_INET6, srv6_ero->rse_sid.u.rses_addr, sidstr_ipv6, sizeof(sidstr_ipv6));
            }
            break;
            default:
                break;
        }
    memset(temp, '\0', sizeof(temp));
    snprintf(temp, sizeof(temp), "(v6SID=%s) ", sidstr_ipv6);
    strncat(hops, temp, (buffer_size - strnlen(hops, buffer_size - 1) - 1));
    }
}

static void
pccd_core_print_sr_ero_info(rpd_sr_ero_list_t *rpd_sr_ero)
{   
    struct in_addr addr;
    TRACE_CORE("Number of SR-ERO subobjects: %d", rpd_sr_ero->rsel_n_eros);
    for (unsigned i = 0; i < rpd_sr_ero->rsel_n_eros; i++) {
        rpd_sr_ero_t *sr_ero  = &rpd_sr_ero->rsel_ero[i];
        TRACE_CORE("SR-ERO loose_type: %d", sr_ero->rse_loose);
        TRACE_CORE("SR-ERO SID label type: %d", sr_ero->rse_sid.rses_type);
        switch(sr_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                TRACE_CORE("SID is absent");
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
                TRACE_CORE("SR-ERO sid value: %d", htonl(sr_ero->rse_sid.u.rses_label_20));
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
                TRACE_CORE("SR-ERO sid value: %d", htonl(sr_ero->rse_sid.u.rses_label_32));
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
                TRACE_CORE("SR-ERO sid value: %d", htonl(sr_ero->rse_sid.u.rses_index));
                break;
            default:
                TRACE_CORE("Unknown SID type is received");
                LOGGING_ERR("Unknown SID type is received");
        }
        TRACE_CORE("SR-ERO NAI type: %d", sr_ero->rse_nai.rsen_type);
        switch(sr_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                TRACE_CORE("NAI is absent");
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_node_ipv4_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_CORE("SR-ERO IPv4-Node addr for subobject %i: %s", i, inet_ntoa(addr));
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                TRACE_CORE("SR-ERO NAI is Node IPv6 address");
                break;
#endif
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_local_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_CORE("SR-ERO IPv4-ADJ local addr for subobject %i: %s", i, inet_ntoa(addr));
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_CORE("SR-ERO IPv4-ADJ remote addr for subobject %i: %s", i, inet_ntoa(addr));
                
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                TRACE_CORE("SR-ERO NAI is ADJ IPv6 address");
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
                TRACE_CORE("SR-ERO NAI is Unnumbered address");
                break;
#endif
            default:
                TRACE_CORE("Unknown segment object NAI type: %d", 
                            sr_ero->rse_nai.rsen_type);
        }
    }
}

static void
pccd_core_print_srv6_ero_info(rpd_sr_ero_list_t *rpd_sr_ero)
{
    TRACE_CORE("Number of SRv6-ERO subobjects: %d", rpd_sr_ero->rsel_n_eros);
    for (unsigned i = 0; i < rpd_sr_ero->rsel_n_eros; i++) {
        rpd_sr_ero_t *srv6_ero  = &rpd_sr_ero->rsel_ero[i];
        TRACE_CORE("SRv6-ERO loose_type: %d, sid_verification: %d, "
                "sid structure valid: %d, endpoint behavior: %d",
                srv6_ero->rse_srv6_loose, srv6_ero->rse_srv6_sid_verification,
                srv6_ero->rse_srv6_sid_structure_valid, srv6_ero->rse_srv6_endpoint_behavior);
        TRACE_CORE("SRv6-ERO SID label type: %d", srv6_ero->rse_sid.rses_type);
        switch(srv6_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                TRACE_CORE("SID is absent");
                break;
            case RPD_SR_ERO_SID_TYPE_SRV6: {
                char sidstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_sid.u.rses_addr, sidstr_ipv6, sizeof(sidstr_ipv6));
                TRACE_CORE("SR-ERO sid value: %s", sidstr_ipv6);
            }
                break;
            default:
                TRACE_CORE("Unknown SID type is received");
                LOGGING_ERR("Unknown SID type is received");
        }
        TRACE_CORE("SRv6-ERO NAI type: %d", srv6_ero->rse_nai.rsen_type);
        switch(srv6_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                TRACE_CORE("NAI is absent in SRv6 ERO");
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID: {
                char nodeidstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_node_ipv6_addr, nodeidstr_ipv6, sizeof(nodeidstr_ipv6));

                TRACE_CORE("SRv6-ERO IPv6-Node addr for subobject %i: %s", i, nodeidstr_ipv6);
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                TRACE_CORE("SRv6-ERO IPv6-ADJ local addr for subobject %i: %s", i, localipstr_ipv6);
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                TRACE_CORE("SRv6-ERO IPv6-ADJ remote addr for subobject %i: %s", i, remoteipstr_ipv6);
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                TRACE_CORE("SRv6-ERO IPv6-ADJ local addr, interface id for subobject %i: %s, %u",
                        i, localipstr_ipv6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id);
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                TRACE_CORE("SRv6-ERO IPv6-ADJ remote addr, interface id for subobject %i: %s, %u",
                        i, remoteipstr_ipv6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id);
            }
                break;
            default:
                TRACE_CORE("Unknown segment object NAI type: %d",
                            srv6_ero->rse_nai.rsen_type);
        }

        if (srv6_ero->rse_srv6_sid_structure_valid) {
            TRACE_CORE("SRv6-ERO sid structure: lb length: %d, ln length: %d"
                       "function length: %d, arg length: %d",
                       srv6_ero->rse_srv6_sid_structure.lb_length,
                       srv6_ero->rse_srv6_sid_structure.ln_length,
                       srv6_ero->rse_srv6_sid_structure.fun_length,
                       srv6_ero->rse_srv6_sid_structure.arg_length);
        }
    }
}

static int
pccd_core_rpd_to_sr_ero(struct pcep_obj_ero *ero, rpd_sr_ero_list_t* rpd_sr_ero)
{
    uint32_t len = 0;
    unsigned sr_ero_count = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(ero != NULL);
    INSIST_ERR(rpd_sr_ero != NULL);

    pccd_core_print_sr_ero_info(rpd_sr_ero);

    len = RPD_SR_ERO_LIST_LEN(rpd_sr_ero);
    LOGGING_INFO("Reported SR-ERO object length is: %d",len);
    sr_ero_count = rpd_sr_ero->rsel_n_eros;
    ero->subcount = (uint8_t)sr_ero_count;
    ero->path_attribs.path_id = rpd_sr_ero->rsel_path_id;
    ero->path_attribs.weight = rpd_sr_ero->rsel_weight;
    if (rpd_sr_ero->resel_path_flags & LSP_PATH_TYPE_PRIMARY) {
        ero->path_attribs.secondary_path = false;
    } else {
        ero->path_attribs.secondary_path = true;
    }
    ero->path_attribs.op_state = rpd_sr_ero->rsel_op_state;
    LOGGING_INFO(" PCRpt - sr ero details: sending path_id: %u "
                 "weight: %u Path_type: %s Operational_state: %u",
                 ero->path_attribs.path_id, ero->path_attribs.weight,
                 (ero->path_attribs.secondary_path? "Secondary" : "Primary"),
                 ero->path_attribs.op_state);
    for (i = 0; i < sr_ero_count; i++ ) {
        struct pcep_obj_ero_sub *sub = &ero->subs[i];
        rpd_sr_ero_t *sr_ero  = &rpd_sr_ero->rsel_ero[i];
        sub->loose = sr_ero->rse_loose;
        
        sub->type = PCEP_ERO_SUB_SR;
        switch(sr_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                sub->data.sr_ero.S_bit = 0x1;
                sub->data.sr_ero.sid = 0;
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
                sub->data.sr_ero.M_bit = 0x1;
                sub->data.sr_ero.sid = ntohl(sr_ero->rse_sid.u.rses_label_20);
                sub->data.sr_ero.sid = sub->data.sr_ero.sid << 12;
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
                sub->data.sr_ero.M_bit = 0x1;
                sub->data.sr_ero.C_bit = 0x1;
                sub->data.sr_ero.sid = ntohl(sr_ero->rse_sid.u.rses_label_32);
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
                sub->data.sr_ero.sid = ntohl(sr_ero->rse_sid.u.rses_index);
                break;
            default:
                LOGGING_ERR("Unknown SID type is received");
        }

        switch(sr_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_ABSENT;
                sub->data.sr_ero.F_bit = 0x1;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID;
                memcpy(&sub->data.sr_ero.NAI_data.ipv4_node_id.address, 
                       &sr_ero->rse_nai.u.rsen_node_ipv4_addr, 4);
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(&sub->data.sr_ero.NAI_data.ipv6_node_id.address, 
                       sr_ero->rse_nai.u.rsen_node_ipv6_addr, 16);
                break;
#endif
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ;
                memcpy(&sub->data.sr_ero.NAI_data.ipv4_adjacency.local, 
                       &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_local_addr, 4);
                memcpy(&sub->data.sr_ero.NAI_data.ipv4_adjacency.remote, 
                       &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr, 4);
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ;
                memcpy(&sub->data.sr_ero.NAI_data.ipv6_adjacency.local, 
                       sr_ero->rse_nai.u.rsen_adj_ipv6.rsen_local_addr, 16);
                memcpy(&sub->data.sr_ero.NAI_data.ipv6_adjacency.remote, 
                       sr_ero->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr, 16);
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
                sub->data.sr_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_UNNUMBERED;
                sub->data.sr_ero.NAI_data.unnum_adj.local_node_id = 
                          ntohl(sr_ero->rse_nai.u.rsen_unnumbered.rsen_local_node_id);
                sub->data.sr_ero.NAI_data.unnum_adj.local_interface_id =
                          ntohl(sr_ero->rse_nai.u.rsen_unnumbered.rsen_local_intf_id);
                sub->data.sr_ero.NAI_data.unnum_adj.remote_node_id = 
                          ntohl(sr_ero->rse_nai.u.rsen_unnumbered.rsen_remote_node_id);
                sub->data.sr_ero.NAI_data.unnum_adj.remote_interface_id =
                          ntohl(sr_ero->rse_nai.u.rsen_unnumbered.rsen_remote_intf_id);
                break;
#endif
            default:
                LOGGING_ERR("Unknown segment object NAI type: %ux", 
                            sr_ero->rse_nai.rsen_type);
                TRACE_FUNCTION_RETURN(-1);
        }
    }

    TRACE_CORE("SR-ERO count: %d", sr_ero_count);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_rpd_to_srv6_ero(struct pcep_obj_ero *ero, rpd_sr_ero_list_t* rpd_sr_ero_list)
{
    uint32_t len = 0;
    unsigned srv6_ero_count = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(ero != NULL);
    INSIST_ERR(rpd_sr_ero_list != NULL);

    pccd_core_print_srv6_ero_info(rpd_sr_ero_list);

    len = RPD_SR_ERO_LIST_LEN(rpd_sr_ero_list);
    LOGGING_INFO("Reported SR-ERO object length is: %d",len);
    srv6_ero_count = rpd_sr_ero_list->rsel_n_eros;
    ero->subcount = (uint8_t)srv6_ero_count;
    ero->path_attribs.path_id = rpd_sr_ero_list->rsel_path_id;
    ero->path_attribs.weight = rpd_sr_ero_list->rsel_weight;
    if (rpd_sr_ero_list->resel_path_flags & LSP_PATH_TYPE_PRIMARY) {
        ero->path_attribs.secondary_path = false;
    } else {
        ero->path_attribs.secondary_path = true;
    }
    ero->path_attribs.op_state = rpd_sr_ero_list->rsel_op_state;
    LOGGING_INFO(" PCRpt - srv6 ero details: sending path_id: %u "
                 "weight: %u Path_type: %s Operational_state:%u",
                 ero->path_attribs.path_id, ero->path_attribs.weight,
                 (ero->path_attribs.secondary_path? "Secondary" : "Primary"),
                 ero->path_attribs.op_state);
    for (i = 0; i < srv6_ero_count; i++ ) {
        struct pcep_obj_ero_sub *sub = &ero->subs[i];
        rpd_sr_ero_t *srv6_ero  = &rpd_sr_ero_list->rsel_ero[i];
        sub->loose = srv6_ero->rse_srv6_loose;
        sub->data.srv6_ero.endpoint_behavior = srv6_ero->rse_srv6_endpoint_behavior;
        sub->data.srv6_ero.V_bit = srv6_ero->rse_srv6_sid_verification;
        sub->data.srv6_ero.T_bit = srv6_ero->rse_srv6_sid_structure_valid;
        sub->data.srv6_ero.F_bit = 0;
        sub->data.srv6_ero.S_bit = 0;

        sub->type = srv6_ero_subobject_type;
        switch(srv6_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                sub->data.srv6_ero.S_bit = 0x1;
                memset(&sub->data.srv6_ero.sid,
                       0, 16);
                break;
            case RPD_SR_ERO_SID_TYPE_SRV6:
                memcpy(&sub->data.srv6_ero.sid,
                       srv6_ero->rse_sid.u.rses_addr, 16);
                break;
            default:
                LOGGING_ERR("Unknown SID type is received");
        }

        switch(srv6_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                sub->data.srv6_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_ABSENT;
                sub->data.srv6_ero.F_bit = 0x1;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                sub->data.srv6_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(&sub->data.srv6_ero.NAI_data.ipv6_node_id.address,
                       srv6_ero->rse_nai.u.rsen_node_ipv6_addr, 16);
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                sub->data.srv6_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ;
                memcpy(&sub->data.srv6_ero.NAI_data.ipv6_adjacency.local,
                       srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_local_addr, 16);
                memcpy(&sub->data.srv6_ero.NAI_data.ipv6_adjacency.remote,
                       srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr, 16);
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                sub->data.srv6_ero.nai_type = PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ;
                memcpy(&sub->data.srv6_ero.NAI_data.ipv6_linklocal_adj.local_ipv6_addr,
                        srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr, 16);
                sub->data.srv6_ero.NAI_data.ipv6_linklocal_adj.local_interface_id =
                          srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id;
                memcpy(&sub->data.srv6_ero.NAI_data.ipv6_linklocal_adj.remote_ipv6_addr,
                        srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr, 16);
                sub->data.srv6_ero.NAI_data.ipv6_linklocal_adj.remote_interface_id =
                          srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id;
                break;
            default:
                LOGGING_ERR("Unknown segment object NAI type: %ux",
                            srv6_ero->rse_nai.rsen_type);
                TRACE_FUNCTION_RETURN(-1);
        }

        if (sub->data.srv6_ero.T_bit) {
            sub->data.srv6_ero.sid_structure.lb_length = srv6_ero->rse_srv6_sid_structure.lb_length;
            sub->data.srv6_ero.sid_structure.ln_length = srv6_ero->rse_srv6_sid_structure.ln_length;
            sub->data.srv6_ero.sid_structure.fun_length = srv6_ero->rse_srv6_sid_structure.fun_length;
            sub->data.srv6_ero.sid_structure.arg_length = srv6_ero->rse_srv6_sid_structure.arg_length;
        }
    }

    TRACE_CORE("SRv6-ERO count: %d", srv6_ero_count);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_ro_to_ero (struct pcep_obj_ero *ero, const RouteObj *obj)
{
    const OBJ_HDR *hdr = NULL;
    const uint8_t *beyond_byte = NULL;
    const ro_entry *ro = NULL;
    struct pcep_obj_ero_sub *sub = NULL;
    unsigned int len = 0;
    unsigned ero_idx = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(ero != NULL);
    INSIST_ERR(obj != NULL);

    hdr = &obj->hdr;
    len = ntohs(hdr->obj_length) - sizeof(OBJ_HDR);

    if (ntohs(hdr->obj_length) <= sizeof(OBJ_HDR)) {
        LOGGING_ERR("Reported ERO object length is too small: %d",
                    ntohs(hdr->obj_length));
        TRACE_FUNCTION_RETURN(-1);
    }

    TRACE_CORE("RPD's RouteObject class %d type %d", hdr->obj_class,
               hdr->obj_ctype);

    beyond_byte = (const uint8_t*)(obj->entry) + len;
    ro = (const ro_entry *) obj->entry;
    sub = &ero->subs[ero_idx++];
    while ((const uint8_t *)ro < beyond_byte) {
        if (!pccd_ro_validate_entry(ro)) {
            LOGGING_ERR("Could not validate ro entry, type: 0x%x", ro->type);
            TRACE_FUNCTION_RETURN(-1);
        }

        switch(ro->type & 0x7f) {
        case RO_TYPE_IPV4:{
            const ro_entry_v4 *v4 = (const ro_entry_v4 *)ro;
            struct in_addr addr;

            if (ro->len != sizeof(*v4)) {
                LOGGING_ERR("IPV4 routing object entry of bad length: %d",
                            ro->len);
                TRACE_FUNCTION_RETURN(-1);
            }
            if (type_loose(ro->type)) {
                sub->loose = true;
            }
            sub->type = PCEP_ERO_SUB_IPV4;
            memcpy(&sub->data.ipv4_prefix.address, &v4->node,
                   sizeof(sub->data.ipv4_prefix.address));
            sub->data.ipv4_prefix.prefix_length = v4->mask;
            memcpy(&addr.s_addr, &v4->node, sizeof(addr.s_addr));
            TRACE_CORE("Added IPV4 RO to ERO subobject %i: %s", ero_idx-1,
                       inet_ntoa(addr));
            break;
        }
        case RO_TYPE_IPV6:
            LOGGING_ERR("Received IPV6 routing object type from RPD - "
                        "unimplemented");
            abort();
        case RO_TYPE_UNNUM: {
            const ro_entry_unnum *unnum =
                              (const ro_entry_unnum *)(const void *)ro;
            struct in_addr addr;

            if (ro->len != sizeof(*unnum)) {
                LOGGING_ERR("Unnumbered interface routing object entry "
                        "of bad length: %d", ro->len);
                TRACE_FUNCTION_RETURN(-1);
            }
            sub->loose = false;
            sub->type = PCEP_ERO_SUB_UNNUMBERED_IID;
            sub->data.unnumbered_iid.router_id = unnum->rtr_id;
            sub->data.unnumbered_iid.interface_id = ntohl(unnum->if_id);

            memcpy(&addr.s_addr, &unnum->rtr_id, sizeof(addr.s_addr));
            TRACE_CORE("Added UNNUMBERED IF/ID to ERO subobject %i: ,"
                    "RID: %s, IFID: %lu", (ero_idx-1), inet_ntoa(addr),
                    ntohl(unnum->if_id));
            break;
        }
        default:
            LOGGING_ERR("Unknown routing object entry type: %ux", ro->type);
            TRACE_FUNCTION_RETURN(-1);
        }

        ro = (const ro_entry*)(((const uint8_t *) ro) + ro->len);
        sub = &ero->subs[ero_idx++];
    }

    ero->subcount = (uint8_t)(--ero_idx); // lower the ero_idx by one so that it reflects count
    TRACE_CORE("ERO count: %d", ero->subcount);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_rpd_to_sr_rro(struct pcep_obj_rro *rro, rpd_sr_ero_list_t* rpd_sr_rro)
{
    uint32_t len = 0;
    unsigned sr_rro_count =0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(rro != NULL);
    INSIST_ERR(rpd_sr_rro != NULL);
    
    pccd_core_print_sr_ero_info(rpd_sr_rro);

    len = RPD_SR_ERO_LIST_LEN(rpd_sr_rro);
    LOGGING_INFO("Reported SR-RRO object length is: %d",len);
    sr_rro_count = rpd_sr_rro->rsel_n_eros;
    rro->subcount = (uint8_t)sr_rro_count;
    rro->path_attribs.path_id = rpd_sr_rro->rsel_path_id;
    rro->path_attribs.weight = rpd_sr_rro->rsel_weight;
    if (rpd_sr_rro->resel_path_flags & LSP_PATH_TYPE_PRIMARY) {
        rro->path_attribs.secondary_path = false;
    } else {
        rro->path_attribs.secondary_path = true;
    }
    rro->path_attribs.op_state = rpd_sr_rro->rsel_op_state;
    LOGGING_INFO(" PCRpt - sr rro details: sending path_id: %u "
                 "weight: %u Path_type: %s Operational_state:%u",
                 rro->path_attribs.path_id, rro->path_attribs.weight,
                 (rro->path_attribs.secondary_path? "Secondary" : "Primary"),
                 rro->path_attribs.op_state);
    for (i = 0; i < sr_rro_count; i++ ) {
        struct pcep_obj_rro_sub *sub = &rro->subs[i];
        rpd_sr_ero_t *sr_rro  = &rpd_sr_rro->rsel_ero[i];
        sub->loose = sr_rro->rse_loose;
        
        sub->type = PCEP_RRO_SUB_SR;
        switch(sr_rro->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                sub->data.sr_rro.S_bit = 0x1;
                sub->data.sr_rro.sid = 0;
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
                sub->data.sr_rro.M_bit = 0x1;
                sub->data.sr_rro.sid = ntohl(sr_rro->rse_sid.u.rses_label_20);
                sub->data.sr_rro.sid = sub->data.sr_rro.sid << 12;
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
                sub->data.sr_rro.M_bit = 0x1;
                sub->data.sr_rro.C_bit = 0x1;
                sub->data.sr_rro.sid = ntohl(sr_rro->rse_sid.u.rses_label_32);
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
                sub->data.sr_rro.sid = ntohl(sr_rro->rse_sid.u.rses_index);
                break;
            default:
                LOGGING_ERR("Unknown SID type is received");
        }

        switch(sr_rro->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_ABSENT;
                sub->data.sr_rro.F_bit = 0x1;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID;
                memcpy(&sub->data.sr_rro.NAI_data.ipv4_node_id.address, 
                       &sr_rro->rse_nai.u.rsen_node_ipv4_addr, 4);
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(&sub->data.sr_rro.NAI_data.ipv6_node_id.address, 
                       sr_rro->rse_nai.u.rsen_node_ipv6_addr, 16);
                break;
#endif
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ;
                memcpy(&sub->data.sr_rro.NAI_data.ipv4_adjacency.local, 
                       &sr_rro->rse_nai.u.rsen_adj_ipv4.rsen_local_addr, 4);
                memcpy(&sub->data.sr_rro.NAI_data.ipv4_adjacency.remote, 
                       &sr_rro->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr, 4);
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ;
                memcpy(&sub->data.sr_rro.NAI_data.ipv6_adjacency.local, 
                       sr_rro->rse_nai.u.rsen_adj_ipv6.rsen_local_addr, 16);
                memcpy(&sub->data.sr_rro.NAI_data.ipv6_adjacency.remote, 
                       sr_rro->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr, 16);
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
                sub->data.sr_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_UNNUMBERED;
                sub->data.sr_rro.NAI_data.unnum_adj.local_node_id = 
                          ntohl(sr_rro->rse_nai.u.rsen_unnumbered.rsen_local_node_id);
                sub->data.sr_rro.NAI_data.unnum_adj.local_interface_id =
                          ntohl(sr_rro->rse_nai.u.rsen_unnumbered.rsen_local_intf_id);
                sub->data.sr_rro.NAI_data.unnum_adj.remote_node_id = 
                          ntohl(sr_rro->rse_nai.u.rsen_unnumbered.rsen_remote_node_id);
                sub->data.sr_rro.NAI_data.unnum_adj.remote_interface_id =
                          ntohl(sr_rro->rse_nai.u.rsen_unnumbered.rsen_remote_intf_id);
                break;
#endif
            default:
                LOGGING_ERR("Unknown segment object NAI type: %ux", 
                            sr_rro->rse_nai.rsen_type);
                TRACE_FUNCTION_RETURN(-1);
        }
    }

    TRACE_CORE("SR-RRO count: %d", sr_rro_count);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_rpd_to_srv6_rro (struct pcep_obj_rro *rro, rpd_sr_ero_list_t* rpd_sr_rro_list)
{
    uint32_t len = 0;
    unsigned srv6_rro_count = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(rro != NULL);
    INSIST_ERR(rpd_sr_rro_list != NULL);

    pccd_core_print_srv6_ero_info(rpd_sr_rro_list);

    len = RPD_SR_ERO_LIST_LEN(rpd_sr_rro_list);
    LOGGING_INFO("Reported SR-ERO object length is: %d",len);
    srv6_rro_count = rpd_sr_rro_list->rsel_n_eros;
    rro->subcount = (uint8_t)srv6_rro_count;
    rro->path_attribs.path_id = rpd_sr_rro_list->rsel_path_id;
    rro->path_attribs.weight = rpd_sr_rro_list->rsel_weight;
    if (rpd_sr_rro_list->resel_path_flags & LSP_PATH_TYPE_PRIMARY) {
        rro->path_attribs.secondary_path = false;
    } else {
        rro->path_attribs.secondary_path = true;
    }
    rro->path_attribs.op_state = rpd_sr_rro_list->rsel_op_state;
    LOGGING_INFO(" PCRpt - srv6 rro details: sending path_id: %u "
                 "weight: %u Path_type: %s Operational_state:%u ",
                 rro->path_attribs.path_id, rro->path_attribs.weight,
                 (rro->path_attribs.secondary_path? "Secondary" : "Primary"),
                 rro->path_attribs.op_state);
    for (i = 0; i < srv6_rro_count; i++ ) {
        struct pcep_obj_rro_sub *sub = &rro->subs[i];
        rpd_sr_ero_t *srv6_rro  = &rpd_sr_rro_list->rsel_ero[i];
        sub->loose = srv6_rro->rse_srv6_loose;
        sub->data.srv6_rro.endpoint_behavior = srv6_rro->rse_srv6_endpoint_behavior;
        sub->data.srv6_rro.V_bit = srv6_rro->rse_srv6_sid_verification;
        sub->data.srv6_rro.T_bit = srv6_rro->rse_srv6_sid_structure_valid;
        sub->data.srv6_rro.F_bit = 0;
        sub->data.srv6_rro.S_bit = 0;

        sub->type = srv6_rro_subobject_type;
        switch(srv6_rro->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                sub->data.srv6_rro.S_bit = 0x1;
                memset(&sub->data.srv6_rro.sid,
                       0, 16);
                break;
            case RPD_SR_ERO_SID_TYPE_SRV6:
                memcpy(&sub->data.srv6_rro.sid,
                       srv6_rro->rse_sid.u.rses_addr, 16);
                break;
            default:
                LOGGING_ERR("Unknown SID type is received");
        }

        switch(srv6_rro->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                sub->data.srv6_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_ABSENT;
                sub->data.srv6_rro.F_bit = 0x1;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                sub->data.srv6_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(&sub->data.srv6_rro.NAI_data.ipv6_node_id.address,
                       srv6_rro->rse_nai.u.rsen_node_ipv6_addr, 16);
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                sub->data.srv6_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ;
                memcpy(&sub->data.srv6_rro.NAI_data.ipv6_adjacency.local,
                       srv6_rro->rse_nai.u.rsen_adj_ipv6.rsen_local_addr, 16);
                memcpy(&sub->data.srv6_rro.NAI_data.ipv6_adjacency.remote,
                       srv6_rro->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr, 16);
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                sub->data.srv6_rro.nai_type = PCEP_SR_RRO_NAI_TYPE_IPV6_LINKLOCAL_ADJ;
                memcpy(&sub->data.srv6_rro.NAI_data.ipv6_linklocal_adj.local_ipv6_addr,
                        srv6_rro->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr, 16);
                sub->data.srv6_rro.NAI_data.ipv6_linklocal_adj.local_interface_id =
                          srv6_rro->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id;
                memcpy(&sub->data.srv6_rro.NAI_data.ipv6_linklocal_adj.remote_ipv6_addr,
                        srv6_rro->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr, 16);
                sub->data.srv6_rro.NAI_data.ipv6_linklocal_adj.remote_interface_id =
                          srv6_rro->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id;
                break;
            default:
                LOGGING_ERR("Unknown segment object NAI type: %ux",
                            srv6_rro->rse_nai.rsen_type);
                TRACE_FUNCTION_RETURN(-1);
        }

        if (sub->data.srv6_rro.T_bit) {
            sub->data.srv6_rro.sid_structure.lb_length = srv6_rro->rse_srv6_sid_structure.lb_length;
            sub->data.srv6_rro.sid_structure.ln_length = srv6_rro->rse_srv6_sid_structure.ln_length;
            sub->data.srv6_rro.sid_structure.fun_length = srv6_rro->rse_srv6_sid_structure.fun_length;
            sub->data.srv6_rro.sid_structure.arg_length = srv6_rro->rse_srv6_sid_structure.arg_length;
        }
    }

    TRACE_CORE("SRv6-RRO count: %d", srv6_rro_count);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_ro_to_rro (struct pcep_obj_rro *rro, const RouteObj *obj)
{
    const OBJ_HDR *hdr = NULL;
    unsigned int len = 0;
    const uint8_t *beyond_byte = NULL;
    const ro_entry *ro = NULL;
    unsigned rro_idx = 0;
    struct pcep_obj_rro_sub *sub = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(rro != NULL);
    INSIST_ERR(obj != NULL);

    hdr = &obj->hdr;
    len = ntohs(hdr->obj_length) - sizeof(OBJ_HDR);

    if (ntohs(hdr->obj_length) <= sizeof(OBJ_HDR)) {
        LOGGING_ERR("Reported RRO object length is too small: %d",
                    ntohs(hdr->obj_length));
        TRACE_FUNCTION_RETURN(-1);
    }

    TRACE_CORE("RPD's RouteObject class %d type %d", hdr->obj_class,
               hdr->obj_ctype);

    beyond_byte = (const uint8_t*)(obj->entry) + len;
    ro = (const ro_entry *) obj->entry;
    sub = &rro->subs[rro_idx++];
    while ((const uint8_t *)ro < beyond_byte) {
        if (!pccd_ro_validate_entry(ro)) {
            LOGGING_ERR("Could not validate ro entry, type: 0x%x", ro->type);
            TRACE_FUNCTION_RETURN(-1);
        }

        switch(ro->type & 0x7f) {
        case RO_TYPE_IPV4:{
            const ro_entry_v4 *v4 = (const ro_entry_v4 *)ro;
            if (ro->len != sizeof(*v4)) {
                LOGGING_ERR("IPV4 routing object entry of bad length: %d",
                            ro->len);
                TRACE_FUNCTION_RETURN(-1);
            }
            if (type_loose(ro->type)) {
                sub->loose = true;
            }
            sub->type = PCEP_RRO_SUB_IPV4;
            memcpy(&sub->data.ipv4_address.address, &v4->node,
                   sizeof(sub->data.ipv4_address.address));
            TRACE_CORE("Added IPV4 RO to RRO subobject %i: %s", rro_idx-1,
                       inet_ntoa(sub->data.ipv4_address.address));
            TRACE_CORE("Mask  hex value is: 0x%x", v4->mask);
	    TRACE_CORE("Flags hex value is: 0x%x", v4->flags);
	    sub->data.ipv4_address.flags = v4->flags;
	    sub->data.ipv4_address.lprot_available = is_bit_set(v4->flags, 0);
	    sub->data.ipv4_address.lprot_inuse = is_bit_set(v4->flags, 1);
	    TRACE_CORE("Link protection available: %u", 
		       sub->data.ipv4_address.lprot_available);
	    TRACE_CORE("Link protection in use: %u", 
		       sub->data.ipv4_address.lprot_inuse);
            break;
        }
        case RO_TYPE_IPV6:
            LOGGING_ERR("Received IPV6 routing object type from RPD - "
                        "unimplemented");
            abort();
        case RO_TYPE_UNNUM: {
            struct in_addr addr;
            const ro_entry_unnum *unnum =
                              (const ro_entry_unnum *)(const void *) ro;

            if (ro->len != sizeof(*unnum)) {
                LOGGING_ERR("Unnumbered interface routing object entry "
                        "of bad length: %d", ro->len);
                TRACE_FUNCTION_RETURN(-1);
            }
            if (type_loose(ro->type)) {
                sub->loose = true;
            }
            sub->type = PCEP_RRO_SUB_UNNUMBERED_IID;
            sub->data.unnumbered_iid.router_id = unnum->rtr_id;
            sub->data.unnumbered_iid.interface_id = ntohl(unnum->if_id);

            memcpy(&addr.s_addr, &unnum->rtr_id, sizeof(addr.s_addr));
            TRACE_CORE("Added UNNUMBERED IF/ID to RRO subobject %i: "
                    "RID: %s, IFID: %lu", rro_idx-1, inet_ntoa(addr),
                    ntohl(unnum->if_id));
            break;
        }
        case RO_LABEL: {
            const struct ro_entry_label *label =
                    (const struct ro_entry_label *)(const void *)ro;
            if (ro->len != sizeof(*label)) {
                LOGGING_ERR("Label routing object entry has invalid length: "
                        "%d", ro->len);
                TRACE_FUNCTION_RETURN(-1);
            }
            sub->type = PCEP_RRO_SUB_LABEL;
            sub->data.label.ctype = label->ctype;
            sub->data.label.label = ntohl(label->label);
            sub->data.label.upstream = false;
            sub->data.label.global_label = (
                    label->flag && RRO_GLOBAL_LABEL) == RRO_GLOBAL_LABEL;
            TRACE_CORE("Added LABEL to RRO subobject %i: "
                       "ctype: %hhu label: %"PRIu32" "
                       "upstream: '%s' global-label: '%s'", rro_idx-1,
                       sub->data.label.ctype, sub->data.label.label,
                       sub->data.label.upstream ? "true" : "false",
                       sub->data.label.global_label ? "true" : "false");
            break;
        }
        default:
            LOGGING_ERR("Unknown routing object entry type: %ux", ro->type);
            TRACE_FUNCTION_RETURN(-1);
        }

        ro = (const ro_entry*)(((const uint8_t *) ro) + ro->len);
        sub = &rro->subs[rro_idx++];
    }

    rro->subcount = (uint8_t)(--rro_idx);    // lower the rro_idx by one so that it reflects count
    TRACE_CORE("RRO count: %d", rro->subcount);

    TRACE_FUNCTION_RETURN(0);
}

static bool
pccd_core_send_message(struct pce_cfg_core *pce, pcep_msg_t type,
                       const struct pcep_object *objs, size_t count)
{
    bool ret = FALSE;

    if (pce->pc_state < PCE_STATE_SYNC) {
        TRACE_CORE("Could not send out message %s to PCE '%s' as it is in %s", 
                   pcep_msg_type_to_str(type), pce->pc_pce.pce_id, 
                   pccd_core_get_pce_state_name(pce));
        return true;
    }

    ret = pcep_send_message(pce->pc_conn, type, objs, count);
    if (ret) {
        return true;
    }

    switch (type) {
    case PCEP_MSG_PC_REPORT :
        if (!pccd_add_timed_stat(&pce->pc_statistics.pc_rpts)) {
	    LOGGING_ERR("Adding timed stat for PCRpt failed.");
	}
        break;
    case PCEP_MSG_PC_REQUEST :
        if (!pccd_add_timed_stat(&pce->pc_statistics.pc_reqs)) {
	    LOGGING_ERR("Addign timed stat for PCReq failed.");
	}
        break;
    default :
        break;
    }

    return false;
}

static int
pccd_core_report_empty_lsp (struct pce_cfg_core *pce, uint32_t srp_id)
{
    struct pcep_object objs[3]; // SRP, LSP and ERO
    daemon_trace_file_options_t *dtfo = NULL;
    struct pcep_obj_lsp *lsp = NULL;
    int obj_index = 0;
    uint32_t dummy_1 = 0;
    uint16_t dummy_2 = 0;

    TRACE_FUNCTION_ENTRY();
	
    memset(objs, 0, sizeof(objs));

    dtfo = pccd_core_pce_get_traceoptions(pce);

    // SRP object
    objs[obj_index].type = PCEP_OBJ_SRP;
    if (pccd_core_fill_srp(&objs[obj_index].u.srp, srp_id, RSVP)) {
        LOGGING_ERR("Could not create SRP object for Empty PCRpt");
        TRACE_FUNCTION_RETURN(-1);
    }
    
    // LSP object
    objs[++obj_index].type = PCEP_OBJ_LSP;

    lsp = &objs[obj_index].u.lsp;
    bzero(lsp, sizeof (struct pcep_obj_lsp));

    lsp->plsp_id = PLSPID_RESERVED;

    /* Sending IPV4-LSP-IDENTIFIERS TLV */
    lsp->lsp_identifiers_len = 16;
    memcpy(lsp->lsp_identifiers,     &dummy_1, sizeof(uint32_t));
    memcpy(lsp->lsp_identifiers + 4, &dummy_2, sizeof(uint16_t));
    memcpy(lsp->lsp_identifiers + 6, &dummy_2, sizeof(uint16_t));
    memcpy(lsp->lsp_identifiers + 8, &dummy_1, sizeof(uint32_t));
    memcpy(lsp->lsp_identifiers + 12, &dummy_1, sizeof(uint32_t));	

    // ERO object (empty ERO)
    objs[++obj_index].type = PCEP_OBJ_ERO;
    objs[obj_index].u.ero.subcount = 0;
    
    TRACE_PCEP(dtfo, "Sending message objs %p count: %u to pce '%s'", objs,
               obj_index, pce->pc_pce.pce_id);
    if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, objs, ++obj_index)) {
        LOGGING_ERR("Could not send PCRpt message to PCE '%s'",
                    pce->pc_pce.pce_id);
        TRACE_FUNCTION_RETURN(-1);
    }
    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the ero obj in PCRpt
 */
static int
pccd_core_fill_ero (struct pcep_obj_ero            *ero,
                    const struct pccd_rpd_lsp_info *rpd_lsp,
                    uint32_t                        iter)
{
    uint32_t count = 0;

    TRACE_FUNCTION_ENTRY();     
    if (rpd_lsp->ero_info 
        && ((rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
            || (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE))) {
        if (rpd_lsp->ero_len < sizeof(OBJ_HDR)) {
 		    LOGGING_ERR("ERO data len %d is incomplete",
 			            rpd_lsp->ero_len);
 		        TRACE_FUNCTION_RETURN(-1);
 	        }
 	        if (pccd_core_ro_to_ero(ero, rpd_lsp->ero_info)) {
 		        TRACE_FUNCTION_RETURN(-1);
             }
    } else if (rpd_lsp->srte_ero_info) {
        rpd_sr_ero_list_t *srte_ero_info = (rpd_sr_ero_list_t *) rpd_lsp->srte_ero_info;
        while (count < iter) {
            srte_ero_info = (rpd_sr_ero_list_t *)&(srte_ero_info->rsel_ero[srte_ero_info->rsel_n_eros]);
            count++;
        }
        if (srte_ero_info->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
            if (pccd_core_rpd_to_sr_ero(ero, srte_ero_info)) {
                TRACE_FUNCTION_RETURN(-1);
            }
        } else if(srte_ero_info->rsel_type == RPD_SR_ERO_LIST_SRV6) {
            if(pccd_core_rpd_to_srv6_ero(ero, srte_ero_info)) {
                TRACE_CORE("Failed to fill SRv6-ERO info");
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }
    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the lspa in PCRpt
 */
static int
pccd_core_fill_lspa(struct pcep_obj_lspa *lspa,
                   const struct pccd_rpd_lsp_info *rpd_lsp)
{
    TRACE_FUNCTION_ENTRY();
    lspa->hold_prio = rpd_lsp->hold_prio;
    lspa->setup_prio = rpd_lsp->setup_prio;
    lspa->pol_exclude_any = rpd_lsp->prli_admin_grp_exclude_any;
    lspa->pol_include_any = rpd_lsp->prli_admin_grp_include_any;
    lspa->pol_include_all = rpd_lsp->prli_admin_grp_include_all;

    if (BIT_TEST(rpd_lsp->path_flags, LSP_PATH_LOCAL_PROTECTION_DESIRED)) {
        lspa->local_prot = TRUE;
    }

    /* PCE Initiated Bypass : begin */ 
    if (rpd_lsp->bypass_info.bp_nhaddr != 0) {
        lspa->bypass_tlv = TRUE;
        memcpy(&lspa->bypadd_ipv4_addr, &rpd_lsp->bypass_info.bp_nhaddr,
                       sizeof(struct in_addr));
        lspa->node_prot = rpd_lsp->bypass_info.bp_prot_type;
        lspa->local_prot_in_use = rpd_lsp->bypass_info.bp_prot_in_use;
        lspa->subsc_mul = rpd_lsp->bypass_info.bp_subscr;
    }
    /* PCE Initiated Bypass : end */ 
    
    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the bandwidth in PCRpt
 */
static int
pccd_core_fill_bandwidth (struct pcep_obj_bandwidth *lsp_bw,
                          const struct pccd_rpd_lsp_info *rpd_lsp)
{
    TRACE_FUNCTION_ENTRY();
    lsp_bw->bps = (float)rpd_lsp->bandwidth / 8;
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 * fill the bandwidth in PCRpt
 */
static int
pccd_core_fill_bandwidth_intended (struct pcep_obj_bandwidth *lsp_bw,
                                   const struct pccd_rpd_lsp_info *rpd_lsp)
{
    TRACE_FUNCTION_ENTRY();
    if ((LSP_TYPE_EXTERNALLY_PROVISIONED == rpd_lsp->type) 
        || (LSP_TYPE_EXTERNALLY_CONTROLLED == rpd_lsp->type)) {
        lsp_bw->bps = ((rpd_lsp->intended_attrs.bw_valid) ? ((float)rpd_lsp->intended_attrs.bw / 8) : 0);
    } else  {
        lsp_bw->bps = (float)rpd_lsp->configured_bandwidth / 8;
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 * fill the RRO in PCRpt
 */
static int
pccd_core_fill_rro (struct pcep_obj_rro            *lsp_rro,
                    const struct pccd_rpd_lsp_info *rpd_lsp,
                    uint32_t                        iter)
{
    uint32_t count = 0;

    TRACE_FUNCTION_ENTRY();
    if (rpd_lsp->rro_info 
        && ((rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
            || (rpd_lsp->setup_type 
                               == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE))) {
        if (rpd_lsp->rro_len < sizeof(OBJ_HDR)) {
 		    LOGGING_ERR("RRO data len %d is incomplete",
 			            rpd_lsp->rro_len);
 		        TRACE_FUNCTION_RETURN(-1);
 	        }
 	        if (pccd_core_ro_to_rro(lsp_rro, rpd_lsp->rro_info)) {
 		        TRACE_FUNCTION_RETURN(-1);
             }
    } else if (rpd_lsp->srte_rro_info) {
        rpd_sr_ero_list_t *srte_rro_info = (rpd_sr_ero_list_t *) rpd_lsp->srte_rro_info;
        while (count < iter) {
            srte_rro_info = (rpd_sr_ero_list_t *)&(srte_rro_info->rsel_ero[srte_rro_info->rsel_n_eros]);
            count++;
        }
        if (srte_rro_info->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
            if (pccd_core_rpd_to_sr_rro(lsp_rro, srte_rro_info)) {
                TRACE_FUNCTION_RETURN(-1);
            }
        } else if(srte_rro_info->rsel_type == RPD_SR_ERO_LIST_SRV6) {
            if(pccd_core_rpd_to_srv6_rro(lsp_rro, srte_rro_info)) {
                TRACE_CORE("Failed to fill SRv6-RRO info");
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }
    TRACE_FUNCTION_RETURN(0);
}

static uint16_t
pccd_core_convert_pcep_assoc_type_to_rpd_assoc_type(
                const uint16_t pcep_assoc_type)
{
    uint16_t rpd_assoc_type = LSP_ASSOCIATION_TYPE_MAX;
    if (ASSOCIATION_TYPE_PATH_PROTECTION == pcep_assoc_type) {
        rpd_assoc_type = LSP_ASSOCIATION_TYPE_PROTECTION;
    } else if (ASSOCIATION_TYPE_TE_PLUS_PLUS == pcep_assoc_type) {
        rpd_assoc_type = LSP_ASSOCIATION_TYPE_TE_PLUSPLUS;
    } else if (ASSOCIATION_TYPE_SRPAG == pcep_assoc_type) {
        rpd_assoc_type = LSP_ASSOCIATION_TYPE_SRPAG;
    } else if (ASSOCIATION_TYPE_DISJOINT == pcep_assoc_type) {
        rpd_assoc_type = LSP_ASSOCIATION_TYPE_DISJOINT;
    }

    return rpd_assoc_type;
}

/**
* Convert RPD association type to PCEP association type
*/
static uint16_t
pccd_core_convert_rpd_assoc_type_to_pcep_assoc_type(
                   const lsp_association_type rpd_assoc_type)
{
    uint16_t pcep_assoc_type = ASSOCIATION_TYPE_MAX;
    if (LSP_ASSOCIATION_TYPE_PROTECTION == rpd_assoc_type) {
        pcep_assoc_type = ASSOCIATION_TYPE_PATH_PROTECTION;
    } else if (LSP_ASSOCIATION_TYPE_TE_PLUSPLUS == rpd_assoc_type) {
        pcep_assoc_type = ASSOCIATION_TYPE_TE_PLUS_PLUS;
    } else if(LSP_ASSOCIATION_TYPE_SRPAG == rpd_assoc_type) {
        pcep_assoc_type = ASSOCIATION_TYPE_SRPAG;
    } else if(LSP_ASSOCIATION_TYPE_DISJOINT == rpd_assoc_type) {
        pcep_assoc_type = ASSOCIATION_TYPE_DISJOINT;
    }

    TRACE_CORE("RPD association type: %u,PCEP association type: %u",
        rpd_assoc_type, pcep_assoc_type);

    return pcep_assoc_type;
}

/**
 * fill nonRFC Association in PCRpt
 */
static int
pccd_core_fill_association_non_rfc(struct pcep_obj_association_non_rfc *assoc,
                           const lsp_association_info *assoc_info)
{
    TRACE_FUNCTION_ENTRY();
    assoc->type =
        (uint8_t) assoc_info->assoc_type;

    assoc->flag_remove =
        (uint8_t)(assoc_info->assoc_flags &
                  LSP_PATH_STATE_ASSOCIATION_REMOVED)?1:0;

    assoc->flag_standby =
        (uint8_t)(assoc_info->assoc_flags &
                  LSP_PATH_TYPE_SECONDARY_STANDBY)?1:0;

    assoc->flag_protection =
        (uint8_t)(assoc_info->assoc_flags &
                  LSP_PATH_TYPE_PRIMARY)?0:1;

    assoc->association_group_id =
        assoc_info->assoc_grp_id;

    TRACE_CORE("Assoc Type: %d, grpid: %d flag_stand_by: %d"
               " flag_protection: %d flags_remove: %d",
               assoc_info->assoc_type,
               assoc->association_group_id,
               assoc->flag_standby,
               assoc->flag_protection,
               assoc->flag_remove);
    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the Association in PCRpt
 */
static int
pccd_core_fill_association(struct pcep_obj_association *assoc,
                           const lsp_association_info *assoc_info)
{
    TRACE_FUNCTION_ENTRY();

    assoc->reserved = 0;
    assoc->flag_remove = (uint8_t)(assoc_info->assoc_flags &
                            LSP_PATH_STATE_ASSOCIATION_REMOVED) ? 1 : 0;

    assoc->association_type =
        pccd_core_convert_rpd_assoc_type_to_pcep_assoc_type(assoc_info->assoc_type);

    assoc->association_id = 0; //Default Value    

    memcpy(&assoc->ipv4_association_source, &assoc_info->assoc_source_u.v4,
                   sizeof(struct in_addr));

    if(ASSOCIATION_TYPE_PATH_PROTECTION == assoc->association_type) {
        assoc->path_protection = true;
        assoc->extended_assoc_id = true;

        assoc->path_protection_tlv.protection_type = 4;

        assoc->path_protection_tlv.unassigned_flags = 0;

        assoc->path_protection_tlv.flag_secondary =
            (uint8_t)(assoc_info->assoc_flags & LSP_PATH_TYPE_SECONDARY) ? 1 : 0;

        assoc->path_protection_tlv.flag_protection = 
            (uint8_t)(assoc_info->assoc_flags & LSP_PATH_TYPE_PRIMARY) ? 0 : 1;

        assoc->extended_assoc_id_tlv.extended_assoc_id = assoc_info->assoc_grp_id;

        TRACE_CORE("Path protection tlv info: Protection type: %u, unassigned flags: "
            "%u, secondary: %u, protection: %u. Extended assoc id tlv: "
            "Extended assoc id: %u", assoc->path_protection_tlv.protection_type,
                                     assoc->path_protection_tlv.unassigned_flags,
                                     assoc->path_protection_tlv.flag_secondary,
                                     assoc->path_protection_tlv.flag_protection,
                                     assoc->extended_assoc_id_tlv.extended_assoc_id);
    }
    else if (ASSOCIATION_TYPE_TE_PLUS_PLUS == assoc->association_type) {
        assoc->path_protection = false;
        assoc->extended_assoc_id = true;
        assoc->extended_assoc_id_tlv.extended_assoc_id = assoc_info->assoc_grp_id;

        TRACE_CORE("Extended assoc id tlv: Extended assoc id: %u",
                                         assoc->extended_assoc_id_tlv.extended_assoc_id);
    }
    else if(ASSOCIATION_TYPE_SRPAG == assoc->association_type) {
        struct in_addr end_point;
        struct in_addr originator_ip;
        assoc->association_id = assoc_info->assoc_grp_id;
        assoc->extended_assoc_id = true;
        assoc->extended_assoc_id_tlv.process_as_srpag_tlv = true;
        assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6 = false;
        assoc->extended_assoc_id_tlv.srpag_color = assoc_info->sr_srpag_t.color;
        if (assoc_info->sr_srpag_t.is_srpag_endpoint_ipv6) {
            TRACE_CORE("Failed to populate association info, SRPAG endpoint is not IPv4");
            TRACE_FUNCTION_RETURN(-1);
        }

        memcpy(&assoc->extended_assoc_id_tlv.srpag_endpoint.v4,
                &assoc_info->sr_srpag_t.srpag_endpoint_addr_u.v4,
               sizeof(struct in_addr));

        assoc->sr_candidate_path_identifier = true;
        assoc->sr_candidate_path_identifier_tlv.proto_origin_ =
            (pcep_sr_cpath_proto_origin_t) assoc_info->sr_srpag_t.sr_proto_origin;
        assoc->sr_candidate_path_identifier_tlv.originator_asn =
            assoc_info->sr_srpag_t.originator_asn;

        if (assoc_info->sr_srpag_t.is_srpag_originator_ipv6) {
            TRACE_CORE("Failed to populate association info, SRPAG originator address is not IPv4");
            TRACE_FUNCTION_RETURN(-1);
        }

        memcpy(&assoc->sr_candidate_path_identifier_tlv.originator_address.v4,
            &assoc_info->sr_srpag_t.originator_addr_u.v4, sizeof(struct in_addr));
        assoc->sr_candidate_path_identifier_tlv.discriminator =
            assoc_info->sr_srpag_t.discriminator;

        if (assoc_info->sr_srpag_t.preference_valid) {
            assoc->sr_preference = true;
            assoc->sr_preference_tlv.preference = assoc_info->sr_srpag_t.preference;
        }

        memcpy(&end_point.s_addr, &assoc->extended_assoc_id_tlv.srpag_endpoint.v4,
            sizeof(end_point.s_addr));
        memcpy(&originator_ip.s_addr, &assoc->sr_candidate_path_identifier_tlv.originator_address.v4,
            sizeof(originator_ip.s_addr));

        TRACE_CORE("SRPAG association: color: %u, end point: %s, proto origin: %u, "
            "originator asn: %u, originator ip: %s, discriminator: %u, "
            "preference valid: %u, preference: %u",
            assoc->extended_assoc_id_tlv.srpag_color,
            inet_ntoa(end_point),
            assoc->sr_candidate_path_identifier_tlv.proto_origin_,
            assoc->sr_candidate_path_identifier_tlv.originator_asn,
            inet_ntoa(originator_ip),
            assoc->sr_candidate_path_identifier_tlv.discriminator,
            assoc_info->sr_srpag_t.preference_valid,
            assoc->sr_preference_tlv.preference
            );
    }

    TRACE_CORE("Reserved: %u, Flag remove: %u, Association type: %u"
                    "Association id: %u",assoc->reserved,
                                         assoc->flag_remove,
                                         assoc->association_type,
                                         assoc->association_id);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the Association IPv6 in PCRpt
 */
static int
pccd_core_fill_association_ipv6(struct pcep_obj_association_ipv6 *assoc,
                           const lsp_association_info *assoc_info)
{
    TRACE_FUNCTION_ENTRY();

    assoc->reserved = 0;
    assoc->flag_remove = (uint8_t)(assoc_info->assoc_flags &
                            LSP_PATH_STATE_ASSOCIATION_REMOVED) ? 1 : 0;

    assoc->association_type =
        pccd_core_convert_rpd_assoc_type_to_pcep_assoc_type(assoc_info->assoc_type);

    assoc->association_id = 0; //Default Value

    memcpy(&assoc->ipv6_association_source, assoc_info->assoc_source_u.v6,
                   sizeof(struct in6_addr));

    if(ASSOCIATION_TYPE_SRPAG == assoc->association_type) {
        char end_point_str[INET6_ADDRSTRLEN];
        char originator_ip_str[INET6_ADDRSTRLEN];
        assoc->association_id = assoc_info->assoc_grp_id;
        assoc->extended_assoc_id = true;
        assoc->extended_assoc_id_tlv.process_as_srpag_tlv = true;
        if (!assoc_info->sr_srpag_t.is_srpag_endpoint_ipv6) {
            TRACE_CORE("Failed to populate association info, SRPAG endpoint is not IPv6");
            TRACE_FUNCTION_RETURN(-1);
        }
        assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6 = true;
        assoc->extended_assoc_id_tlv.srpag_color = assoc_info->sr_srpag_t.color;
        memcpy(&assoc->extended_assoc_id_tlv.srpag_endpoint.v6,
                assoc_info->sr_srpag_t.srpag_endpoint_addr_u.v6,
               sizeof(struct in6_addr));

        assoc->sr_candidate_path_identifier = true;
        assoc->sr_candidate_path_identifier_tlv.proto_origin_ =
            (pcep_sr_cpath_proto_origin_t) assoc_info->sr_srpag_t.sr_proto_origin;
        assoc->sr_candidate_path_identifier_tlv.originator_asn =
            assoc_info->sr_srpag_t.originator_asn;
        if (!assoc_info->sr_srpag_t.is_srpag_originator_ipv6) {
            TRACE_CORE("Failed to populate association info, SRPAG originator address is not IPv6");
            TRACE_FUNCTION_RETURN(-1);
        }
        assoc->sr_candidate_path_identifier_tlv.is_originator_address_ipv6 = true;
        memcpy(&assoc->sr_candidate_path_identifier_tlv.originator_address.v6,
            assoc_info->sr_srpag_t.originator_addr_u.v6, sizeof(struct in6_addr));
        assoc->sr_candidate_path_identifier_tlv.discriminator =
            assoc_info->sr_srpag_t.discriminator;

        if (assoc_info->sr_srpag_t.preference_valid) {
            assoc->sr_preference = true;
            assoc->sr_preference_tlv.preference = assoc_info->sr_srpag_t.preference;
        }

        inet_ntop(AF_INET6, &assoc->extended_assoc_id_tlv.srpag_endpoint.v6, end_point_str,
                sizeof(end_point_str));
        inet_ntop(AF_INET6, &assoc->sr_candidate_path_identifier_tlv.originator_address.v6,
                originator_ip_str, sizeof(originator_ip_str));

        TRACE_CORE("SRPAG association: color: %u, end point: %s, proto origin: %u, "
            "originator asn: %u, originator ip: %s, discriminator: %u, "
            "preference valid: %u, preference: %u",
            assoc->extended_assoc_id_tlv.srpag_color,
            end_point_str,
            assoc->sr_candidate_path_identifier_tlv.proto_origin_,
            assoc->sr_candidate_path_identifier_tlv.originator_asn,
            originator_ip_str,
            assoc->sr_candidate_path_identifier_tlv.discriminator,
            assoc_info->sr_srpag_t.preference_valid,
            assoc->sr_preference_tlv.preference
            );
    }

    TRACE_CORE("Reserved: %u, Flag remove: %u, Association type: %u"
                    "Association id: %u",assoc->reserved,
                                         assoc->flag_remove,
                                         assoc->association_type,
                                         assoc->association_id);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the Association in PCRpt
 */
static int
pccd_core_fill_vendor(struct pcep_obj_vendor *lsp_vendor_info,
                      const struct pccd_rpd_lsp_info *rpd_lsp)
{
    uint8_t lsp_vendor_info_index = 0;
    bool band_width = false;

    TRACE_FUNCTION_ENTRY();

    lsp_vendor_info->size = 0;
    lsp_vendor_info->enterprise = JNPR_ENTERPRISE_NUMBER;
    if (rpd_lsp->path_flags & LSP_PATH_TYPE_AUTOBW) {
        /*
         * LSP type autoBW
         */
        lsp_vendor_info->info[lsp_vendor_info_index].type = PCEP_VENDOR_INFO_TYPE_LSP ;
        lsp_vendor_info->info[lsp_vendor_info_index].enterprise = JNPR_ENTERPRISE_NUMBER; 
        lsp_vendor_info->info[lsp_vendor_info_index].u.lsp_type = PCEP_VENDOR_LSP_TYPE_AUTOBW;
        band_width = true;
        lsp_vendor_info_index++;
    } else if (rpd_lsp->path_flags & LSP_PATH_TYPE_TE_PLUS_PLUS) {
        /*
         * LSP type TE++ 
         */
        lsp_vendor_info->info[lsp_vendor_info_index].type = PCEP_VENDOR_INFO_TYPE_LSP ;
        lsp_vendor_info->info[lsp_vendor_info_index].enterprise = JNPR_ENTERPRISE_NUMBER; 
        lsp_vendor_info->info[lsp_vendor_info_index].u.lsp_type = PCEP_VENDOR_LSP_TYPE_TEPLUSPLUS;
        band_width = true;
        lsp_vendor_info_index++;
    }

    if (band_width && (rpd_lsp->msg_trigger_reason
                       & RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW)) {
        /*
         * New autoBW requested
         */
	    lsp_vendor_info->info[lsp_vendor_info_index].type = PCEP_VENDOR_INFO_TYPE_BW ;
        lsp_vendor_info->info[lsp_vendor_info_index].enterprise = JNPR_ENTERPRISE_NUMBER; 
	    lsp_vendor_info->info[lsp_vendor_info_index].u.bps = (float)rpd_lsp->auto_bandwidth/8;
	    TRACE_CORE("new auto-bw  %d, / %f", rpd_lsp->auto_bandwidth, lsp_vendor_info->info[lsp_vendor_info_index].u.bps);
        TRACE_RPD("new auto-bw %"PRIu64" bps", rpd_lsp->auto_bandwidth);
        lsp_vendor_info_index++;
    }

     if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) &&
        (rpd_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED) && 
        (NULL != rpd_lsp->p2mp_lsp)) {
        /*
         * P2MP Tree Name
         */
	    lsp_vendor_info->info[lsp_vendor_info_index].type =
            PCEP_VENDOR_INFO_TYPE_P2MP_TREE_NAME;
        lsp_vendor_info->info[lsp_vendor_info_index].enterprise = JNPR_ENTERPRISE_NUMBER;

        strncpy(lsp_vendor_info->info[lsp_vendor_info_index].u.p2mp_tree_name,
                rpd_lsp->p2mp_lsp->p2mp_name,
                MAX_SYMB_NAME_SIZE);
        lsp_vendor_info->info[lsp_vendor_info_index].u.p2mp_tree_name[MAX_SYMB_NAME_SIZE-1] = '\0';
	    TRACE_CORE("p2mp tree name %s",
                   lsp_vendor_info->info[lsp_vendor_info_index].u.p2mp_tree_name);
        lsp_vendor_info_index++;
    }

     if (rpd_lsp->metric) {
         /*
          * Route Preference
          */
         lsp_vendor_info->info[lsp_vendor_info_index].type = PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE;
         lsp_vendor_info->info[lsp_vendor_info_index].enterprise = JNPR_ENTERPRISE_NUMBER;
         lsp_vendor_info->info[lsp_vendor_info_index].u.route_preference = rpd_lsp->metric;
         lsp_vendor_info_index++;
     }

    lsp_vendor_info->size = lsp_vendor_info_index;

    TRACE_FUNCTION_RETURN(0);
}

/**
 * fill the p2mp endpoint obj in PCRpt
 */
static int
pccd_core_fill_p2mp_endpoints_ipv4(struct pcep_obj_p2mp_endpoints_ipv4 *endpoint_obj,
                                   const struct pccd_rpd_lsp_info *rpd_lsp,
                                   LeafType leaftype)
{
    TRACE_FUNCTION_ENTRY();
    endpoint_obj->leaftype = leaftype;
    memcpy(&endpoint_obj->source, &rpd_lsp->srcaddr.v4,
                   sizeof(endpoint_obj->source));
    /* Only support one destination */
    endpoint_obj->subcount = 1; 
    memcpy(&endpoint_obj->destinations, &rpd_lsp->dstaddr.v4,
                   sizeof(struct in_addr));
    TRACE_FUNCTION_RETURN(0);
}


/**
 * fill the S2LS obj in PCRpt
 */
static int
pccd_core_fill_s2ls(struct pcep_obj_s2ls *s2ls_obj,
                   const struct pccd_rpd_lsp_info *rpd_lsp)
{
    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(rpd_lsp != NULL);
    s2ls_obj->lsp_oper_state = (int)get_lsp_op_value(rpd_lsp->state);
    
    TRACE_CORE("p2mp branch(%s) operational: %d", 
                rpd_lsp->lsp_name, s2ls_obj->lsp_oper_state);
    TRACE_FUNCTION_RETURN(0);
}

/**
 * pccd_core_report_p2mp_lsp
 *
 * Prepares PCReport for p2mp lsp and send it to particular PCE
 *
 * @param[in] pce         : pce to  which this lsp report will be sent
 *           p2mp_lsp     : pccd local lsp info
 *            send_symb_name :
 *            srp_id      :
 *            leaftype    :
 *            fragment    :
 *
 * @return  0, If report is sent to PCE.
 *          -1, on failure
 */
static int
pccd_core_report_p2mp_lsp (struct pce_cfg_core *pce,
                      const struct pccd_p2mp_lsp_info *p2mp_lsp,
                      bool send_symb_name UNUSED, uint32_t srp_id,
                      LeafType leaftype)
{
    struct pccd_rpd_lsp_info *rpd_lsp= NULL;
    struct pccd_rpd_lsp_info *tmp = NULL;

	TRACE_FUNCTION_ENTRY();

	if (!pce || !p2mp_lsp)
		TRACE_FUNCTION_RETURN(-1);

    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
        if (pccd_core_report_lsp(pce, rpd_lsp, true,
                                 pce->pc_state >= PCE_STATE_SYNC, srp_id,
								 leaftype, true)) {
            LOGGING_ERR("Could not send PCRpt to pce '%s'",
                         pce->pc_pce.pce_id);
            TRACE_FUNCTION_RETURN(-1);
        }
    }

	TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_parse_lsp_diversity_association (struct pcep_conn                     *conn,
                                           rpd_extctrl_lsp_config_status_info_t *info,
                                           uint32_t                              dag_obj_count,
                                           bool                                  dag_obj_isipv6[8],
                                           struct pcep_object                   *dag_obj_list[8],
                                           uint32_t                              srp_id,
                                           bool                                  is_pcupd)
{
    uint32_t div_assoc_iter = 0;

    TRACE_FUNCTION_ENTRY();
    if (!conn) {
        TRACE_FUNCTION_RETURN(-1);
    }

    TRACE_CORE("DAG: Parsing diversity association information in the PCEP message - %s",
               is_pcupd? "PCUpd" : "PCInit");
    while (div_assoc_iter < dag_obj_count) {
        if (div_assoc_iter == 0) {
            info->div_assoc_info = xcalloc(1, sizeof(lsp_association_info) * dag_obj_count);
        }
        info->div_assoc_info[div_assoc_iter].assoc_type = LSP_ASSOCIATION_TYPE_DISJOINT;
        info->div_assoc_info_count++;
        if (dag_obj_isipv6[div_assoc_iter]) {
            if ((is_pcupd == false) &&
                (dag_obj_list[div_assoc_iter]->u.association_ipv6.flag_remove == true)) {
                TRACE_CORE("DAG: Remove flag in association object is not expected in PCInit message");
                free(info->div_assoc_info);
                info->div_assoc_info = NULL;
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_PCCREATE,
                                         PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            if (dag_obj_list[div_assoc_iter]->u.association_ipv6.flag_remove == true) {
                info->div_assoc_info[div_assoc_iter].assoc_flags = true;
            } else {
                info->div_assoc_info[div_assoc_iter].assoc_flags = false;
            }
            info->div_assoc_info[div_assoc_iter].is_assoc_src_ipv6 = true;
            info->div_assoc_info[div_assoc_iter].assoc_grp_id =
                            dag_obj_list[div_assoc_iter]->u.association_ipv6.association_id;
            memcpy(info->div_assoc_info[div_assoc_iter].assoc_source_u.v6,
                   &dag_obj_list[div_assoc_iter]->u.association_ipv6.ipv6_association_source,
                   sizeof(struct in6_addr));
            if (dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config) {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info_valid
                                                                            = true;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.link_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config_tlv.link_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.node_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config_tlv.node_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.srlg_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config_tlv.srlg_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.shortest_first =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config_tlv.shortest_path_flag;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.strictness =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_config_tlv.stictness_flag;
            } else {
                TRACE_CORE("Association config info not found. stopping processing the message");
                pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_DISJ_CONFIG_MISSING);
                free(info->div_assoc_info);
                info->div_assoc_info = NULL;
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL)
            }
            if (dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status) {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info_valid
                                                                            = true;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.link_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status_tlv.link_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.node_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status_tlv.node_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.srlg_diverse =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status_tlv.srlg_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.shortest_first =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status_tlv.shortest_path_flag;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.strictness =
                     dag_obj_list[div_assoc_iter]->u.association_ipv6.disjoint_status_tlv.stictness_flag;
            } else {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info_valid
                                                                            = false;
            }
        } else {
            info->div_assoc_info[div_assoc_iter].is_assoc_src_ipv6 = false;
            info->div_assoc_info[div_assoc_iter].assoc_grp_id =
                            dag_obj_list[div_assoc_iter]->u.association.association_id;
            if ((is_pcupd == false) &&
                (dag_obj_list[div_assoc_iter]->u.association.flag_remove == true)) {
                TRACE_CORE("DAG: Remove flag in association object is not expected in PCInit message");
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_PCCREATE,
                                         PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            if (dag_obj_list[div_assoc_iter]->u.association.flag_remove == true) {
                info->div_assoc_info[div_assoc_iter].assoc_flags = true;
            } else {
                info->div_assoc_info[div_assoc_iter].assoc_flags = false;
            }
            memcpy(&info->div_assoc_info[div_assoc_iter].assoc_source_u.v4,
                   &dag_obj_list[div_assoc_iter]->u.association.ipv4_association_source,
                   sizeof(struct in_addr));
            if (dag_obj_list[div_assoc_iter]->u.association.disjoint_config) {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info_valid
                                                                            = true;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.link_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_config_tlv.link_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.node_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_config_tlv.node_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.srlg_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_config_tlv.srlg_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.shortest_first =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_config_tlv.shortest_path_flag;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info.strictness =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_config_tlv.stictness_flag;
            } else {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_conf_info_valid
                                                                            = false;
            }
            if (dag_obj_list[div_assoc_iter]->u.association.disjoint_status) {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info_valid
                                                                            = true;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.link_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_status_tlv.link_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.node_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_status_tlv.node_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.srlg_diverse =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_status_tlv.srlg_disjoint;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.shortest_first =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_status_tlv.shortest_path_flag;
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info.strictness =
                     dag_obj_list[div_assoc_iter]->u.association.disjoint_status_tlv.stictness_flag;
            } else {
                info->div_assoc_info[div_assoc_iter].disjoint_assoc_list.assoc_status_info_valid
                                                                            = false;
            }
        }
        div_assoc_iter++;
    }

    TRACE_FUNCTION_RETURN(0);
}

/**
 * pccd_core_report_lsp
 *
 * Prepares PCReport and send it to particular PCE
 *
 * @param[in] pce         : pce to  which this lsp report will be sent
 *            rpd_lsp     : pccd local lsp info
 *            last        : indicator for the last lsp
 *            send_symb_name :
 *            srp_id      :
 *            leaftype    :
 *            fragment    :
 *
 * @return  0, If report is sent to PCE.
 *          -1, on failure
 */
static int
pccd_core_report_lsp (struct pce_cfg_core *pce,
                      const struct pccd_rpd_lsp_info *rpd_lsp, bool last,
                      bool send_symb_name, uint32_t srp_id,
                      LeafType leaftype, bool fragment)
{
    daemon_trace_file_options_t *dtfo = NULL;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    bool is_report_not_allow = false;
    int objects = 0;
    uint8_t pcep_setup_type = RSVP;
    bool delegate;
    struct pcep_object objs[600]; /* SRP, LSP, ERO, LSPA, BW, METRIC, RRO,
                                   ERO, LSPA, BW, RRO, ENDPOINT, S2LS, VENDOR,
                                 ASSOCATION FLOWSPEC*/
    struct lsp_vector *lsp = NULL;
    uint32_t ero_counter = 0, rro_counter = 0;

    TRACE_FUNCTION_ENTRY();

    /* NSR Begin */
    if (!pccd_nsr_master()) {
        TRACE_FUNCTION_RETURN(0);
    }
    /* NSR End */

    dtfo = pccd_core_pce_get_traceoptions(pce);


    /*
     * reporting of lsp is not allowed:
     * 1. If lsp is p2mp type AND
     * 2. p2mp lsp reporting capability of PCE is turned off
     */
    if (rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) {
        if (!pce->pc_pce.pce_p2mp_lsp_report_capability) {
            is_report_not_allow = true;
        }
    }

    /*
     * reporting of lsp is not allowed:
     * 1. If lsp is SR type AND
     * 2. SR capability of PCE is turned off
     */
    if (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
        if (!pccd_core_pce_spring_capability(pce)) {
            is_report_not_allow = true;
        }
    }
    /*
     * reporting of lsp is not allowed:
     * 1. If lsp is SRv6 type AND
     * 2. SRv6 capability of PCE is turned off
     */
    else if (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
        if (!pccd_core_pce_srv6_capability(pce)) {
            is_report_not_allow = true;
        }
    }

    if (is_report_not_allow) {
        TRACE_CORE("Not reporting LSP: lsp_name is %s, path_name is %s", 
            rpd_lsp->lsp_name, rpd_lsp->path_name);
        if ((pce->pc_state == PCE_STATE_SYNC) && last){
            /* Send all previous LSP report if any*/
            if (pce->objects_lsps_stack) {
                TRACE_PCEP(dtfo, "Sending message(s) objs %p count: %u to pce '%s'",
                           pce->objs_stack, pce->objects_stack, pce->pc_pce.pce_id);
                if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, pce->objs_stack,
                                           pce->objects_stack)) {
                    LOGGING_ERR("Could not send PCRpt message to PCE '%s'",
                                pce->pc_pce.pce_id);
                    free(pce->objs_stack);
                    pce->objs_stack = NULL;
                    TRACE_FUNCTION_RETURN(-1);
                }
                pce->objects_lsps_stack = 0;
                pce->objects_stack = 0;
                free(pce->objs_stack);
                pce->objs_stack = NULL;
            }
            // Send an Empty report after Last LSP
            pccd_core_report_empty_lsp(pce, SRP_ID_RESV1);

            INSIST_ERR(pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
                       pce->pc_pce.pce_opts.pco_pce_type ==
                       PCE_TYPE_STATEFULACTIVE);
            pccd_core_pce_transition_state(pce, PCE_STATE_UP);
            
        }
        TRACE_FUNCTION_RETURN(0);
    }


    memset(objs, 0, sizeof(objs));

    if (pce->pc_state == PCE_STATE_SYNC) {
        if (pce->objects_stack == 0) {
            if (pce->objs_stack == NULL) {
                pce->objs_stack = xcalloc(PCCD_MAX_LSPS_IN_REPORT, sizeof(objs));
            }
        }
    }


    /* retrieve our internal lsp object */
    lsp = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
    if (lsp==NULL) {
        LOGGING_ERR("Could not retrieve LSP in internal list");
        TRACE_FUNCTION_RETURN(-1);
    }


    pccd_core_update_pcreport_reason(rpd_lsp);

    delegate = false;
    switch (rpd_lsp->type) {
        case LSP_TYPE_EXTERNALLY_CONTROLLED:
            if (pce->pc_main &&
                    (rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED) &&
                    (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE)) {
                delegate = true;
                if (lsp->lv_retry_delegation == false) {
                    lsp->lv_want_to_delegate = true;
                    lsp->lv_ack_delegated = true;
                }
            } else {
                delegate = false;
            }
            break;
        case LSP_TYPE_EXTERNALLY_PROVISIONED:
            if (lsp->lv_pce == pce) {
                delegate = lsp->lv_ack_delegated;
            } else {
                delegate = false;
            }
            break;
        default:
            lsp->lv_want_to_delegate = false;
            lsp->lv_ack_delegated = false;
            break;
    }

    /*
     * If PCEP session recovers before
     * delegation-cleanup-timer expires,
     * we need to clear lsp-cleanup-timer
     */
    if (delegate) {
        pccd_core_clear_lsp_cleanup_tid(lsp);
    }

    if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) && 
        (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED)) {
        if (send_symb_name && rpd_lsp->p2mp_lsp->p2mp_name[0] == '\0') {
            LOGGING_ERR("Empty LSP name for rpd_lsp %p", rpd_lsp->p2mp_lsp);
            TRACE_FUNCTION_RETURN(-1);
        }
    } else { 
        if (send_symb_name && (rpd_lsp->lsp_name[0] == '\0') && (rpd_lsp->path_name[0] == '\0')) {
            LOGGING_ERR("Empty LSP name for rpd_lsp %p", rpd_lsp);
            TRACE_FUNCTION_RETURN(-1);
        }
    }

	pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
		rpd_lsp->lsp_name, rpd_lsp->path_name);

    objs[objects].type = PCEP_OBJ_SRP;
    if (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == rpd_lsp->setup_type) {
        pcep_setup_type = SEGMENT;
    } else if(RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == rpd_lsp->setup_type) {
        pcep_setup_type = srv6_pst_type;
    } else {
        pcep_setup_type = RSVP;
    }
    if (pccd_core_fill_srp(&objs[objects].u.srp, srp_id, pcep_setup_type)) {
		LOGGING_ERR("Could not create SRP object for PCRpt message");
		TRACE_FUNCTION_RETURN(-1);
    }

    if (rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) {
        /* For point to multipoint LSPs P2MP*/

        objs[++objects].type = PCEP_OBJ_LSP;
        if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
            if (rpd_lsp->msg_trigger_reason & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN) {
                leaftype = OLD_LEAVES_TO_REMOVE;
            }
            if (pccd_core_fill_report_lsp(&objs[objects].u.lsp, rpd_lsp, delegate,
                                          (pce->pc_state == PCE_STATE_SYNC), fragment,
                                          send_symb_name ? rpd_lsp->p2mp_lsp->p2mp_name : "")) {
                LOGGING_ERR("Could not create LSP object for PCRpt message");
                TRACE_FUNCTION_RETURN(-1);
            }
        } else {
            if (pccd_core_fill_report_lsp(&objs[objects].u.lsp, rpd_lsp, delegate,
                                          (pce->pc_state == PCE_STATE_SYNC), fragment,
                                            send_symb_name ? lsp_full_name : "")) {
                LOGGING_ERR("Could not create LSP object for PCRpt message");
                TRACE_FUNCTION_RETURN(-1);
            }
        }

        objs[++objects].type = PCEP_OBJ_P2MP_ENDPOINTS_IPV4;
        if (pccd_core_fill_p2mp_endpoints_ipv4(&objs[objects].u.p2mp_endpoints_ipv4,
                                               rpd_lsp, leaftype)< 0) {
            LOGGING_ERR("Could not create ENDPOINT object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }

        objs[++objects].type = PCEP_OBJ_S2LS_VAL;
        if (pccd_core_fill_s2ls(&objs[objects].u.s2ls,
                                          rpd_lsp)< 0) {
            LOGGING_ERR("Could not create S2LS object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }

        objs[++objects].type = PCEP_OBJ_ERO;
        if (pccd_core_fill_ero(&objs[objects].u.ero, rpd_lsp, 0)< 0) {
            LOGGING_ERR("Could not create ERO object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }

        if (rpd_lsp->rro_info || rpd_lsp->srte_rro_info){
            objs[++objects].type = PCEP_OBJ_RRO;
            if (pccd_core_fill_rro(&objs[objects].u.rro, rpd_lsp, 0)< 0) {
                LOGGING_ERR("Could not create RRO object for PCRpt message");
                TRACE_FUNCTION_RETURN(-1);
            }
        }

        objs[++objects].type = PCEP_OBJ_LSPA;
        if (pccd_core_fill_lspa(&objs[objects].u.lspa, rpd_lsp)< 0) {
            LOGGING_ERR("Could not create LSPA object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }

        objs[++objects].type = PCEP_OBJ_BANDWIDTH_REQUEST;
        if (pccd_core_fill_bandwidth(&objs[objects].u.bandwidth, rpd_lsp)< 0) {
            LOGGING_ERR("Could not create bandwidth object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }

        if (pccd_core_fill_flowspec_obj(objs, &objects, rpd_lsp)) {
            LOGGING_ERR("Could not create flowspec object(s) in PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }
    } else {

        objs[++objects].type = PCEP_OBJ_LSP;
        if (pccd_core_fill_report_lsp(&objs[objects].u.lsp, rpd_lsp, delegate,
                                      (pce->pc_state == PCE_STATE_SYNC), false,
                                      send_symb_name ? lsp_full_name : "")) {
            LOGGING_ERR("Could not create LSP object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }
        for (int count = 0; count < MAX_PATH_BINDING_TLVS; count++) {
            if (objs[objects].u.lsp.path_binding[count].mpls_label_binding_value) {
                pccd_core_pce_disable_tlv_path_binding(&objs[objects].u.lsp, pce);
            }
        }
        objs[objects].u.lsp.propagate_max_segment_list = propagate_maxsegment_list_field;
        objs[objects].u.lsp.max_segment_list = rpd_lsp->max_segment_list;
        TRACE_CORE(" PCRpt - filling LSP object with multipath values - "
                   "Propagate multipath in LSP object: %u max_computed_segment_list: %u",
                   objs[objects].u.lsp.propagate_max_segment_list,
                   objs[objects].u.lsp.max_segment_list);

        /*fill association objects*/
        if (rpd_lsp->num_assoc_info) {
            u_int count = 0;
            while (count < rpd_lsp->num_assoc_info) {

                if (rpd_lsp->assoc_info[count].is_assoc_src_ipv6) {
                    objs[++objects].type = PCEP_OBJ_ASSOCIATION_IPV6;
                    if (pccd_core_fill_association_ipv6(&objs[objects].u.association_ipv6,
                                                        &rpd_lsp->assoc_info[count]) < 0 ) {
                        LOGGING_ERR("Could not create ASSOC IPv6 object for PCRpt message");
                        TRACE_FUNCTION_RETURN(-1);
                    }
                    count++;
                    continue;
                }

                if(rpd_lsp->assoc_info[count].assoc_type == LSP_ASSOCIATION_TYPE_PROTECTION) {
                    /* PCCD need to send the assocaition object only if LSP has multiple paths
                     * or PCE has included assoc obj in PCCreate or PCUpdate request
                     */
                    if (!rpd_lsp->assoc_requested && !(rpd_lsp->num_paths >1)) {
                        /*Don't send protection object if neither it is requested or LSP
                         * has more than one path
                         */
                        count++;
                        continue;
                    }
                }
                if(ASSOC_OBJ_RFC_COMPLAINT == assoc_obj_complaince) {
                    objs[++objects].type = PCEP_OBJ_ASSOCIATION;
                    if (pccd_core_fill_association(&objs[objects].u.association,
                                                   &rpd_lsp->assoc_info[count]) < 0 ) {
                        LOGGING_ERR("Could not create ASSOC object for PCRpt message");
                        TRACE_FUNCTION_RETURN(-1);
                    }
                } else {
                    objs[++objects].type = PCEP_OBJ_ASSOCIATION_VAL;
                    if (pccd_core_fill_association_non_rfc(&objs[objects].u.association_non_rfc,
                                                   &rpd_lsp->assoc_info[count])< 0) {
                        LOGGING_ERR("Could not create RRO object for PCRpt message");
                        TRACE_FUNCTION_RETURN(-1);
                    }
                }
                count++;
            }
        }

        if (rpd_lsp->div_assoc_info_count) {
            uint32_t div_assoc_iter = 0, obj_delete_count = 0;
            TRACE_CORE(" PCRpt: filling disjoint association config info");
            while (div_assoc_iter < rpd_lsp->div_assoc_info_count) {
                rpd_disjoint_assoc_block_t *dag_ptr = NULL;
                dag_ptr = &rpd_lsp->div_assoc_info[div_assoc_iter].disjoint_assoc_list;
                if (!dag_ptr->assoc_conf_info_valid) {
                    div_assoc_iter++;
                    TRACE_CORE(" PCRpt: Unexpected scenario. Missing disjoint "
                               "configuration information");
                    continue;
                }
                if (rpd_lsp->div_assoc_info[div_assoc_iter].is_assoc_src_ipv6) {
                    objs[++objects].type = PCEP_OBJ_ASSOCIATION_IPV6;
                    objs[objects].u.association_ipv6.association_id =
                                            rpd_lsp->div_assoc_info[div_assoc_iter].assoc_grp_id;
                    memcpy(&objs[objects].u.association_ipv6.ipv6_association_source,
                           rpd_lsp->div_assoc_info[div_assoc_iter].assoc_source_u.v6,
                           sizeof(struct in6_addr));
                    objs[objects].u.association_ipv6.disjoint_config =  true;
                    objs[objects].u.association_ipv6.association_type = ASSOCIATION_TYPE_DISJOINT;
                    if (rpd_lsp->div_assoc_info[div_assoc_iter].assoc_flags) {
                        objs[objects].u.association_ipv6.flag_remove = true;
                        obj_delete_count++;
                    } else {
                        objs[objects].u.association_ipv6.flag_remove = false;
                    }
                    objs[objects].u.association_ipv6.disjoint_config_tlv.link_disjoint =
                                            dag_ptr->assoc_conf_info.link_diverse;
                    objs[objects].u.association_ipv6.disjoint_config_tlv.node_disjoint =
                                            dag_ptr->assoc_conf_info.node_diverse;
                    objs[objects].u.association_ipv6.disjoint_config_tlv.srlg_disjoint =
                                            dag_ptr->assoc_conf_info.srlg_diverse;
                    objs[objects].u.association_ipv6.disjoint_config_tlv.shortest_path_flag =
                                            dag_ptr->assoc_conf_info.shortest_first;
                    objs[objects].u.association_ipv6.disjoint_config_tlv.stictness_flag =
                                            dag_ptr->assoc_conf_info.strictness;
                } else {
                    objs[++objects].type = PCEP_OBJ_ASSOCIATION;
                    memcpy(&objs[objects].u.association.ipv4_association_source,
                           &rpd_lsp->div_assoc_info[div_assoc_iter].assoc_source_u.v4,
                           sizeof(struct in_addr));
                    objs[objects].u.association.association_id =
                                            rpd_lsp->div_assoc_info[div_assoc_iter].assoc_grp_id;
                    objs[objects].u.association.disjoint_config =  true;
                    objs[objects].u.association.association_type = ASSOCIATION_TYPE_DISJOINT;
                    if (rpd_lsp->div_assoc_info[div_assoc_iter].assoc_flags) {
                        objs[objects].u.association.flag_remove = true;
                        obj_delete_count++;
                    } else {
                        objs[objects].u.association.flag_remove = false;
                    }
                    objs[objects].u.association.disjoint_config_tlv.link_disjoint =
                                            dag_ptr->assoc_conf_info.link_diverse;
                    objs[objects].u.association.disjoint_config_tlv.node_disjoint =
                                            dag_ptr->assoc_conf_info.node_diverse;
                    objs[objects].u.association.disjoint_config_tlv.srlg_disjoint =
                                            dag_ptr->assoc_conf_info.srlg_diverse;
                    objs[objects].u.association.disjoint_config_tlv.shortest_path_flag =
                                            dag_ptr->assoc_conf_info.shortest_first;
                    objs[objects].u.association.disjoint_config_tlv.stictness_flag =
                                            dag_ptr->assoc_conf_info.strictness;
                }
                div_assoc_iter++;
            }
            if (obj_delete_count) {
                /*
                 * Currently, PCCD will send delete diversity association group for
                 * an LSP only when delegation control is removed. Hence, all groups
                 * will be deleted. Partial delete scenarios does not exist today
                 * In future when PCC controlled LSPs support diversity association
                 * groups, this logic could be modified.
                 */
                struct pccd_rpd_lsp_info *ptr = (struct pccd_rpd_lsp_info *) rpd_lsp;
                free(ptr);
                ptr->div_assoc_info = NULL;
                ptr->div_assoc_info_count = 0;
            }
        }

        /* For point to point LSPs*/
        if ((rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
            (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
            for (ero_counter=0; ero_counter < rpd_lsp->srte_total_ero_count; ero_counter++) {
                if (multipath_enabled && (rpd_lsp->srte_total_ero_count > 1)) {
                    objs[++objects].type = PCEP_OBJ_PATH_ATTRIBUTE;
                }
                objs[++objects].type = PCEP_OBJ_ERO;
                if (pccd_core_fill_ero(&objs[objects].u.ero, rpd_lsp, ero_counter)< 0) {
                    LOGGING_ERR("Could not create ERO object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }
                if (multipath_enabled && (rpd_lsp->srte_total_ero_count > 1)) {
                    objs[objects-1].u.path_attr.path_id = objs[objects].u.ero.path_attribs.path_id;
                    objs[objects-1].u.path_attr.weight = objs[objects].u.ero.path_attribs.weight;
                    objs[objects-1].u.path_attr.op_state = get_lsp_op_value(
                                                             objs[objects].u.ero.path_attribs.op_state);
                    objs[objects-1].u.path_attr.secondary_path = objs[objects].u.ero.path_attribs.secondary_path;
                    TRACE_CORE(" PCRpt - pcep_obj_ero contents - "
                               " lsp:%s path_id %u weight %u op_state %u",
                               rpd_lsp->lsp_name,
                               objs[objects].u.ero.path_attribs.path_id,
                               objs[objects].u.ero.path_attribs.weight,
                               get_lsp_op_value(
                                            objs[objects].u.ero.path_attribs.op_state));
                }
            }
            /*
             * Fill empty ERO object when no ERO entry is available
             */
            if (!rpd_lsp->srte_total_ero_count) {
                objs[++objects].type = PCEP_OBJ_ERO;
                if (pccd_core_fill_ero(&objs[objects].u.ero, rpd_lsp, 0)< 0) {
                    LOGGING_ERR("Could not create ERO object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }
            }
        } else {
            objs[++objects].type = PCEP_OBJ_ERO;
            if (pccd_core_fill_ero(&objs[objects].u.ero, rpd_lsp, 0)< 0) {
                LOGGING_ERR("Could not create ERO object for PCRpt message");
                TRACE_FUNCTION_RETURN(-1);
            }
        }

        if (rfc8231_compliant) {
            if ((rpd_lsp->type != LSP_TYPE_CLI_REGULAR_SIGNALLED) ||
                ((rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) &&
                 (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {

                struct lsp_metric_s *actual_metric = NULL, *tmp = NULL;

                objs[++objects].type = PCEP_OBJ_BANDWIDTH_REOPTIM;
                if (pccd_core_fill_bandwidth(&objs[objects].u.bandwidth, rpd_lsp)< 0) {
                    LOGGING_ERR("Could not create bandwidth object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }

                SLIST_FOREACH_SAFE(actual_metric, &rpd_lsp->actual_metric_head, metric_next, tmp) {
                    TRACE_CORE("PCRpt: actual metric contents: type:%u, value:%u, b:%d,c:%d",
                                                         actual_metric->metric_info.metric_type,
                                                         actual_metric->metric_info.metric,
                                                         actual_metric->metric_info.bound_flag,
                                                         actual_metric->metric_info.computed_flag);
                    objs[++objects].type = PCEP_OBJ_METRIC;
                    objs[objects].u.metric.type = actual_metric->metric_info.metric_type;
                    objs[objects].u.metric.value = (float)actual_metric->metric_info.metric;
                    objs[objects].u.metric.bound = actual_metric->metric_info.bound_flag;
                    objs[objects].u.metric.computed = actual_metric->metric_info.computed_flag;
                }
            }

            if (rpd_lsp->srte_rro_info) {
                for (rro_counter=0; rro_counter < rpd_lsp->srte_total_rro_count; rro_counter++) {
                    if (multipath_enabled && (rpd_lsp->srte_total_rro_count>1)) {
                        objs[++objects].type = PCEP_OBJ_PATH_ATTRIBUTE;
                    }
                    objs[++objects].type = PCEP_OBJ_RRO;
                    if (pccd_core_fill_rro(&objs[objects].u.rro, rpd_lsp, rro_counter)< 0) {
                        LOGGING_ERR("Could not create RRO object for PCRpt message");
                        TRACE_FUNCTION_RETURN(-1);
                    }
                    if (multipath_enabled && (rpd_lsp->srte_total_rro_count>1)) {
                        objs[objects-1].u.path_attr.path_id = objs[objects].u.rro.path_attribs.path_id;
                        objs[objects-1].u.path_attr.weight = objs[objects].u.rro.path_attribs.weight;
                        objs[objects-1].u.path_attr.op_state = get_lsp_op_value(
                                                                objs[objects].u.rro.path_attribs.op_state);
                        objs[objects-1].u.path_attr.secondary_path = objs[objects].u.rro.path_attribs.secondary_path;
                        TRACE_CORE(" PCRpt - pcep_obj_rro contents - "
                                   " lsp:%s path_id %u weight %u op_state %u",
                                   rpd_lsp->lsp_name,
                                   objs[objects].u.rro.path_attribs.path_id,
                                   objs[objects].u.rro.path_attribs.weight,
                                   get_lsp_op_value(
                                                objs[objects].u.rro.path_attribs.op_state));
                    }
                }
                if (!rpd_lsp->srte_total_rro_count) {
                    objs[++objects].type = PCEP_OBJ_RRO;
                    if (pccd_core_fill_rro(&objs[objects].u.rro, rpd_lsp, 0)< 0) {
                        LOGGING_ERR("Could not create RRO object for PCRpt message");
                        TRACE_FUNCTION_RETURN(-1);
                    }
                }
            } else if (rpd_lsp->rro_info) {
                objs[++objects].type = PCEP_OBJ_RRO;
                if (pccd_core_fill_rro(&objs[objects].u.rro, rpd_lsp, 0)< 0) {
                    LOGGING_ERR("Could not create RRO object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }
            } else {
                /* PR 1612991: EANTC PR: Nokia PCE is rejecting PCRpt message when SR LSP is delegated while creation*/
                objs[++objects].type = PCEP_OBJ_RRO;
                TRACE_CORE("Adding Empty RRO");
            }

            if ((rpd_lsp->type != LSP_TYPE_CLI_REGULAR_SIGNALLED) ||
                ((rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) &&
                 (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {

                struct lsp_metric_s *intended_metric = NULL, *tmp;

                objs[++objects].type = PCEP_OBJ_LSPA;
                if (pccd_core_fill_lspa(&objs[objects].u.lspa, rpd_lsp)< 0) {
                    LOGGING_ERR("Could not create LSPA object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }

                /* Send intended bandwith received */
                objs[++objects].type = PCEP_OBJ_BANDWIDTH_REQUEST;
                if (pccd_core_fill_bandwidth_intended(&objs[objects].u.bandwidth, rpd_lsp)< 0) {
                    LOGGING_ERR("Could not create bandwidth object for PCRpt message");
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }

                SLIST_FOREACH_SAFE(intended_metric, &rpd_lsp->intended_attrs.intended_metric_head, metric_next, tmp) {
                    if ((SEGMENT_ID_DEPTH == intended_metric->metric_info.metric_type) &&
                        (intended_metric->metric_info.bound_flag) &&
                        ((intended_metric->metric_info.metric > maximum_srmpls_segment_list_depth) ||
                        (false == propagate_lsp_max_segmentlist_depth))) {
                        TRACE_CORE("Skip sending MSD metric value:%u for lsp:%s in PCRpt message",
                                intended_metric->metric_info.metric,
                                lsp_full_name);
                    } else {
                        TRACE_CORE("PCRpt: Intended metric contents: type:%u, value:%u, b:%d,c:%d",
                                intended_metric->metric_info.metric_type,
                                intended_metric->metric_info.metric,
                                intended_metric->metric_info.bound_flag,
                                intended_metric->metric_info.computed_flag);
                        objs[++objects].type = PCEP_OBJ_METRIC;
                        objs[objects].u.metric.type = intended_metric->metric_info.metric_type;
                        objs[objects].u.metric.value = (float)intended_metric->metric_info.metric;
                        objs[objects].u.metric.bound = intended_metric->metric_info.bound_flag;
                        objs[objects].u.metric.computed = intended_metric->metric_info.computed_flag;
                    }
                }
            }
        } else {
            if ((rpd_lsp->type != LSP_TYPE_CLI_REGULAR_SIGNALLED) ||
                ((rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) &&
                 (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {
                objs[++objects].type = PCEP_OBJ_LSPA;
                if (pccd_core_fill_lspa(&objs[objects].u.lspa, rpd_lsp)< 0) {
                    LOGGING_ERR("Could not create LSPA object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }

                objs[++objects].type = PCEP_OBJ_BANDWIDTH_REQUEST;
                if (pccd_core_fill_bandwidth(&objs[objects].u.bandwidth, rpd_lsp)< 0) {
                    LOGGING_ERR("Could not create bandwidth object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }
            }

            if (rpd_lsp->rro_info || rpd_lsp->srte_rro_info) {
                if (rpd_lsp->srte_total_rro_count> 1) {
                    LOGGING_ERR("multi RRO is not supported when rfc8231_compliant is not enabled");
                    TRACE_FUNCTION_RETURN(-1);
                }
                objs[++objects].type = PCEP_OBJ_RRO;
                if (pccd_core_fill_rro(&objs[objects].u.rro, rpd_lsp, 0)< 0) {
                    LOGGING_ERR("Could not create RRO object for PCRpt message");
                    TRACE_FUNCTION_RETURN(-1);
                }
            }
        }

        /* Report Flowspec objects if flowspec capability is supported over PCEP */
        if (pce->pc_pce.pce_flowspec_capability) {
            /* Populate flowspec object*/
            if (pccd_core_fill_flowspec_obj(objs, &objects, rpd_lsp)) {
                LOGGING_ERR("Could not create flowspec object(s) in PCRpt message");
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }

    if ((rpd_lsp->path_flags & LSP_PATH_TYPE_AUTOBW) ||
        (rpd_lsp->path_flags & LSP_PATH_TYPE_TE_PLUS_PLUS) ||
        ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) &&
                (rpd_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED)) ||
        (rpd_lsp->metric)){
        /* Add vendor specific TLV for
         * 1. Auto-bw LSP
         * 2. TE PLUS PLUS LSP
         * 3. P2MP LSP: P2MP tree name
         * 4. route preference
         */

        /* handle vendor specific information */
        objs[++objects].type = PCEP_OBJ_VENDOR;
        objs[objects].procrule = false;
        objs[objects].ignore   = true;

        if (pccd_core_fill_vendor(&objs[objects].u.vendor,
                rpd_lsp)< 0) {
            LOGGING_ERR("Could not create Vendor object for PCRpt message");
            TRACE_FUNCTION_RETURN(-1);
        }
    }

    if (lsp->lv_want_to_delegate && !lsp->lv_ack_delegated &&
        (lsp->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV)) {

        if (LSP_TYPE_EXTERNALLY_CONTROLLED == rpd_lsp->type) {
            /*
                1. LSP is delegated.
                    Type = control_status = externally controlled
                    lv_want_to_delegate = lv_ack_delegated = true
                    lv_retry_delegation = false
                2. Controller gives back the control of LSP and
                    PCCD sent return control message to RPD
                    PCCD is yet to receive PCReport from RPD
                    Type = control_status = externally controlled
                    lv_want_to_delegate = true
                    lv_ack_delegated = false
                    lv_retry_delegation = true
                */
            if (LSP_EXTERNALLY_CONTROLLED == rpd_lsp->control_status) {
                /*
                    3. PCCD received PCReport from RPD and
                        RPD did not take the LSP control back
                        Type = control_status = externally controlled
                        Setting lv_want_to_delegate = true,
                        lv_ack_delegated = true and
                        lv_retry_delegation = false
                        D = 1 while reporting LSP to controller
                */
                lsp->lv_want_to_delegate = true;
                lsp->lv_ack_delegated = true;
                pccd_core_clear_lsp_delegation_retry_tid(lsp);
            } else if (LSP_LOCALLY_CONTROLLED == rpd_lsp->control_status) {
                /*
                    3. PCCD received PCReport from RPD and
                        LSP in under RPD control
                        Type = externally controlled ,control_status = locally controlled
                        Setting lv_want_to_delegate = false,
                        lv_ack_delegated = false and
                        lv_retry_delegation = true (refer 2)
                        D = 0 while reporting LSP to controller
                */
                lsp->lv_want_to_delegate = false;
                lsp->lv_ack_delegated = false;
            }
        }

        if (pce->pc_pce.pce_opts.pco_delegation_setup_timeout &&
            !evTestID(lsp->lv_delegation_setup_tid)) {
            /* Start the delegation_setup timer */
            TRACE_CORE("Arming delegation_setup_tid for PCE: %s and LSP id: %u",
                       pce->pc_pce.pce_id, lsp->lv_lsp_id);
            if (evSetTimer(pccd_core_ev_ctx, pccd_core_delegation_setup_timedout,
                           lsp, evAddTime(evNowTime(),
                                          evConsTime(pce->pc_pce.pce_opts.pco_delegation_setup_timeout, 0)),
                           evConsTime(0,0), 
                           &lsp->lv_delegation_setup_tid) == -1) {
                LOGGING_ERR("Failed to initialise delegation setup timer: %s",
                            strerror(errno));
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }
    ++objects; // No more indexing.. now this represents count..
    if (pce->pc_state == PCE_STATE_SYNC) {
        /* Accumulate LSPs */
        memmove(&pce->objs_stack[pce->objects_stack],
                objs, (objects * sizeof(struct pcep_object)));
        pce->objects_stack = pce->objects_stack + objects;
        pce->objects_lsps_stack++;
        if (pce->objects_lsps_stack >= PCCD_MAX_LSPS_IN_REPORT || last == true) {
            /* Send report */
            TRACE_PCEP(dtfo, "Sending message(s) objs %p count: %u to pce '%s'",
                       pce->objs_stack, pce->objects_stack, pce->pc_pce.pce_id);
            if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, pce->objs_stack,
                                       pce->objects_stack)) {
                LOGGING_ERR("Could not send PCRpt message to PCE '%s'",
                            pce->pc_pce.pce_id);
                free(pce->objs_stack);
                pce->objs_stack = NULL;
                TRACE_FUNCTION_RETURN(-1);
            }
            pce->objects_lsps_stack = 0;
            pce->objects_stack = 0;
            free(pce->objs_stack);
            pce->objs_stack = NULL;

            // Send an Empty report after Last LSP
            if (last) {
                pccd_core_report_empty_lsp(pce, SRP_ID_RESV1);
            }
        }
    } else {
        TRACE_PCEP(dtfo, "Sending message objs %p count: %u to pce '%s'", objs,
                   objects, pce->pc_pce.pce_id);
        if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, objs, objects)){
            LOGGING_ERR("Could not send PCRpt message to PCE '%s'",
                        pce->pc_pce.pce_id);
            TRACE_FUNCTION_RETURN(-1);
        }
    }

    if (pce->pc_state == PCE_STATE_SYNC && last == true) {
        INSIST_ERR(pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
                   pce->pc_pce.pce_opts.pco_pce_type ==
                   PCE_TYPE_STATEFULACTIVE);
        pccd_core_pce_transition_state(pce, PCE_STATE_UP);
    }
    lsp->ack = true;

    TRACE_FUNCTION_RETURN(0);
}

/*
 *  try delegating the LSP again. This timer is fired from the 
 *  re-delegation or delgation failure.
 */
int
pccd_core_delegation_retry_by_lsp_name(char* lsp_name) 
{
    const struct pccd_rpd_lsp_info *lsp_info = NULL;
    struct lsp_vector *lsp_vec = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(lsp_name != NULL);

    lsp_info = pccd_rpd_get_lsp_by_name(lsp_name);
    if (!lsp_info) {
        TRACE_RPD("Retry delegation, can't find lsp '%s' in local LSP cache", lsp_name);
        TRACE_FUNCTION_RETURN(-1);
    }
    TRACE_RPD("Retry delegation, found lsp '%s' in local LSP cache", lsp_name);

    if (lsp_info->path_flags & LSP_PATH_TYPE_P2MP) {
        TRACE_RPD("Retry delegation, LSP '%s' is P2MP LSP, delegation not supported", lsp_name);
        TRACE_FUNCTION_RETURN(-1);
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp_info->id);

    if (lsp_vec == NULL)
        TRACE_FUNCTION_RETURN(-1);

    if (!lsp_vec->lv_retry_delegation)  {
        TRACE_RPD("Retry delegation, lsp '%s' is not in re-delgation state", lsp_name);
        TRACE_FUNCTION_RETURN(0);
    }

    /* if the retry timer is on, stop and clean it. */ 
    pccd_core_clear_lsp_delegation_retry_tid(lsp_vec);

    TRACE_CORE("re-Delegation for LSP id: %d with lsp_name: '%s' and path_name '%s'",
		lsp_info->id, lsp_info->lsp_name, lsp_info->path_name);
    return pccd_rpd_lsp_get_control(lsp_info);
}

/*
 *  try delegating the LSP again. This timer is fired from the 
 *  re-delegation or delgation failure.
 */
static void
pccd_core_delegation_retry_timedout(evContext ctx UNUSED, void *uap,
                                    struct timespec due UNUSED,
                                    struct timespec inter UNUSED)
{
    struct lsp_vector *lsp = NULL;
    struct pce_cfg_core *pce = NULL;
    const struct pccd_rpd_lsp_info *rpd_lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    lsp = uap;
    pce = lsp->lv_pce;

    INSIST_ERR(evTestID(lsp->lv_lsp_delegation_retry_tid));
    evInitID(&lsp->lv_lsp_delegation_retry_tid); /* clean timer */
    lsp->lv_retry_delegation = false;

    LOGGING_INFO("Delegation retry timedout: LSP id: %d with PCE: %s",
					lsp->lv_lsp_id, pce->pc_pce.pce_id);

    rpd_lsp = pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);
    if (rpd_lsp) {
        pccd_rpd_lsp_get_control(rpd_lsp);
    } else {
        LOGGING_ERR("Error: couldn't find rpd_lsp. LSP id: %d with PCE: %s",
					lsp->lv_lsp_id, pce->pc_pce.pce_id);
    }
}

static void
pccd_core_delegation_setup_timedout(evContext ctx UNUSED, void *uap,
                                    struct timespec due UNUSED,
                                    struct timespec inter UNUSED)
{
    struct lsp_vector *lsp = NULL;
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *new_pce = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    lsp = uap;

    INSIST_ERR(evTestID(lsp->lv_delegation_setup_tid));

    pce = lsp->lv_pce;
    if (lsp->lv_delegation_failed > PCEP_MAX_DELEG_RETRY) {
        lsp->lv_delegation_failed = 0;
        LOGGING_ERR("Delegation failed for LSP id: %d with PCE: %s",
                       lsp->lv_lsp_id, pce->pc_pce.pce_id);
        TRACE_CORE("Delegation failed for LSP id: %d with PCE: %s",
                       lsp->lv_lsp_id, pce->pc_pce.pce_id);

        pccd_core_pce_disconnect(pce);

        new_pce = pccd_core_select_new_main_pce(pce);
        INSIST_ERR(new_pce != NULL);

        if (new_pce != pce) {
            TRACE_CORE("PCClose sent to PCE: '%s', switching to new PCE: '%s'",
                       pce->pc_pce.pce_id, new_pce->pc_pce.pce_id);
        } else {
            /*
             * No other PCE is available.  Return control of all LSPs to local 
             * control.
             */
            if (!pccd_rpd_lsp_return_control_all()) {
                LOGGING_ERR("Returning control for all LSPs failed");
            }
        }

        if (pccd_core_set_new_main_pce(new_pce)) {
            LOGGING_ERR("Unable to set new main pce");
        }

        /*
         * Need to reconnect to pce later.
         */
        pccd_core_pce_schedule_reconnect(pce);
    }
    TRACE_FUNCTION_EXIT();
}

/**
 * Get pce_common_opts of PCE.
 */
struct pce_common_opts *
pccd_core_pce_get_common_opts (struct pce_cfg_core *pce)
{
    return &pce->pc_pce.pce_opts;
}

/**
 * Get id of PCE.
 */
char *
pccd_core_pce_get_id (struct pce_cfg_core *pce)
{
    return pce->pc_pce.pce_id;
}

/**
 * Get reference to statistics of PCE.
 */
struct pce_statistics *
pccd_core_pce_get_statistics (struct pce_cfg_core *pce)
{
    return &pce->pc_statistics;
}

/**
 * @brief
 * Get reference to traceoptions of PCE
 *
 * @detail
 * if searching for pce
 * 	1. search if traceoptions is configured at pce level else
 * 	2. search if traceoptions is configured at pce-group level
 * 	3. search if traceoptions is configured at pce protocols level
 * if search without pce (i.e pce argument is NULL)
 * 	1. search if traceoptions is configured at pce protocols level only.
 *
 * @param[in] pce handle to a specific pce config
 * @return
 * 	handle to the trace file option
 */
daemon_trace_file_options_t *
pccd_core_pce_get_traceoptions (struct pce_cfg_core *pce)
{
    daemon_trace_file_options_t *dtfo = NULL;

    if (pce) {
        if (pce->pc_pce.pce_opts.pco_traceoptions.dtf_trace_file) {
            dtfo = &pce->pc_pce.pce_opts.pco_traceoptions;
        } else {
            /* search group level */
            dtfo = pccd_cfg_pce_group_traceoptions_get(pce->pc_pce.pce_pce_group);
        }
    }
    if (!dtfo){
	dtfo = pccd_trace_get_pccd_traceoptions();
    }
    return dtfo;
}

/**
 * Get ip address of PCE.
 */
struct in_addr *
pccd_core_pce_get_ip_addr (struct pce_cfg_core *pce)
{
    return &pce->pc_pce.pce_dest_addr.v4;
}

/**
 * Get destination ip address string of PCE
 */
void
pccd_core_pce_get_dest_ip_str (struct pce_cfg_core *pce, char* ip_str)
{
    if (pce->pc_pce.is_ipv6_session) {
        inet_ntop(AF_INET6, &pce->pc_pce.pce_dest_addr.v6, ip_str,
                    INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET, &pce->pc_pce.pce_dest_addr.v4, ip_str,
                    INET_ADDRSTRLEN);
    }
}


/**
 * Get ip local ip address of PCC.
 */
struct in_addr
pccd_core_pce_get_local_ip_addr (struct pce_cfg_core *pce)
{
    struct in_addr *l_addr;
    struct sockaddr_in local_addr;
    int fd;
    unsigned int len;

    l_addr = &pce->pc_pce.pce_local_addr.v4;

    /* if pcc local-address is not configured
     * we need to get socket address
     */
    if ((l_addr->s_addr == 0) && (pce->pc_conn)) {
        fd = get_conn_fd(pce->pc_conn);
        len = sizeof(local_addr);
        bzero(&local_addr, len);
        if (getsockname(fd, (struct sockaddr *)&local_addr, &len) < 0) {
            LOGGING_ERR("getsockname failed: %s (%d)", strerror(errno), errno);
        }
        l_addr = &local_addr.sin_addr;
    }

    return *l_addr;
}


/**
 * Get local ipv6 address of PCC.
 */
struct in6_addr
pccd_core_pce_get_local_ipv6_addr (struct pce_cfg_core *pce)
{
    struct in6_addr* l_addr;
    struct sockaddr_in6 local_addr;
    int fd;
    unsigned int len;

    l_addr = &pce->pc_pce.pce_local_addr.v6;

    /**
     * if pcc v6 local-address is not configured
     * we need to get v6 socket address
     */
    if (!pce->pc_pce.is_local_v6_configured && (pce->pc_conn)) {
        fd = get_conn_fd(pce->pc_conn);
        len = sizeof(local_addr);
        bzero(&local_addr, len);
        if (getsockname(fd, (struct sockaddr *)&local_addr, &len) < 0) {
            LOGGING_ERR("getsockname failed: %s (%d)", strerror(errno), errno);
        }
        l_addr = &local_addr.sin6_addr;
    }

    return *l_addr;
}


/**
 * Get local ip address string of PCE
 */
void
pccd_core_pce_get_local_ip_str (struct pce_cfg_core *pce, char* ip_str)
{
    if (pce->pc_pce.is_ipv6_session) {
        struct in6_addr laddr6 = pccd_core_pce_get_local_ipv6_addr(pce);
        inet_ntop(AF_INET6, &laddr6, ip_str, INET6_ADDRSTRLEN);
    } else {
        struct in_addr laddr = pccd_core_pce_get_local_ip_addr(pce);
        inet_ntop(AF_INET, &laddr, ip_str, INET_ADDRSTRLEN);
    }
    TRACE_CORE("Local ip address: %s", ip_str);
}



/**
 * Get connect parameters of PCE.
 */
struct pcep_connect_parameters *
pccd_core_pce_get_connect_parameters (struct pce_cfg_core *pce)
{
    return &pce->pc_params;
}

/**
 * Get PCE priority depending on PCE type.
 *
 * @ return request priority in case of stateless PCE,
 *          delegation priority otherwise
 */
int
pccd_core_pce_get_priority (struct pce_cfg_core *pce)
{
    if (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATELESS) {
        return pce->pc_pce.pce_request_prio;
    } else {
        return pce->pc_pce.pce_delegation_prio;
    }
}

/**
 * Get Authentication Keychain for the PCEP session.
 */
char *
pccd_core_pce_get_auth_keychain (struct pce_cfg_core *pce)
{
    return pce->pc_pce.pce_opts.pco_auth_keychain;
}

/**
 * Get Authentication Algorithm for the PCEP session.
 */
char *
pccd_core_pce_get_auth_algorithm (struct pce_cfg_core *pce)
{
    return pce->pc_pce.pce_opts.pco_auth_algorithm;
}

/**
 * Get Authentication Key for the PCEP session.
 */
char *
pccd_core_pce_get_auth_key (struct pce_cfg_core *pce)
{
    return pce->pc_pce.pce_opts.pco_auth_key;
}

/**
 * Get max unknown messages value of PCE.
 */
int
pccd_core_pce_get_max_unknown_msgs (struct pce_cfg_core *pce)
{
    return pce->pc_pce.pce_opts.pco_max_unknown_messages;
}

/**
 * Check whether PCE is main.
 */
bool
pccd_core_pce_ismain(struct pce_cfg_core *pce)
{
    return pce->pc_main;
}

/**
 * Compute absolute priority for given PCE. The result priority is
 * constructed as 4 bytes, where the upper 2 bytes are pce type: STATELESS,
 * STATEFUL, STATEFULACTIVE (from the lowest to highest prio), and the lower
 * are computed from the CLI-read priority (either request prio or deleg prio).
 * The priority in CLI is stored from 0 to USHRT max, where 0 is the highest
 * priority.
 * @param pce[in] PCE to compute priority for
 * @return (c) pce priority computed from pce type and CLI configured PRIO
 */
static uint32_t
pccd_core_compute_prio(const struct pce_cfg_core *pce)
{
    uint32_t prio = (pce->pc_pce.pce_opts.pco_pce_type << 16 );

    if (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATELESS) {
        if (pce->pc_pce.pce_request_prio != 0) {
            prio = prio + (USHRT_MAX - pce->pc_pce.pce_request_prio + 1);
        }
    } else {
        if (pce->pc_pce.pce_delegation_prio != 0) {
            prio = prio + (USHRT_MAX - pce->pc_pce.pce_delegation_prio + 1); // Add 1 to handle case of prio == 65535
        }
    }
    return prio;
}

static int
pccd_core_compare_pces(const struct pce_cfg_core *c1,
                       const struct pce_cfg_core *c2)
{
    uint32_t c1_prio = 0;
    uint32_t c2_prio = 0;
    INSIST_ERR(c1 != NULL);
    INSIST_ERR(c2 != NULL);
    INSIST_ERR(c1->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_NONE);
    INSIST_ERR(c2->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_NONE);
    BUILD_ASSERT(sizeof(c1->pc_pce.pce_delegation_prio) == 2);
    BUILD_ASSERT(sizeof(c1->pc_pce.pce_request_prio) == 2);

    c1_prio = pccd_core_compute_prio(c1);
    c2_prio = pccd_core_compute_prio(c2);

    if (c1_prio > c2_prio) {
        TRACE_CORE("%s > %s", c1->pc_pce.pce_id, c2->pc_pce.pce_id);
        return 1;
    } else if (c1_prio == c2_prio) {
        TRACE_CORE("%s == %s", c1->pc_pce.pce_id, c2->pc_pce.pce_id);
        return 0;
    } else {
        TRACE_CORE("%s < %s", c1->pc_pce.pce_id, c2->pc_pce.pce_id);
        return -1;
    }
}

/* 
 * Iterate over list of all PCEs and call callback for each.
 *
 * @return 0 if success 
 */
int
pccd_core_foreach_pce_do (mgmt_sock_t *mgmt_sock, pce_cb cb, bool detailed)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(0);
    }
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if ((cb)( mgmt_sock, pce, detailed)) {
            TRACE_FUNCTION_RETURN(-1);
        }
    }
    TRACE_FUNCTION_RETURN(0);
}

/* 
 * Iterate over list of all PCEs and call callback for each.
 *
 * @return 0 if success 
 */
int
pccd_core_flowspec_foreach_pce_do (struct rpd_extr_flow_spec_info_s *rpd_fs_info, 
                                                  pce_fs_cb cb)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(0);
    }
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if ((cb)(rpd_fs_info, pce)) {
            TRACE_FUNCTION_RETURN(-1);
        }
    }
    TRACE_FUNCTION_RETURN(0);
}

int
pccd_core_foreach_lsp_do (mgmt_sock_t *mgmt_sock, pce_lsp_cb cb, uint32_t flag)
{
    struct lsp_vector *lsp_vec = NULL;
    const struct pccd_rpd_lsp_info *lsp = NULL;
    const struct pccd_rpd_lsp_info *tmp = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    TRACE_FUNCTION_ENTRY();


    PCCD_ALL_LSP_VECTOR(lsp_vec) {
        struct pce_cfg_core *pce = NULL;
        if (lsp_vec->lv_ack_delegated == true) {
            pce = lsp_vec->lv_pce;
        }

        if (lsp_vec->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
            p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp_vec->lv_lsp_id);
            if (NULL != p2mp_lsp) {
                SLIST_FOREACH_SAFE(lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
                    if ((cb)( mgmt_sock, pce, lsp, flag)) {
                        TRACE_FUNCTION_RETURN(-1);
                    }
                }
            }
        } else {
            lsp = pccd_rpd_get_lsp_by_id(lsp_vec->lv_lsp_id);
            if ((cb)( mgmt_sock, pce, lsp, flag)) {
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }PCCD_ALL_LSP_VECTOR_END(lsp_vec);

    TRACE_FUNCTION_RETURN(0);
}

int
pccd_core_status_foreach_pce_do (mgmt_sock_t *mgmt_sock, pce_status_cb cb, bool lsp, bool is_extensive)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(0);
    }
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        struct pce_lsp_statistic pce_lsp_stats;
        
        memset(&pce_lsp_stats, 0, sizeof(struct pce_lsp_statistic));

        if (lsp) {
            /* count delegated and provisioned LSPs */
            struct lsp_vector *lsp_vec = NULL;
            struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
            void* next_node = NULL;

            PCCD_ALL_LSP_VECTOR(lsp_vec) {
                if ((lsp_vec->lv_pce == pce) && (lsp_vec->lv_type == LSP_VECTOR_P2P)) {
                    if (lsp_vec->lv_ack_delegated) {
                        const struct pccd_rpd_lsp_info *rpd_lsp = pccd_rpd_get_lsp_by_id(lsp_vec->lv_lsp_id);
                        if (rpd_lsp && rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                            pce_lsp_stats.provisioned++;                            
                            pce_lsp_stats.provisioned_p2p++;
                            if (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)
                                pce_lsp_stats.provisioned_p2p_bypass++;
                        } else {
                            pce_lsp_stats.delegated++;
                            pce_lsp_stats.delegated_p2p++;
                            /* need to increment delegated bypass, once it is supported */
                        }
                    }
                }
            }PCCD_ALL_LSP_VECTOR_END(lsp_vec);

             p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
             while(NULL != p2mp_lsp){
                 lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
                 if (lsp_vec && (lsp_vec->lv_pce == pce) && (lsp_vec->lv_ack_delegated)) {
                     if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                         pce_lsp_stats.provisioned_p2mp_trees++;
                         pce_lsp_stats.provisioned += p2mp_lsp->branch_lsp_count;                            
                         pce_lsp_stats.provisioned_p2mp += p2mp_lsp->branch_lsp_count;
#if 0
                    /* enable this code when support delegation of p2mp lsp */
                     } else {
                         pce_lsp_stats.delegated_p2mp_trees++;
                         pce_lsp_stats.delegated += p2mp_lsp->branch_lsp_count;
                         pce_lsp_stats.delegated_p2mp += p2mp_lsp->branch_lsp_count;
#endif
                     }
                 }
                 p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
             }   
         }
        
        if ((cb)( mgmt_sock, pce, &pce_lsp_stats, is_extensive)) {
            TRACE_FUNCTION_RETURN(-1);
        }
    }
    TRACE_FUNCTION_RETURN(0);
}

int
pccd_core_get_lsp_statistic (struct lsp_statistic *stats)
{
    struct lsp_vector *lsp_vec = NULL;
    void* next_node = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(-1);
    }

    memset(stats, 0, sizeof(struct lsp_statistic));

    PCCD_ALL_LSP_VECTOR(lsp_vec) {
        if (lsp_vec->lv_type == LSP_VECTOR_P2P) {
            const struct pccd_rpd_lsp_info *rpd_lsp =
                    pccd_rpd_get_lsp_by_id(lsp_vec->lv_lsp_id);
            switch (rpd_lsp->type) {
                case LSP_TYPE_CLI_REGULAR_SIGNALLED:
                    stats->static_lsp++;
                    stats->static_lsp_p2p++;
                    if (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)
                        stats->static_lsp_p2p_bypass++;
                    break;
                case LSP_TYPE_EXTERNALLY_CONTROLLED:
                    if (rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED){
                        stats->external++;
                        stats->external_p2p++;
                    } else {
                        stats->static_lsp++;
                        stats->static_lsp_p2p++;
                    }
                    // need to increment delegated bypass p2p counter once supported
                    break;
                case LSP_TYPE_EXTERNALLY_PROVISIONED:
                    if (lsp_vec->lv_ack_delegated == false) {
                        stats->orphan++;
                    }
                    stats->provisioned_counter++;
                    stats->provisioned_counter_p2p++;
                    if (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)
                        stats->provisioned_counter_p2p_bypass++;
                    break;
            }
            stats->total++;
        }
    }PCCD_ALL_LSP_VECTOR_END(lsp_vec);
    stats->provisioned_limit = pccd_provisioned_lsps.limit;


    p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
    while(NULL != p2mp_lsp){        
        switch (p2mp_lsp->type) {
            case LSP_TYPE_CLI_REGULAR_SIGNALLED:
                stats->static_lsp_p2mp_trees++;
                stats->static_lsp += p2mp_lsp->branch_lsp_count;
                stats->static_lsp_p2mp += p2mp_lsp->branch_lsp_count;
                break;
#if 0
            /* enable this code when support delegation of p2mp lsp */
            case LSP_TYPE_EXTERNALLY_CONTROLLED:
                stats->external_p2mp_trees++;
                if (p2mp_lsp->control_status == LSP_EXTERNALLY_CONTROLLED){
                    stats->external += p2mp_lsp->branch_lsp_count;
                    stats->external_p2mp += p2mp_lsp->branch_lsp_count;
                } else {
                    stats->static_lsp += p2mp_lsp->branch_lsp_count;
                    stats->static_lsp_p2mp += p2mp_lsp->branch_lsp_count;
                }
                break;
#endif
            case LSP_TYPE_EXTERNALLY_PROVISIONED:
                lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
                if ((lsp_vec) && (lsp_vec->lv_ack_delegated == false)) {
                    stats->orphan += p2mp_lsp->branch_lsp_count;
                }
                stats->provisioned_counter_p2mp_trees++;
                stats->provisioned_counter += p2mp_lsp->branch_lsp_count;
                stats->provisioned_counter_p2mp += p2mp_lsp->branch_lsp_count;
                break;
        }
        stats->total += p2mp_lsp->branch_lsp_count;
        p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
    }
    
    TRACE_FUNCTION_RETURN(0);
}

/**
 * Iterate over list of PCEs and return pce_ptr with matching id.
 * @param id[in] ID of the PCE to find.
 * @return Pointer to matching PCE or NULL of none found.
 */
struct pce_cfg_core *
pccd_core_get_pce_by_id (const char *id)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    if (NULL == id) {
        TRACE_FUNCTION_RETURN(NULL);
    }

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(NULL);
    }
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        TRACE_CORE("searching for: %s node pceid: %s", id, pce->pc_pce.pce_id);
        if (!strncmp(pce->pc_pce.pce_id, id, PCCD_PCE_ID_MAX)) {
            TRACE_FUNCTION_RETURN(pce);
        }
    }

    TRACE_FUNCTION_RETURN(NULL);
}

struct pce_cfg_core *
pccd_core_select_new_main_pce(struct pce_cfg_core *last_main)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(last_main != NULL);
    
    if (last_main) {
        INSIST_ERR(!SLIST_EMPTY(&pce_cfg_head));
    }

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(last_main);
    }

    /* First search for any PCEs which have not been tried */
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce == last_main) {
            continue;
        }
        if (pce->pc_reconnects == 0) {
            break;
        }
    }

    /* If no such PCE has been found, try to use next PCE in the list*/
    if (!pce) {
        if (last_main->pc_next.sle_next != NULL) {
            pce = last_main->pc_next.sle_next;
        } else {
            /* If there are no more PCEs in the list, start from the beginning */
            pce = SLIST_FIRST(&pce_cfg_head);
        }
    }

    INSIST_ERR(pce != NULL);
    TRACE_FUNCTION_RETURN(pce);
}

/**
 * Set new PCE as main.
 */
bool
pccd_core_set_new_main_pce (struct pce_cfg_core *new_main)
{
    struct pce_cfg_core *last_main = NULL;

    TRACE_FUNCTION_ENTRY();

    if (!new_main) {
        TRACE_FUNCTION_RETURN(false);
    }

    last_main = pccd_core_get_main_pce();

    if (new_main) {
        INSIST_ERR(!SLIST_EMPTY(&pce_cfg_head));
    }

    if (last_main) {
        INSIST_ERR(!SLIST_EMPTY(&pce_cfg_head));
    }

    if (last_main == new_main) {
        TRACE_FUNCTION_RETURN(true);
    }

    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN(false);
    }

    pccd_core_switch_main_pces(last_main, new_main);
    if (new_main) {
        TRACE_CORE("PCE '%s' set as main", new_main->pc_pce.pce_id);
    }

    TRACE_FUNCTION_RETURN(true);
}

struct pce_cfg_core *
pccd_core_get_main_pce(void)
{
    struct pce_cfg_core *pce = NULL;
    TRACE_FUNCTION_ENTRY();

    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce->pc_main == true) {
            break;
        }
    }

    TRACE_FUNCTION_RETURN(pce);
}

/**
 * Get string name of PCE's state.
 */
const char*
pccd_core_get_pce_state_name (struct pce_cfg_core *pce)
{
    return pccd_core_get_pce_state_str(pce->pc_state);
}

/**
 * Get string name of PCE's state for cli status.
 */
const char*
pccd_core_get_pce_state_name_cli (struct pce_cfg_core *pce)
{
    switch (pce->pc_state) {
    case PCE_STATE_DELETED:
        return "Deleted";
    case PCE_STATE_NEW:
        return "New";
    case PCE_STATE_RECONNECT:
        return "Reconnect";
    case PCE_STATE_CONNECTING:
        return "Connecting";
    case PCE_STATE_CONNECTED:
        return "Connected";
    case PCE_STATE_SYNC:
        return "Sync";
    case PCE_STATE_UP:
        return "Up";
    }
    LOGGING_ERR("Unknown internal pce state: %d",pce->pc_state);
    abort();
}

/**
 * Get string name of PCE's type.
 */
const char*
pccd_core_get_pce_type_name (struct pce_cfg_core *pce)
{
    static const char *pce_type_str[] = {
            "PCE_TYPE_NONE",
            "PCE_TYPE_STATELESS",
            "PCE_TYPE_STATEFUL",
            "PCE_TYPE_STATEFULACTIVE"
    };

    pce_type_t state = pce->pc_pce.pce_opts.pco_pce_type;
    if (state <= PCE_TYPE_STATEFULACTIVE) {
        return pce_type_str[state];
    }

    return "<UNKNOWN>";
}

/**
 * Get string name of PCE's type for cli status.
 */
const char*
pccd_core_get_pce_type_name_cli (struct pce_cfg_core *pce)
{
    static const char *pce_type_str[] = {
            "None",
            "Stateless",
            "Stateful",
            "Stateful Active"
    };

    pce_type_t state = pce->pc_pce.pce_opts.pco_pce_type;
    if (state <= PCE_TYPE_STATEFULACTIVE) {
        return pce_type_str[state];
    }

    return "Unknown";
}

/**
 * Get PCE's type.
 */
bool
pccd_core_get_pce_type (struct pce_cfg *pce)
{
    return pce->pce_opts.pco_pce_type;
}

/**
 * Get LSP provisioning ability of PCCD provided to PCE.
 */
bool
pccd_core_pce_lsp_provisioning (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_lsp_provisioning) {
            return true;
        } else {
            return false;
        }
    } else {
        if (pce->pc_pce.pce_opts.pco_lsp_provisioning) {
            return true;
        } else {
            return false;
        }
    }
}

/**
 * Get Spring provisioning ability of PCCD provided to PCE.
 */
bool
pccd_core_pce_spring_capability (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_spring_capability) {
            return true;
        } else {
            return false;
        }
    } else {
        if (pce->pc_pce.pce_opts.pco_spring_capability) {
            return true;
        } else {
            return false;
        }
    }
}

bool
pccd_core_pce_srv6_capability (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_srv6_capability) {
            return true;
        } else {
            return false;
        }
    } else {
        TRACE_CORE("PCE is not in up/sync state");
        if (pce->pc_pce.pce_opts.pco_srv6_capability) {
            return true;
        } else {
            return false;
        }
    }
}

/**
 * Get p2mp LSP reporting ability of PCCD provided to PCE.
 */
bool
pccd_core_pce_p2mp_lsp_reporting (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_p2mp_lsp_report_capability) {
            return true;
        } else {
            return false;
        }
    } else {
        if (pce->pc_pce.pce_opts.pco_p2mp_lsp_report_capability) {
            return true;
        } else {
            return false;
        }
    }
}



/**
 * Get p2mp LSP update ability of PCCD provided to PCE.
 */
bool
pccd_core_pce_p2mp_lsp_update (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_p2mp_lsp_update_capability) {
            return true;
        } else {
            return false;
        }
    } else {
        if (pce->pc_pce.pce_opts.pco_p2mp_lsp_update_capability) {
            return true;
        } else {
            return false;
        }
    }
}


/**
 * Get p2mp LSP init ability of PCCD provided to PCE.
 */
bool
pccd_core_pce_p2mp_lsp_init (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        if (pce->pc_pce.pce_p2mp_lsp_init_capability) {
            return true;
        } else {
            return false;
        }
    } else {
        if (pce->pc_pce.pce_opts.pco_p2mp_lsp_init_capability) {
            return true;
        } else {
            return false;
        }
    }
}

/**
 *@brief
 * stringize empty ero action. If there is no empty-ero action configured, then
 * send-err is the default.
 *
 *@input[in] pce
 * pointer to pce config
 *@return
 * pointer to the string corresponding to the empty ero action.
 */
const char *
pccd_core_get_pcupdate_empty_ero_action_str (struct pce_cfg_core *pce)
{
    if (TRUE == pce->pc_pce.pce_opts.pco_empty_ero_send_err) {
        return "send-err";
    } else if (TRUE == pce->pc_pce.pce_opts.pco_empty_ero_path_tear_down) {
        return "tear-down-path";
    } else if (TRUE == pce->pc_pce.pce_opts.pco_empty_ero_routing_decision) {
        return "routing-decision";
    }

    return "routing-decision";
}

/**
 * Get LSP cleanuo timer value of PCCD provided to PCE.
 */
unsigned int
pccd_core_get_pce_lsp_cleanup_timer_value (struct pce_cfg_core *pce)
{
    if (pce->pc_state > PCE_STATE_CONNECTED) {
        return pce->pc_pce.pce_lsp_cleanup_timer;
    } else {
        return pce->pc_pce.pce_opts.pco_lsp_cleanup_timer;
    }
}

/**
 * Populate and get reference to statistics of PCE.
 */
struct pce_statistics *
pccd_core_get_statistics(struct pce_cfg_core *pce) {
    pce->pc_statistics.reftime = time(NULL);

    pccd_populate_stat_timed(pce->pc_statistics.reftime,
                             &pce->pc_statistics.pc_reqs);
    pccd_populate_stat_timed(pce->pc_statistics.reftime,
                             &pce->pc_statistics.pc_reps);
    pccd_populate_stat_timed(pce->pc_statistics.reftime,
                             &pce->pc_statistics.pc_rpts);
    pccd_populate_stat_timed(pce->pc_statistics.reftime,
                             &pce->pc_statistics.pc_updates);
    pccd_populate_stat_timed(pce->pc_statistics.reftime,
                             &pce->pc_statistics.pc_creates);

    pccd_populate_stat_key(&pce->pc_statistics.pc_errs_recv);
    pccd_populate_stat_key(&pce->pc_statistics.pc_errs_sent);
    pccd_populate_stat_key(&pce->pc_statistics.pce_pcc_ntfs);
    pccd_populate_stat_key(&pce->pc_statistics.pcc_pce_ntfs);

    if (true == pce->pc_main) {
        pce->pc_statistics.primary_elapsed_current = (
                pce->pc_statistics.reftime - pccd_last_primary_switch);
    } else {
        pce->pc_statistics.primary_elapsed_current = 0;
    }

    if( pce->pc_conn) {
        pce->pc_statistics.pcep_statistics.deadtimer =
            pcep_stats_get_deadtimer(pce->pc_conn, pce->pc_statistics.reftime);
        pce->pc_statistics.pcep_statistics.unknown_messages_rate =
            pcep_stats_get_unknown_messages_rate(pce->pc_conn,
                                            pce->pc_statistics.reftime);
        pce->pc_statistics.pcep_statistics.keepalive_recv =
                pcep_get_keepalives_recv(pce->pc_conn);
        pce->pc_statistics.pcep_statistics.keepalive_sent =
                pcep_get_keepalives_sent(pce->pc_conn);
    }

    return &pce->pc_statistics;
}

bool
pccd_core_clear_statistics(struct pce_cfg_core *pce)
{
    if (true == pce->pc_main) {
        pccd_last_primary_switch = time(NULL);
    }

    pcep_conn_clear_statistics(pce->pc_conn);
    return pccd_clear_statistics(&pce->pc_statistics);
}

void
pccd_core_delete_all_provisioned_lsps (void)
{
    pccd_rpd_delete_all_provisioned_lsps();
}

/*
 * Insert the PCE into pce config list.
 * Keep the list sorted - find a place where to insert the pce config
 * order: stateful active, stateful, stateless
 * pri 1 is the highest
 */
static void
pccd_core_insert_pce_into_pce_list (struct pce_cfg_core *pce)
{
    struct pce_cfg_core *node = NULL, *last = NULL;

    TRACE_FUNCTION_ENTRY();


    SLIST_FOREACH(node, &pce_cfg_head, pc_next) {
        if (pccd_core_compare_pces(pce, node) > 0) {
            if (last) {
                SLIST_INSERT_AFTER(last, pce, pc_next);
                TRACE_CORE("Inserting PCE '%s' after PCE '%s'",
                           pce->pc_pce.pce_id, last->pc_pce.pce_id);
            } else {
                SLIST_INSERT_HEAD(&pce_cfg_head, pce, pc_next);
                TRACE_CORE("PCE '%s' has highest priority, inserting at top",
                           pce->pc_pce.pce_id);
            }
            break;
        }
        last = node;
    }

    if (pce->pc_next.sle_next == NULL) {
        TRACE_CORE("Went through PCE list, couldn't find the correct"
                   " spot for pce '%s'", pce->pc_pce.pce_id);
        if (SLIST_EMPTY(&pce_cfg_head)) {
            SLIST_INSERT_HEAD(&pce_cfg_head, pce, pc_next);
            TRACE_CORE("The PCE list is empty, inserting at head");
        } else {
            INSIST_ERR(last != NULL);
            SLIST_INSERT_AFTER(last, pce, pc_next);
            TRACE_CORE("Appending the PCE at the end of the list");
        }
    }    

    TRACE_FUNCTION_EXIT();
}

/**
 * When PCE config is changed, PCE delegation priority
 * might be changed, then pce_cfg_head list needs to be maintained
 * in sorted order.
 */
void
pccd_core_update_pce_list (struct pce_cfg *pec)
{
    struct pce_cfg_core *pce, *new_main_pce;

    TRACE_FUNCTION_ENTRY();


    pce = CONTAINER_OF(pec, struct pce_cfg_core, pc_pce);
    new_main_pce = NULL;

    TRACE_CORE("PCE %s, will be removed from list and added to correct place", pec->pce_id);
    SLIST_REMOVE(&pce_cfg_head, pce, pce_cfg_core, pc_next);

    pce->pc_next.sle_next = NULL;

    pccd_core_insert_pce_into_pce_list(pce);

    /**
     * If the updated PCE was main PCE, we need to update the new main PCE
     * if new main PCE has higher priority (lower delegation-priority)
     * In othercase, pccd_pcep_onconnect_cb will take care of switching the PCE's
     */
    if (main_pce_locked == 0) {

        if (pccd_core_pce_ismain(pce) && SLIST_FIRST(&pce_cfg_head) != pce) {
            new_main_pce = pccd_core_select_new_main_pce(pce);
            if (new_main_pce->pc_state >= PCE_STATE_SYNC) {
                pccd_core_switch_main_pces(pce, new_main_pce);
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}

/**
 * When a PCE configuration knob is parsed from configuration, and it doesn't
 * exist in local db yet, this function is called for that purpose.
 *
 * @param[in] pec pointer to the pce configuration struct
 * @return 0 on success, -1 on error
 */
int
pccd_core_created_pce(struct pce_cfg *pec)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();
    if (!pec) {
        TRACE_FUNCTION_RETURN(-1);
    }

    pce = CONTAINER_OF(pec, struct pce_cfg_core, pc_pce);
    INSIST_ERR(pce->pc_state == PCE_STATE_DELETED);
    INSIST_ERR(pce->pc_next.sle_next == NULL);
    pccd_core_pce_transition_state(pce, PCE_STATE_NEW);
    pccd_init_statistics(&pce->pc_statistics);

    if (SLIST_EMPTY(&pce_cfg_head)) {
        /* If this PCE is the only one in list of PCEs, set it as main */
        pce->pc_main = true;
        pccd_last_primary_switch = time(NULL);
        /*FIXME: add a transaction marker to configuration, so that pccd_core
         * can say, when all PCEs has been configured properly  -  this
         * would allow core to chose PCE with highest prio */
        /* NSR Begin */
        pccd_repl_handle_update_active_pce(pce->pc_pce.pce_id);
        /* NSR End */
    }

    if (pccd_rpd_is_up()) {
        pccd_core_pce_connect(pce);
    }

    pccd_core_insert_pce_into_pce_list(pce);
    pccd_core_init_pccd_flowspec_info_root (pce);

    TRACE_FUNCTION_RETURN(0);
}

static void
pccd_core_free_pce_cfg(struct pce_cfg_core *pce)
{
    INSIST_ERR(pce != NULL);

    SLIST_REMOVE(&pce_cfg_head, pce, pce_cfg_core, pc_next);
    pccd_core_pce_clear_delegation_cleanup_timer(pce);
    pccd_free_statistics(&pce->pc_statistics);
    pccd_free_mib_tables(&pce->pc_pce);
    if (pce->pc_pce.pce_opts.pco_traceoptions.dtf_trace_file) {
        daemon_trace_close(&pce->pc_pce.pce_opts.pco_traceoptions);
    }
    free(pce);
}

/**
 * Called when pce config is deleted and no other main pce can be selected.
 * 1. delete all provisioned lsp
 * 2. return control for all externally controlled lsp
 * 3. cleanup local lsp db
 *
 */
static void pccd_core_cleanup_pce(void)
{
    /* No other PCE to select as main */

    /* delete all provisioned lsp from rpd */
    pccd_rpd_delete_all_provisioned_lsps();

    /* return control for all externally controlled lsp */
    pccd_rpd_lsp_return_control_all();
    
    /* cleanup all lsp from db */
    pccd_core_delete_all_lsps();
}

/**
 * When a PCE configuration knob is deleted from configuration, and it exists
 * in local db, this function is called for that purpose.
 *
 * @param[in] pec pointer to the pce configuration struct
 * @return 0 on success, -1 on error
 */
int
pccd_core_deleted_pce(struct pce_cfg *pec)
{
    struct pce_cfg_core *pce = NULL;
    boolean delete_all_prov_lsps_for_pce = false;

    TRACE_FUNCTION_ENTRY();
    if (!pec) {
        TRACE_CORE("invalid pec pointer (NULL)");
        TRACE_FUNCTION_RETURN(-1);
    }

    pce = CONTAINER_OF(pec, struct pce_cfg_core, pc_pce);
    TRACE_CORE("Removing PCE ID '%s' from list", pce->pc_pce.pce_id);
    pccd_core_pce_clear_delegation_cleanup_timer(pce);
    if (pce->pc_state > PCE_STATE_NEW) {
        pccd_core_pce_disconnect(pce);
    } else {
        INSIST_ERR(!evTestID(pce->pc_reconnect_timer));
    }
    // pce is main, choose a new one and handle lsps management
    if (pce->pc_main) {
        struct pce_cfg_core *new_pce = pccd_core_select_new_main_pce(pce);
        INSIST_ERR(new_pce != NULL);
        if (new_pce == pce) {
            /* NSR Begin */
            pccd_repl_handle_delete_active_pce(pce->pc_pce.pce_id);
            /* NSR End */

            /* No other PCE to select as main */
            pccd_core_cleanup_pce();
        } else {
        /* If the new_pce != pce, then the pccd_core_switch_main_pces can't
         * fail.
         */
            INSIST_ERR(pccd_core_switch_main_pces(pce, new_pce) == 0);

            /* Need to delete all provisioned lsps for deleted pce */
            delete_all_prov_lsps_for_pce = true;
        }
    } else {
        /* Need to delete all provisioned lsps for deleted pce */
        delete_all_prov_lsps_for_pce = true;
    }

    if (delete_all_prov_lsps_for_pce) {
        /**
         * Delete all externally provisioned lsps for deleted pce and
         * report to other controllers
         */
        pccd_core_delete_all_provisioned_lsps_for_pce(pce);
    }

    pccd_core_clear_new_main_pce_timer(pce);

    pccd_core_free_pce_cfg(pce);
    TRACE_FUNCTION_RETURN(0);
}

void
pccd_core_delete_all_pces(void)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;

    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        pccd_core_deleted_pce(&pce->pc_pce);
    }
    TRACE_CORE("Deleted all PCES");
    INSIST_ERR(SLIST_EMPTY(&pce_cfg_head));
    TRACE_FUNCTION_EXIT();
}

void
pccd_core_reload_pce(struct pce_cfg *pce)
{
    struct pce_cfg_core *pce_core = NULL;

    TRACE_FUNCTION_ENTRY();
    if (!pccd_nsr_master()) {
        return;
    }

    //FIXME: Check whether the pce configuration has changed
    pce_core = CONTAINER_OF(pce, struct pce_cfg_core, pc_pce);
    pccd_core_pce_disconnect(pce_core);
    pccd_core_pce_connect(pce_core);
    TRACE_FUNCTION_EXIT();
}

/*
 * Reload all PCEs with SRMPLS and SRv6 capability
 */
void
pccd_core_reload_all_sr_pces(void)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;

    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        //Reload PCEP session only if SRMPLS or SRv6 capability is configured in PCE
        if (pce->pc_pce.pce_opts.pco_spring_capability || pce->pc_pce.pce_opts.pco_srv6_capability) {
            TRACE_CORE("Reloading pce '%s' ", pce->pc_pce.pce_id);
            pccd_core_reload_pce(&pce->pc_pce);
        }
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_core_reload_all_srmpls_pces(void)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;

    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        //Reload PCEP session only if SRMPLS capability is configured in PCE
        if (pce->pc_pce.pce_opts.pco_spring_capability) {
            TRACE_CORE("Reloading pce '%s' ", pce->pc_pce.pce_id);
            pccd_core_reload_pce(&pce->pc_pce);
        }
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_core_reload_all_srv6_pces(void)
{
    struct pce_cfg_core *pce = NULL;
    struct pce_cfg_core *tmp = NULL;

    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH_SAFE(pce, &pce_cfg_head, pc_next, tmp) {
        //Reload PCEP session only if SRv6 capability is configured in PCE
        if (pce->pc_pce.pce_opts.pco_srv6_capability) {
            TRACE_CORE("Reloading pce '%s' ", pce->pc_pce.pce_id);
            pccd_core_reload_pce(&pce->pc_pce);
        }
    }
    TRACE_FUNCTION_EXIT();
}

struct pce_cfg *
pccd_core_alloc_pce_cfg(const char pce_id[PCCD_PCE_ID_MAX])
{
    struct pce_cfg_core *pce = xcalloc(1, sizeof(struct pce_cfg_core));
    /* Allocate, and set default values (e.g. for timers) */
    if (pce_id[0] != '\0') {
        strncpy(pce->pc_pce.pce_id, pce_id, sizeof(pce->pc_pce.pce_id));
        pce->pc_pce.pce_id[sizeof(pce->pc_pce.pce_id) - 1] = '\0';
    }

    pce->pc_pce.pce_opts.pco_local_timers.plt_min_keepalive = PCEP_DEF_KEEPALIVE_MIN;
    pce->pc_pce.pce_opts.pco_local_timers.plt_max_keepalive = PCEP_DEF_KEEPALIVE_MAX;
    pce->pc_pce.pce_opts.pco_local_timers.plt_max_deadtimer = PCEP_DEF_DEADTIMER_MAX;
    pce->pc_pce.pce_opts.pco_remote_timers.prt_min_keepalive = PCEP_DEF_KEEPALIVE_MIN;
    pce->pc_pce.pce_opts.pco_remote_timers.prt_max_keepalive = PCEP_DEF_KEEPALIVE_MAX;

    return &pce->pc_pce;
}

struct pce_cfg_core *
pccd_core_get_pce_cfg_core(const char *pce_id)
{
    struct pce_cfg_core *node = NULL;

    if (!pce_id) {
        return NULL;
    }

    SLIST_FOREACH(node, &pce_cfg_head, pc_next) {
        if (!strncmp(node->pc_pce.pce_id, pce_id,
                     sizeof(node->pc_pce.pce_id))) {
            return node;
        }
    }

    return NULL;
}

struct pce_cfg *
pccd_core_get_pce_cfg(const char *pce_id)
{
    struct pce_cfg_core *node = NULL;

    if (!pce_id) {
        return NULL;
    }

    SLIST_FOREACH(node, &pce_cfg_head, pc_next) {
        if (!strncmp(node->pc_pce.pce_id, pce_id,
                     sizeof(node->pc_pce.pce_id))) {
            return &node->pc_pce;
        }
    }

    return NULL;
}

/**
 * Searches for lsp_id in lsp vector list, and returns pce_cfg_core to which
 * this lsp is currently assigned.
 * @param lsp_id
 * @return
 */
static struct pce_cfg_core *
pccd_core_get_pce_cfg_lsp_id(uint32_t lsp_id)
{
    struct lsp_vector *node = NULL;
    struct pce_cfg_core *ret = NULL;

    TRACE_FUNCTION_ENTRY();

    node = pccd_core_get_lsp_vec_by_lsp_id(lsp_id);

    ret = node ? node->lv_pce : NULL;
    TRACE_FUNCTION_RETURN(ret);
}

void
pccd_core_pce_cfg_pce_id(struct pce_cfg *pce,
                         const char pce_id[PCCD_PCE_ID_MAX])
{
    INSIST_ERR(pce != NULL);
    INSIST_ERR(pce_id[0] != '\0');
    INSIST_ERR(pce->pce_id[0] != '\0');

    strncpy(pce->pce_id, pce_id, sizeof(pce->pce_id));
    pce->pce_id[sizeof(pce->pce_id) - 1] = '\0';
}

void
pccd_core_pce_cfg_statefullness(struct pce_cfg *pce, pce_type_t pce_type)
{
    TRACE_CORE("statefullness: %d", pce_type);
    if (pce->pce_opts.pco_pce_type != pce_type) {
        pce->pce_opts.pco_pce_type = pce_type;
        TRACE_CORE("pce '%s' has new pce-type %d", pce->pce_id,
                   pce->pce_opts.pco_pce_type);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_lsp_provisioning(struct pce_cfg *pce, bool lsp_provisioning)
{
    TRACE_CORE("lsp provisioning: %d", lsp_provisioning);
    if (pce->pce_opts.pco_lsp_provisioning != lsp_provisioning) {
        pce->pce_opts.pco_lsp_provisioning = lsp_provisioning;
        TRACE_CORE("pce '%s' has new lsp-provisioning %d", pce->pce_id,
                   pce->pce_opts.pco_lsp_provisioning);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_spring_capability(struct pce_cfg *pce, bool spring_capability)
{
    TRACE_CORE("Spring capability: %d", spring_capability);
    if (pce->pce_opts.pco_spring_capability != spring_capability) {
        pce->pce_opts.pco_spring_capability = spring_capability;
        TRACE_CORE("pce '%s' has new spring capbility %d", pce->pce_id,
                   pce->pce_opts.pco_spring_capability);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_srv6_capability(struct pce_cfg *pce, bool srv6_capability)
{
    TRACE_CORE("SRv6 capability: %d", srv6_capability);
    if (pce->pce_opts.pco_srv6_capability != srv6_capability) {
        pce->pce_opts.pco_srv6_capability = srv6_capability;
        TRACE_CORE("pce '%s' has new srv6 capbility %d", pce->pce_id,
                   pce->pce_opts.pco_srv6_capability);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_disable_tlv_path_binding(struct pce_cfg *pce, bool disable_tlv_path_bind)
{
    TRACE_CORE("disable-tlv-path-binding: %d", disable_tlv_path_bind);
    if (pce->pce_opts.pco_disable_tlv_path_binding != disable_tlv_path_bind) {
        pce->pce_opts.pco_disable_tlv_path_binding = disable_tlv_path_bind;
        TRACE_CORE("pce %s has new disable-tlv-path-binding %d", pce->pce_id,
                    pce->pce_opts.pco_disable_tlv_path_binding);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_p2mp_lsp_report_capability(struct pce_cfg *pce, bool p2mp_lsp_report_capability)
{
    TRACE_CORE("p2mp lsp reporting capability: %d", p2mp_lsp_report_capability);
    if (pce->pce_opts.pco_p2mp_lsp_report_capability != p2mp_lsp_report_capability) {
        pce->pce_opts.pco_p2mp_lsp_report_capability = p2mp_lsp_report_capability;
        TRACE_CORE("pce '%s' has new pco_p2mp_lsp_report_capability %d", pce->pce_id,
                   pce->pce_opts.pco_p2mp_lsp_report_capability);
        pce->pce_session_critical_config_modify = true;
    }
    if (pce->pce_opts.pco_p2mp_lsp_update_capability) {
        pce->pce_opts.pco_p2mp_lsp_report_capability = true;
    }

}

void
pccd_core_pce_cfg_p2mp_lsp_update_capability(struct pce_cfg *pce, bool p2mp_lsp_update_capability)
{
    TRACE_CORE("p2mp lsp update capability: %d", p2mp_lsp_update_capability);
    if (pce->pce_opts.pco_p2mp_lsp_update_capability != p2mp_lsp_update_capability) {
        pce->pce_opts.pco_p2mp_lsp_update_capability = p2mp_lsp_update_capability;
        TRACE_CORE("pce '%s' has new pco_p2mp_lsp_update_capability %d", pce->pce_id,
                   pce->pce_opts.pco_p2mp_lsp_update_capability);
        pce->pce_session_critical_config_modify = true;
    }

    if ( pce->pce_opts.pco_p2mp_lsp_init_capability) {
        pce->pce_opts.pco_p2mp_lsp_update_capability = true;
    }
}

void
pccd_core_pce_cfg_p2mp_lsp_init_capability(struct pce_cfg *pce, bool p2mp_lsp_init_capability)
{
    TRACE_CORE("p2mp lsp init capability: %d", p2mp_lsp_init_capability);
    if (pce->pce_opts.pco_p2mp_lsp_init_capability != p2mp_lsp_init_capability) {
        pce->pce_opts.pco_p2mp_lsp_init_capability = p2mp_lsp_init_capability;
        TRACE_CORE("pce '%s' has new pco_p2mp_lsp_init_capability %d", pce->pce_id,
                   pce->pce_opts.pco_p2mp_lsp_init_capability);
        pce->pce_session_critical_config_modify = true;
    }
}


void
pccd_core_pce_cfg_lsp_cleanup_timer(struct pce_cfg *pce, u_int lct)
{
    if (pce->pce_opts.pco_lsp_cleanup_timer != lct) {
        pce->pce_opts.pco_lsp_cleanup_timer = lct;
        TRACE_CORE("pce '%s' has new lsp_cleanup_timer: %d", pce->pce_id, lct);
        pce->pce_session_critical_config_modify = true;
    }
}

/**
 * Get Authentication Keychain for the PCEP session.
 */
void
pccd_core_auth_keychain(struct pce_cfg *pce,
                        const char auth_keychain[PCCD_AUTH_KEYCHAIN_MAX])
{
    if (strncmp(pce->pce_opts.pco_auth_keychain, auth_keychain,
                sizeof(pce->pce_opts.pco_auth_keychain))) {
        strlcpy(pce->pce_opts.pco_auth_keychain, auth_keychain,
                sizeof(pce->pce_opts.pco_auth_keychain));
        TRACE_CORE("pce '%s' has new auth_keychain %s", pce->pce_id,
                   pce->pce_opts.pco_auth_keychain);
        pce->pce_session_critical_config_modify = true;
    }
}

/**
 * Get Authentication Algorithm for the PCEP session.
 */
void
pccd_core_auth_algorithm (struct pce_cfg *pce,
                          const char auth_algorithm[PCCD_AUTH_ALGORITHM_MAX])
{
    if (strncmp(pce->pce_opts.pco_auth_algorithm, auth_algorithm,
                sizeof(pce->pce_opts.pco_auth_algorithm))) {
        strlcpy(pce->pce_opts.pco_auth_algorithm, auth_algorithm,
                sizeof(pce->pce_opts.pco_auth_algorithm));
        TRACE_CORE("pce '%s' has new auth_algorithm %s", pce->pce_id,
                   pce->pce_opts.pco_auth_algorithm);
        pce->pce_session_critical_config_modify = true;
    }
}

/**
 * Get Authentication Key for the PCEP session.
 */
void
pccd_core_auth_key (struct pce_cfg *pce,
                    const char auth_key[PCCD_AUTH_KEY_MAX])
{
    if (strncmp(pce->pce_opts.pco_auth_key, auth_key,
                sizeof(pce->pce_opts.pco_auth_key))) {
        strlcpy(pce->pce_opts.pco_auth_key, auth_key,
                sizeof(pce->pce_opts.pco_auth_key));
        TRACE_CORE("pce '%s' has new auth_key %s", pce->pce_id,
                   pce->pce_opts.pco_auth_key);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_local_timers(struct pce_cfg *pce,
                               const struct pce_local_timers *timers)
{
    if (memcmp(&pce->pce_opts.pco_local_timers, timers,
               sizeof(pce->pce_opts.pco_local_timers))) {
        memcpy(&pce->pce_opts.pco_local_timers, timers,
               sizeof(pce->pce_opts.pco_local_timers));
        TRACE_CORE("pce '%s' has new pco_local_timers", pce->pce_id);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_remote_timers(struct pce_cfg *pce,
                                const struct pce_remote_timers *timers)
{
    if (memcmp(&pce->pce_opts.pco_remote_timers, timers,
               sizeof(pce->pce_opts.pco_remote_timers))) {
        TRACE_CORE("pce '%s' has new pco_remote_timers", pce->pce_id);
        memcpy(&pce->pce_opts.pco_remote_timers, timers,
               sizeof(pce->pce_opts.pco_remote_timers));
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_request_timer(struct pce_cfg *pce, u_short rt)
{
    if (pce->pce_opts.pco_request_timer != rt) {
        pce->pce_opts.pco_request_timer = rt;
        TRACE_CORE("pce '%s' has new request_timer: %d", pce->pce_id, rt);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_max_unknown_requests(struct pce_cfg *pce, unsigned rqsts)
{
    if (pce->pce_opts.pco_max_unknown_requests != rqsts) {
        pce->pce_opts.pco_max_unknown_requests = rqsts;
        TRACE_CORE("pce '%s' has new max unknown requests: %d", pce->pce_id,
                   rqsts);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_max_unknown_mesgs(struct pce_cfg *pce, unsigned msgs)
{
    struct pce_cfg_core *pce_core = NULL;

    if (pce->pce_opts.pco_max_unknown_messages != msgs) {
        pce->pce_opts.pco_max_unknown_messages = msgs;
        TRACE_CORE("pce '%s' has new max unknown messages: %d", pce->pce_id,
                   msgs);
        pce->pce_session_critical_config_modify = true;
        pce_core = CONTAINER_OF(pce, struct pce_cfg_core, pc_pce);

        if (pce_core->pc_state >= PCE_STATE_CONNECTING) {
            INSIST_ERR(pce_core->pc_conn != NULL);
            if (pcep_set_max_unknown_messages (pce_core->pc_conn, msgs)) {
                LOGGING_ERR("pcep_set_max_unknown_messages: could not allocate memory");
                exit(EX_SOFTWARE);
            }
            TRACE_CORE("Setting max unknown messages: %u", msgs);
        }
    }
}

void
pccd_core_pce_cfg_no_advertise_own_lsps(struct pce_cfg *pce, bool no_advertise)
{
    if (pce->pce_opts.pco_no_advertise_pcc_owned_lsps != no_advertise) {
        pce->pce_opts.pco_no_advertise_pcc_owned_lsps = no_advertise;
        TRACE_CORE("pce '%s' no-advertise-own-lsps has new value: %d",
                   pce->pce_id, no_advertise);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_delegation_cleanup_timeout(struct pce_cfg *pce, u_int secs)
{
    if (pce->pce_opts.pco_delegation_cleanup_timeout != secs) {
        pce->pce_opts.pco_delegation_cleanup_timeout = secs;
        TRACE_CORE("pce '%s' has new delegation-cleanup-timeout: %d",
                   pce->pce_id, secs);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_lsp_retry_delegation(struct pce_cfg *pce, bool retry_delegation)
{
    TRACE_CORE("retry delegation: %d", retry_delegation);
    if (pce->pce_opts.pco_lsp_retry_delegation != retry_delegation) {
        pce->pce_opts.pco_lsp_retry_delegation = retry_delegation;
        TRACE_CORE("pce '%s' has new lsp-retry_delegation %d", pce->pce_id,
                   pce->pce_opts.pco_lsp_retry_delegation);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_delegation_retry_timeout(struct pce_cfg *pce, u_short secs)
{
    if (pce->pce_opts.pco_delegation_retry_timeout != secs) {
        pce->pce_opts.pco_delegation_retry_timeout = secs;
        TRACE_CORE("pce '%s' has new delegation-retry-timeout: %d",
                   pce->pce_id, secs);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_delegation_setup_timeout(struct pce_cfg *pce, u_short secs)
{
    if (pce->pce_opts.pco_delegation_setup_timeout != secs) {
        pce->pce_opts.pco_delegation_setup_timeout = secs;
        TRACE_CORE("pce '%s' has new delegation-setup-timeout: %d",
                   pce->pce_id, secs);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_local_addr(struct pce_cfg *pce, struct in_addr *addr)
{
    if (memcmp(&pce->pce_local_addr.v4, addr, sizeof(pce->pce_local_addr.v4))) {
        memcpy(&pce->pce_local_addr.v4, addr, sizeof(pce->pce_local_addr.v4));
        TRACE_CORE("pcc has new local address: %s", inet_ntoa(*addr));
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_local_v6_addr(struct pce_cfg *pce, struct in6_addr *addr)
{
    if (memcmp(&pce->pce_local_addr.v6, addr, sizeof(pce->pce_local_addr.v6))) {
        memcpy(&pce->pce_local_addr.v6, addr, sizeof(pce->pce_local_addr.v6));

        char addr_str[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &pce->pce_local_addr.v6, addr_str, sizeof(addr_str));
        TRACE_CORE("pcc has new local v6 address: %s", addr_str);

        pce->pce_session_critical_config_modify = true;
    }
}


void
pccd_core_pce_cfg_dest_addr(struct pce_cfg *pce, struct in_addr *addr)
{
    if (memcmp(&pce->pce_dest_addr.v4, addr, sizeof(pce->pce_dest_addr.v4))) {
        memcpy(&pce->pce_dest_addr.v4, addr, sizeof(pce->pce_dest_addr.v4));

        if (pce->peer_table)
            pccd_snmp_update_mib_tables(pce);

        TRACE_CORE("pce '%s' has new dest address: %s", pce->pce_id,
                   inet_ntoa(*addr));
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_dest_v6_addr(struct pce_cfg *pce, struct in6_addr *addr)
{
    if (memcmp(&pce->pce_dest_addr.v6, addr, sizeof(pce->pce_dest_addr.v6))) {
        memcpy(&pce->pce_dest_addr.v6, addr, sizeof(pce->pce_dest_addr.v6));

        if (pce->peer_table)
            pccd_snmp_update_mib_tables(pce);

        char addr_str[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &pce->pce_dest_addr.v6, addr_str, sizeof(addr_str));
        TRACE_CORE("pce '%s' has new dest v6 address: %s", pce->pce_id,
                   addr_str);
        pce->pce_session_critical_config_modify = true;
    }
}


void
pccd_core_pce_cfg_tcp_port(struct pce_cfg *pce, uint16_t port)
{
    if (pce->pce_dest_port != port) {
        pce->pce_dest_port = port;
        TRACE_CORE("pce '%s' has new dest TCP port: %u", pce->pce_id,
                   pce->pce_dest_port);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_delegation_priority(struct pce_cfg *pce, u_short prio)
{
    if (pce->pce_delegation_prio != prio) {
        pce->pce_delegation_prio = prio;
        TRACE_CORE("pce '%s' has new delegation priority: %d",
                   pce->pce_id, prio);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_request_priority(struct pce_cfg *pce, u_short prio)
{
    if (pce->pce_request_prio != prio) {
        pce->pce_request_prio = prio;
        TRACE_CORE("pce '%s' has new request priority: %d", pce->pce_id, prio);
        pce->pce_session_critical_config_modify = true;
    }
}

void
pccd_core_pce_cfg_tls_wait_timer (struct pce_cfg *pce, uint8_t timer_val)
{
    struct pce_cfg_core *pce_core = NULL;
    struct pcep_connect_parameters   *pc_params;

    TRACE_FUNCTION_ENTRY();
    pce_core = CONTAINER_OF(pce, struct pce_cfg_core, pc_pce);

    pc_params = &pce_core->pc_params;
    if (pc_params->tls_wait_timer != timer_val) {
        pc_params->tls_wait_timer = timer_val;
        TRACE_CORE("pce '%s' has new tls wait timer value: %d", pce->pce_id, (int) timer_val);
        pce->pce_session_critical_config_modify = true;
    }
    TRACE_FUNCTION_EXIT();
}

void
pccd_core_pce_cfg_trace_protocol(struct pce_cfg *pce,
                                 daemon_trace_file_options_t *dtfo)
{
        struct pce_cfg_core *pce_core =
                CONTAINER_OF(pce, struct pce_cfg_core, pc_pce);

        if (pce_core->pc_state >= PCE_STATE_CONNECTING) {
            INSIST_ERR(pce_core->pc_conn != NULL);
            pcep_set_trace_mask (pce_core->pc_conn, PCEP_TRC_ALL);
        }
        memcpy(&pce_core->pc_pce.pce_opts.pco_traceoptions, dtfo, 
               sizeof(*dtfo));

        return;
}

static void
pccd_pcep_log_cb(struct pcep *pcep UNUSED, const char *function,
                 const char *fmt, va_list ap)
{
    char buf[1024];
    if (vsnprintf(buf, sizeof(buf), fmt, ap) < 0) {
        return;
    }

    TRACE_CORE("%s(): %s", function, buf);
}

static void
pccd_pcep_trace_cb(struct pcep_conn *conn, uint16_t trace_flags UNUSED,
                   uint16_t dump_flags UNUSED, const char *function,
                   const char *fmt, va_list ap)
{
    char buf[1024];
    struct pce_cfg_core *pce = NULL;
    daemon_trace_file_options_t *dtfo = NULL;

    if (vsnprintf(buf, sizeof(buf), fmt, ap) < 0) {
        LOGGING_ERR("vsnprintf failed in pccd_pcep_trace_cb");
        return;
    }

    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce->pc_conn == conn) {
            dtfo = pccd_core_pce_get_traceoptions(pce);
            TRACE_PCEP_PROTO(dtfo, "%s: %s",function, buf);
            break;
        }
    }
}

static void
pccd_pcep_onconnect_cb(struct pcep *pcep, void *uap)
{
    char dest_ip_str[INET6_ADDRSTRLEN] = {0};
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();
    TRACE_CORE("pcep %p ctx %p - connected", pcep, uap);
    INSIST_ERR(uap != NULL);

    pce = uap;
    pccd_core_pce_get_dest_ip_str(pce, dest_ip_str);
    LOGGING_INFO("Connection with pce %s (%s:%u) successful", pce->pc_pce.pce_id,
                dest_ip_str, pce->pc_pce.pce_dest_port);
    INSIST_ERR(pce->pc_state == PCE_STATE_CONNECTING);

    pce->pc_reconnects = 0; /* Re-initialise the reconnect counter */
    pce->pc_reconnect_sec = PCE_CFG_LOW_RECONNECT_SEC; /* Re-initialise reconnect_sec to lowest value */
    pce->pc_statistics.pcep_connection_active = time(NULL); /* Time when connection started to be active */
    pce->pc_statistics.pcep_connection_down = 0; /* Time when connection started to be down */
    pce->pc_statistics.pcep_statistics.keepalive_recv = 0;
    pce->pc_statistics.pcep_statistics.keepalive_sent = 0;

    pccd_core_pce_transition_state(pce, PCE_STATE_CONNECTED);

    if (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
            pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE) {
        TRACE_CORE("Connection successful with stateful%s PCE",
                   pce->pc_pce.pce_opts.pco_pce_type ==
                           PCE_TYPE_STATEFULACTIVE ? " active" : "");
        pccd_core_pce_transition_state(pce, PCE_STATE_SYNC);
        /* The TCP connection, and capability negotiation has been done by
         * the PCEP library. Now request list of all LSPs from RPD and send
         * them to PCE. */

        /* PCCD must connect to PCE only if the RPD is in UP state. Whenever
         * the RPD reports state as down, PCCD drops all PCE sessions that:
         *  - are type STATEFUL_ACTIVE and are not in UP state
         * Therefore if the PCE connection is reported UP, the RPD
         * state must be in UP state. Otherwise we have reached an
         * inconsistency. */
        INSIST_ERR(pccd_rpd_is_up());

        /* Set lsp provisioning to true if both sides (pccd and pce) are providing it */
        if (pce->pc_pce.pce_opts.pco_lsp_provisioning &&
            pce->pc_params.remote.active.lsp_provisioning) {
                pce->pc_pce.pce_lsp_provisioning = true;
        } else {
            pce->pc_pce.pce_lsp_provisioning = false;
        }
        if (pce->pc_pce.pce_lsp_provisioning) {
            pce->pc_pce.pce_lsp_cleanup_timer =
                        pce->pc_pce.pce_opts.pco_lsp_cleanup_timer;
            TRACE_CORE("LSP Instantiation: On");
            TRACE_CORE("LSP Cleanup Timer: %d",
                       pce->pc_pce.pce_lsp_cleanup_timer);
        } else {
            TRACE_CORE("LSP Instantiation: Off");
        }

        pce->pc_pce.pce_spring_capability = false;
        pce->pc_pce.pce_srv6_capability = false;

        pce->pc_pce.pce_p2mp_lsp_report_capability = false;
        pce->pc_pce.pce_p2mp_lsp_update_capability = false;
        pce->pc_pce.pce_p2mp_lsp_init_capability = false;
        pce->pc_pce.pce_flowspec_capability = false;
        pce->pc_pce.pce_multipath_capability = false;
        pce->pc_pce.pce_disjoint_assoc_capability = false;
        pce->pc_pce.pce_tls_enabled = false;

        // Set spring capability flag
        if (pce->pc_pce.pce_opts.pco_spring_capability &&
            pce->pc_params.remote.active.spring_capability) {
            pce->pc_pce.pce_spring_capability = true;
        }

        // Set SRv6 capability flag
        if (pce->pc_pce.pce_opts.pco_srv6_capability &&
            pce->pc_params.remote.active.srv6_capability) {
            TRACE_CORE("PCE SRv6 capability: On");
            pce->pc_pce.pce_srv6_capability = true;
        } else {
            TRACE_CORE("PCE SRv6 capability: Off");
        }

        if (pce->pc_pce.pce_opts.pco_multipath_capability && 
            pce->pc_params.remote.active.multipath_capability) {
            TRACE_CORE("PCE Multipath capability: On");
            pce->pc_pce.pce_multipath_capability = true;
            pce->pc_pce.pce_num_multipaths = pce->pc_params.remote.active.max_segment_list;
        } else {
            TRACE_CORE("PCE Multipath capability: Off");
            pce->pc_pce.pce_num_multipaths = 1;
        }

        if (pce->pc_pce.pce_opts.pco_disjoint_assoc_capability &&
            pce->pc_params.remote.active.disjoint_assoc_capability) {
            TRACE_CORE("PCE Disjoint Assoc capability: On");
            pce->pc_pce.pce_disjoint_assoc_capability = true;
        } else {
            TRACE_CORE("PCE Disjoint capability: Off");
        }

        /* Set p2mp flags  to true if both sides (pccd and pce) are providing it */
        if (pce->pc_pce.pce_opts.pco_p2mp_lsp_report_capability &&
            pce->pc_params.remote.active.p2mp_lsp_report_capability) {
                pce->pc_pce.pce_p2mp_lsp_report_capability = true;
        }

        if (pce->pc_pce.pce_p2mp_lsp_report_capability) {
            /* set Update and Initilize flag only when reporting is set*/
            if (pce->pc_pce.pce_opts.pco_p2mp_lsp_update_capability &&
                pce->pc_params.remote.active.p2mp_lsp_update_capability) {
                pce->pc_pce.pce_p2mp_lsp_update_capability = true;
            }

            /*set Initilize only with both reporting and update flag is set*/
            if (pce->pc_pce.pce_p2mp_lsp_update_capability) {
                if (pce->pc_pce.pce_opts.pco_p2mp_lsp_init_capability &&
                    pce->pc_params.remote.active.p2mp_lsp_init_capability) {
                    pce->pc_pce.pce_p2mp_lsp_init_capability = true;
                }
            }
        }

        if (pce->pc_pce.pce_p2mp_lsp_init_capability) {
            pce->pc_pce.pce_lsp_cleanup_timer =
                        pce->pc_pce.pce_opts.pco_lsp_cleanup_timer;
            TRACE_CORE("P2MP LSP Instantiation: On");
            TRACE_CORE("LSP Cleanup Timer: %d",
                       pce->pc_pce.pce_lsp_cleanup_timer);
        } else {
            TRACE_CORE("P2MP LSP Instantiation: Off");
        }

        /* Set pce flowspec capability */
        if (pce->pc_pce.pce_opts.pco_flowspec_capability &&
            pce->pc_params.remote.active.pce_flowspec_capability) {
            pce->pc_pce.pce_flowspec_capability = true;            
            TRACE_CORE("Flow Specification : On");
        } else {
            TRACE_CORE("Flow Specification : Off");
        }

        if (main_pce_locked == 0) {
             struct pce_cfg_core *last_main_pce = pccd_core_get_main_pce();
             int last_pce_prio = USHRT_MAX, pce_prio;

             if (last_main_pce) {
                 last_pce_prio = pccd_core_pce_get_priority(last_main_pce);
                 if (last_pce_prio == 0) {
                     last_pce_prio = USHRT_MAX;
                 }
             }

             pce_prio = pccd_core_pce_get_priority(pce);
             if (pce_prio == 0) {
                 pce_prio = USHRT_MAX;
             }

             if ((last_main_pce && last_main_pce->pc_state < PCE_STATE_CONNECTED) ||
                 (pce_prio < last_pce_prio)) {
                 pccd_core_switch_main_pces(last_main_pce, pce);
             }
        }

        if (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE &&
                pce->pc_main) {
            if (!pccd_rpd_lsp_get_control_all()) {
                LOGGING_WAR("Failed to set external controller control for all "
                        "LSPs");
                TRACE_FUNCTION_RETURN();
            }
        }
        pccd_core_pce_clear_delegation_cleanup_timer(pce);

        if (!pccd_rpd_get_all_lsps()) {
            LOGGING_WAR("Failed to request info about all LSPs");
            TRACE_FUNCTION_RETURN();
        }
    } else {
        TRACE_CORE("Connection successful with non-stateful PCE");
        pccd_core_pce_transition_state(pce, PCE_STATE_UP);
    }

    /*FIXME: Start a timer, after which we clear pce->pc_reconnects */
}

static void
pccd_pcep_onerror_cb(struct pcep *pcep, void *uap, int error,
                     const struct pcep_obj_error *pcerr)
{
    char dest_ip_str[INET6_ADDRSTRLEN] = {0};
    daemon_trace_file_options_t *dtfo;
    struct pce_cfg_core *pce = uap;
    dtfo = pccd_core_pce_get_traceoptions(pce);

    TRACE_FUNCTION_ENTRY();
    TRACE_PCEP(dtfo, "onerror_cb pcep %p ctx %p error %d (%s)", pcep, uap, error,
               strerror(error));
    INSIST_ERR(uap != NULL);

    if (error == 0) {
        pce->pc_pce.peer_table->pcePcepPeerNumPCErrSent++;
        pce->pc_pce.sess_table->pcePcepSessNumPCErrSent++;
        pccd_add_key_stat_elem(&pce->pc_statistics.pc_last_err_sent, pcerr->type, pcerr->value);
        if (!pccd_add_key_stat(&pce->pc_statistics.pc_errs_sent, pcerr->type,
                          pcerr->value)) {
		LOGGING_ERR("Adding key stat for PCErr sent failed.");
	}
        TRACE_PCEP(dtfo, "Outgoing PCErr msg with TYPE:%d and VALUE:%d", pcerr->type, pcerr->value);
        TRACE_FUNCTION_RETURN();
    }

    if (NULL != pcerr) {
        pce->pc_pce.peer_table->pcePcepPeerNumPCErrRcvd++;
        pce->pc_pce.sess_table->pcePcepSessNumPCErrRcvd++;
        pccd_add_key_stat_elem(&pce->pc_statistics.pc_last_err_recv, pcerr->type, pcerr->value);
        if (!pccd_add_key_stat(&pce->pc_statistics.pc_errs_recv, pcerr->type,
                          pcerr->value)) {
	    LOGGING_ERR("Adding key stat for PCErr recv failed.");
	}
    }
    ++(pce->pc_statistics.session_failures);
    if (pce->pc_state >= PCE_STATE_CONNECTED) {
        pce->pc_pce.peer_table->pcePcepPeerNumKeepaliveRcvd +=
            pcep_get_keepalives_recv(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumKeepaliveSent +=
            pcep_get_keepalives_sent(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumCorruptRcvd +=
            pcep_get_corrupted_message_count(pce->pc_conn);
        pce->pc_pce.peer_table->pcePcepPeerNumUnknownRcvd +=
            pcep_get_unknown_message_count(pce->pc_conn);

        pce->pc_statistics.pcep_statistics.keepalive_recv =
            pcep_get_keepalives_recv(pce->pc_conn);
        pce->pc_statistics.pcep_statistics.keepalive_sent =
            pcep_get_keepalives_sent(pce->pc_conn);
    }
    if (pce->pc_reconnects == 0) {
        pccd_core_pce_set_delegation_cleanup_timer(pce);
        pccd_core_pce_set_lsp_cleanup_timer(pce);
        pce->pc_statistics.pcep_connection_active = 0; /* Time when connection started to be active */
        pce->pc_statistics.pcep_connection_down = time(NULL); /* Time when connection started to be down */
    }

    pccd_core_pce_get_dest_ip_str(pce, dest_ip_str);
    LOGGING_INFO("Connection to pce %s (%s:%u) failed", pce->pc_pce.pce_id,
                dest_ip_str,
                pce->pc_pce.pce_dest_port);
    pce->pc_conn = NULL;

    if (evTestID(pce->pc_reconnect_timer)) {
        evClearTimer(pccd_core_ev_ctx, pce->pc_reconnect_timer);
        evInitID(&pce->pc_reconnect_timer);
    }

    pccd_core_set_new_main_pce_timer(pce);
    pccd_core_pce_transition_state(pce, PCE_STATE_NEW);

    pccd_core_pce_schedule_reconnect(pce);
    TRACE_FUNCTION_EXIT();
}

static int
pccd_core_parse_lspa(struct pcep_conn *conn UNUSED,
                     rpd_extctrl_lsp_config_status_info_t *info,
                     const struct pcep_obj_lspa *lspa, bool create)
{
    TRACE_FUNCTION_ENTRY();

    info->setup_prio = lspa->setup_prio;
    info->hold_prio = lspa->hold_prio;
    info->relcsi_admin_grp_exclude_any = lspa->pol_exclude_any;
    info->relcsi_admin_grp_include_any = lspa->pol_include_any;
    info->relcsi_admin_grp_include_all = lspa->pol_include_all;
    if (lspa->local_prot) {
        BIT_SET(info->path_flags, LSP_PATH_LOCAL_PROTECTION_DESIRED);
    }
    
    TRACE_CORE("admin grp(excl - %"PRIu32" incl_any - %"PRIu32" incl_all"
	       " - %"PRIu32") setup prio: %u and hold prio: %u",
	       info->relcsi_admin_grp_exclude_any,
	       info->relcsi_admin_grp_include_any,
	       info->relcsi_admin_grp_include_all,
	       info->setup_prio, info->hold_prio);

    if (info->setup_prio > 7 || info->hold_prio > 7) {
        TRACE_CORE("Setup or hold priority in LSPA object out of range");
        TRACE_FUNCTION_RETURN(-1);
    }

    if (create) {
        if (lspa->symbolic_name_tlv) {
            if (lspa->symbolic_name[0] != 0) {
                strncpy(info->name, lspa->symbolic_name, sizeof(info->name));
                info->name[sizeof(info->name) - 1] = '\0';
            }
        }
    }
    
    /* PCE Initiated Bypass : begin */ 
    if (lspa->bypass_tlv) {
        /* Override PCEP Protocol RSVP Setup Type with 
           RPD RSVP BYPASS Setup Type */
        info->lsp_type_info.setup_type = RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE;
        info->rbyp_params.rbp_prot_type = (lspa->node_prot 
                                           ? RSVP_BYP_PROT_TYPE_NODE
                                           : RSVP_BYP_PROT_TYPE_LINK);
        info->rbyp_params.rbp_af = RSVP_BYP_AF_IPV4;
        info->rbyp_params.rbp_nhaddr.rbn_ipv4_addr = 
                                    (u_int32_t)lspa->bypadd_ipv4_addr.s_addr;
        info->rbyp_params.rbp_subscr = (uint32_t)round(lspa->subsc_mul);        
        BIT_SET(info->path_flags, LSP_PATH_TYPE_BYPASS);
    }
    /* PCE Initiated Bypass : end */ 
    
    TRACE_FUNCTION_RETURN(0);
}

 static int
 pccd_core_parse_assoc_obj_non_rfc(struct pcep_conn *conn, uint32_t srp_id,
			rpd_extctrl_lsp_config_status_info_t *info,
			const struct pcep_obj_association_non_rfc *assoc)
 {
     TRACE_FUNCTION_ENTRY();

     if (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == info->lsp_type_info.setup_type) {
         TRACE_CORE("spring_te does not support any association with non rfc association object");
         TRACE_FUNCTION_RETURN(0);
     }

     info->assoc_info[info->num_assoc_info].assoc_type = assoc->type;
     info->assoc_info[info->num_assoc_info].assoc_grp_id = assoc->association_group_id;

     info->assoc_info[info->num_assoc_info].assoc_flags |= (assoc->flag_remove) ?
	 LSP_PATH_STATE_ASSOCIATION_REMOVED:0x0;

     if (assoc->flag_standby) {
	 info->assoc_info[info->num_assoc_info].assoc_flags |= 
	     LSP_PATH_TYPE_SECONDARY_STANDBY;
     }
     if  (assoc->flag_protection) {
	 info->assoc_info[info->num_assoc_info].assoc_flags |=
	     LSP_PATH_TYPE_SECONDARY;
     }

     TRACE_CORE("Set association: 0x%"PRIx64, info->assoc_info[info->num_assoc_info]);
     TRACE_CORE("Set count %d,association Type %d, flags :"
		"0%x standby :%d protection: %d",info->num_assoc_info,
		info->assoc_info[info->num_assoc_info].assoc_type,
		info->assoc_info[info->num_assoc_info].assoc_flags,
		assoc->flag_standby, assoc->flag_protection);

    if (assoc->flag_standby && !assoc->association_group_id) {
        // Send error when standby comes without proper assoc id
        pccd_send_error_with_srp(conn, srp_id,
                                 PCEP_ERR_TYPE_PCCREATE,
                                 PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

     info->num_assoc_info++;
     info->assoc_requested = 1;

     TRACE_FUNCTION_RETURN(0);
 }

 static int
 pccd_core_validate_srpag_identifiers (const lsp_association_info *assoc_info,
             const struct pcep_obj_association *assoc) {
 
     if ((assoc_info->sr_srpag_t.color != assoc->extended_assoc_id_tlv.srpag_color) ||
         (memcmp(&assoc_info->sr_srpag_t.srpag_endpoint_addr_u.v4,
                 &assoc->extended_assoc_id_tlv.srpag_endpoint.v4, sizeof(struct in_addr))) ||
         (assoc_info->sr_srpag_t.sr_proto_origin != (sr_proto_origin_t)assoc->sr_candidate_path_identifier_tlv.proto_origin_) ||
         (assoc_info->sr_srpag_t.originator_asn != assoc->sr_candidate_path_identifier_tlv.originator_asn) ||
         (memcmp(&assoc_info->sr_srpag_t.originator_addr_u.v4,
                 &assoc->sr_candidate_path_identifier_tlv.originator_address.v4, sizeof(struct in_addr))) ||
         (assoc_info->sr_srpag_t.discriminator != assoc->sr_candidate_path_identifier_tlv.discriminator)) {
             TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
     }

     TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);

 }

 static int
 pccd_core_validate_srpag_ipv6_identifiers (const lsp_association_info *assoc_info,
             const struct pcep_obj_association_ipv6 *assoc) {

     if ((assoc_info->sr_srpag_t.color != assoc->extended_assoc_id_tlv.srpag_color) ||
         (memcmp(assoc_info->sr_srpag_t.srpag_endpoint_addr_u.v6,
                 &assoc->extended_assoc_id_tlv.srpag_endpoint.v6, sizeof(struct in6_addr))) ||
         (assoc_info->sr_srpag_t.sr_proto_origin != (sr_proto_origin_t)assoc->sr_candidate_path_identifier_tlv.proto_origin_) ||
         (assoc_info->sr_srpag_t.originator_asn != assoc->sr_candidate_path_identifier_tlv.originator_asn) ||
         (memcmp(assoc_info->sr_srpag_t.originator_addr_u.v6,
                 &assoc->sr_candidate_path_identifier_tlv.originator_address.v6, sizeof(struct in6_addr))) ||
         (assoc_info->sr_srpag_t.discriminator != assoc->sr_candidate_path_identifier_tlv.discriminator)) {
             TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
     }
 
     TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
 
 }

 static int
 pccd_core_parse_assoc_obj(struct pcep_conn *conn, uint32_t srp_id,
            const struct pccd_rpd_lsp_info *rpd_lsp,
            int *srpag_count,
            rpd_extctrl_lsp_config_status_info_t *info,
            const struct pcep_obj_association *assoc)
 {
     bool flag_standby = false;
 
     TRACE_FUNCTION_ENTRY();

     info->assoc_info[info->num_assoc_info].assoc_type =
        pccd_core_convert_pcep_assoc_type_to_rpd_assoc_type(assoc->association_type);

     if(LSP_ASSOCIATION_TYPE_SRPAG != info->assoc_info[info->num_assoc_info].assoc_type) {

        if (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == info->lsp_type_info.setup_type) {
            TRACE_CORE("Received association type:%u is not supported for SR."
                "Not sending association information to RPD", assoc->association_type);
            TRACE_FUNCTION_RETURN(0);
        }

        info->assoc_info[info->num_assoc_info].assoc_flags |= (assoc->flag_remove) ?
            LSP_PATH_STATE_ASSOCIATION_REMOVED:0x0;

        if (assoc->extended_assoc_id) {
            info->assoc_info[info->num_assoc_info].assoc_grp_id =
                        assoc->extended_assoc_id_tlv.extended_assoc_id;
        } else {
            info->assoc_info[info->num_assoc_info].assoc_grp_id = assoc->association_id;
        }

        if (assoc->path_protection) {
            if (assoc->path_protection_tlv.flag_protection) {
                info->assoc_info[info->num_assoc_info].assoc_flags |=
                LSP_PATH_TYPE_SECONDARY;
                if (!assoc->path_protection_tlv.flag_secondary) {
                    info->assoc_info[info->num_assoc_info].assoc_flags |=
                    LSP_PATH_TYPE_SECONDARY_STANDBY;
                    flag_standby = true;
                }
            }
        }

        TRACE_CORE("Set association: 0x%"PRIx64, info->assoc_info[info->num_assoc_info]);
        TRACE_CORE("Set count %d,association Type %d, flags :"
            "0%x secondary :%d protection: %d",info->num_assoc_info,
            info->assoc_info[info->num_assoc_info].assoc_type,
            info->assoc_info[info->num_assoc_info].assoc_flags,
            assoc->path_protection_tlv.flag_secondary, assoc->path_protection_tlv.flag_protection);

        if (flag_standby && !( info->assoc_info[info->num_assoc_info].assoc_grp_id )) {
            // Send error when standby comes without proper assoc id
            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PCCREATE,
                                    PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        BIT_SET(info->lcs_params_flags, TAG_EXTCTRL_PARAMS_ASSOCIATION);
    } else {
        struct in_addr assoc_src;
        struct in_addr end_point;
        struct in_addr originator_ip;
        unsigned itr = 0;
        bool rpd_lsp_srpag_found = false;

        (*srpag_count)++;

        if (*srpag_count > PCEP_SR_SRPAG_ASSOCIATION_MAX_COUNT) {
            TRACE_CORE("sending PCError: more than 1 SRPAG asssociations received for LSP."
                "SRPAG count is: %d", *srpag_count);

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_MULTIPLE_SRPAG_IN_LSP);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if (info->lsp_type_info.setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
            TRACE_CORE("sending PCError: SRPAG received for non SRTE LSP");

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_SRPAG_IN_NON_SR_LSP);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if ((false == assoc->extended_assoc_id) ||
                (false == assoc->extended_assoc_id_tlv.process_as_srpag_tlv) ||
                (true == assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6) ||
                (false == assoc->sr_candidate_path_identifier)) {

            TRACE_CORE("sending PCError: policy or candidate path identifiers is missing"
                "extended aasoc id tlv: %d, is tlv processed as SRPAG: %d, is endpoint ipv6:%d"
                " sr candidate path identifier TLV: %d",
                assoc->extended_assoc_id,
                assoc->extended_assoc_id_tlv.process_as_srpag_tlv,
                assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6,
                assoc->sr_candidate_path_identifier);

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_MISSING_MANDATORY_SRPAG_TLV);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if ( 1 == assoc->flag_remove ) {          
            TRACE_CORE("sending PCError: SRPAG association cannot be removed in lifetime of LSP");

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_RIP,
                                    PCEP_ERR_SRPAG_REMOVE_ASSOCIATION);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        /*
          Below NULL check is passed for PCUpdate only as rpd_lsp is NULL during PCInit
        */
        if (NULL != rpd_lsp) {
            while ((itr < rpd_lsp->num_assoc_info) && (itr < LSP_ASSOCIATION_TYPE_MAX)) {
                if (LSP_ASSOCIATION_TYPE_SRPAG == rpd_lsp->assoc_info[itr].assoc_type) {
                    rpd_lsp_srpag_found = true;
                    if(pccd_core_validate_srpag_identifiers (&rpd_lsp->assoc_info[itr], assoc)) {
                        TRACE_CORE("sending PCError: policy or candidate path identifiers changed");
                        pccd_send_error_with_srp(conn, srp_id,
                                PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                PCEP_ERR_VAL_CONFLICTING_SRPAG_TLV);
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }
                    break;
                }
                itr++;
            }

            if (false == rpd_lsp_srpag_found) {
                TRACE_CORE("sending PCError: srpag cannot be added for uncolored LSP");
                pccd_send_error_with_srp(conn, srp_id,
                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                    PCEP_ERR_VAL_CONFLICTING_SRPAG_TLV);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);                
            }
        }

        info->assoc_info[info->num_assoc_info].assoc_grp_id = assoc->association_id;
        info->assoc_info[info->num_assoc_info].is_assoc_src_ipv6 = false;
        memcpy(&info->assoc_info[info->num_assoc_info].assoc_source_u.v4,
            &assoc->ipv4_association_source, sizeof(struct in_addr));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.color =
            assoc->extended_assoc_id_tlv.srpag_color;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_endpoint_ipv6 = false;
        memcpy(&info->assoc_info[info->num_assoc_info].sr_srpag_t.srpag_endpoint_addr_u.v4,
            &assoc->extended_assoc_id_tlv.srpag_endpoint.v4, sizeof(uint32_t));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.sr_proto_origin =
            (sr_proto_origin_t)assoc->sr_candidate_path_identifier_tlv.proto_origin_;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_asn =
            assoc->sr_candidate_path_identifier_tlv.originator_asn;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_originator_ipv6 = false;
        memcpy(&info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v4,
            &assoc->sr_candidate_path_identifier_tlv.originator_address, sizeof(uint32_t));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.discriminator =
            assoc->sr_candidate_path_identifier_tlv.discriminator;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.preference_valid =
            assoc->sr_preference;

        if (assoc->sr_preference) {
            info->assoc_info[info->num_assoc_info].sr_srpag_t.preference =
                assoc->sr_preference_tlv.preference;
        }

        memcpy(&assoc_src.s_addr, &info->assoc_info[info->num_assoc_info].assoc_source_u.v4,
            sizeof(assoc_src.s_addr));
        memcpy(&end_point.s_addr, &assoc->extended_assoc_id_tlv.srpag_endpoint.v4,
            sizeof(end_point.s_addr));
        memcpy(&originator_ip.s_addr,
            &info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v4,
            sizeof(originator_ip.s_addr));

        TRACE_CORE("Set association: 0x%"PRIx64, info->assoc_info[info->num_assoc_info]);
        TRACE_CORE("Set count %d,association Type %d"
            " association id: %u, association source:%s, ",info->num_assoc_info,
            info->assoc_info[info->num_assoc_info].assoc_type,
            info->assoc_info[info->num_assoc_info].assoc_grp_id,
            inet_ntoa(assoc_src));

        TRACE_CORE("set SRPAG association: color: %u, end point: %s, proto origin: %u, "
                "originator asn: %u, originator ip: %s, discriminator: %u, "
                "preference valid: %u, preference: %u",
                info->assoc_info[info->num_assoc_info].sr_srpag_t.color,
                inet_ntoa(end_point),
                info->assoc_info[info->num_assoc_info].sr_srpag_t.sr_proto_origin,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_asn,
                inet_ntoa(originator_ip),
                info->assoc_info[info->num_assoc_info].sr_srpag_t.discriminator,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.preference_valid,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.preference);
    }

     info->num_assoc_info++;
     info->assoc_requested = 1;
                
     TRACE_FUNCTION_RETURN(0);
 }

 static int
 pccd_core_parse_assoc_ipv6_obj(struct pcep_conn *conn, uint32_t srp_id,
            const struct pccd_rpd_lsp_info *rpd_lsp,
            int *srpag_count,
            rpd_extctrl_lsp_config_status_info_t *info,
            const struct pcep_obj_association_ipv6 *assoc)
 {
     TRACE_FUNCTION_ENTRY();

     info->assoc_info[info->num_assoc_info].assoc_type =
        pccd_core_convert_pcep_assoc_type_to_rpd_assoc_type(assoc->association_type);

     if (LSP_ASSOCIATION_TYPE_SRPAG == info->assoc_info[info->num_assoc_info].assoc_type) {
         char assoc_ip_str[INET6_ADDRSTRLEN] = "";
        char end_point_str[INET6_ADDRSTRLEN] = "";
        char originator_ip_str[INET6_ADDRSTRLEN] = "";
        unsigned itr = 0;
        bool rpd_lsp_srpag_found = false;

        (*srpag_count)++;

        if (*srpag_count > PCEP_SR_SRPAG_ASSOCIATION_MAX_COUNT) {
            TRACE_CORE("sending PCError: more than 1 SRPAG asssociations received for LSP."
                "SRPAG count is: %d", *srpag_count);

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_MULTIPLE_SRPAG_IN_LSP);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if (info->lsp_type_info.setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
            TRACE_CORE("sending PCError: IPv6 SRPAG received for non SRv6 LSP");

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_SRPAG_IN_NON_SR_LSP);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if ((false == assoc->extended_assoc_id) ||
                (false == assoc->extended_assoc_id_tlv.process_as_srpag_tlv)||
                (false == assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6)||
               (false == assoc->sr_candidate_path_identifier)) {

            TRACE_CORE("sending PCError: policy or candidate path identifiers is missing"
                "extended association id TLV: %d, extended assoc id TLV processed as SRPAG: %d"
                "extended assoc id TLV contains SRPAG endpoint: %d, sr candidate path identifier TLV: %d",
                assoc->extended_assoc_id, assoc->extended_assoc_id_tlv.process_as_srpag_tlv,
                assoc->extended_assoc_id_tlv.is_srpag_endpoint_ipv6, assoc->sr_candidate_path_identifier);

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                    PCEP_ERR_VAL_MISSING_MANDATORY_SRPAG_TLV);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if ( 1 == assoc->flag_remove ) {
            TRACE_CORE("sending PCError: SRPAG association cannot be removed in lifetime of LSP");

            pccd_send_error_with_srp(conn, srp_id,
                                    PCEP_ERR_TYPE_RIP,
                                    PCEP_ERR_SRPAG_REMOVE_ASSOCIATION);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        /*
          Below NULL check is passed for PCUpdate only as rpd_lsp is NULL during PCInit
        */
        if (NULL != rpd_lsp) {
            while ((itr < rpd_lsp->num_assoc_info) && (itr < LSP_ASSOCIATION_TYPE_MAX)) {
                if (LSP_ASSOCIATION_TYPE_SRPAG == rpd_lsp->assoc_info[itr].assoc_type) {
                    rpd_lsp_srpag_found = true;
                    if(pccd_core_validate_srpag_ipv6_identifiers (&rpd_lsp->assoc_info[itr], assoc)) {
                        TRACE_CORE("sending PCError: policy or candidate path identifiers changed");
                        pccd_send_error_with_srp(conn, srp_id,
                                PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                                PCEP_ERR_VAL_CONFLICTING_SRPAG_TLV);
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }
                    break;
                }
                itr++;
            }

            if (false == rpd_lsp_srpag_found) {
                TRACE_CORE("sending PCError: srpag cannot be added for uncolored LSP");
                pccd_send_error_with_srp(conn, srp_id,
                    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE,
                    PCEP_ERR_VAL_CONFLICTING_SRPAG_TLV);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
        }

        info->assoc_info[info->num_assoc_info].assoc_grp_id = assoc->association_id;
        info->assoc_info[info->num_assoc_info].is_assoc_src_ipv6 = true;
        memcpy(info->assoc_info[info->num_assoc_info].assoc_source_u.v6,
            &assoc->ipv6_association_source, sizeof(struct in6_addr));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.color =
            assoc->extended_assoc_id_tlv.srpag_color;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_endpoint_ipv6 = true;
        memcpy(info->assoc_info[info->num_assoc_info].sr_srpag_t.srpag_endpoint_addr_u.v6,
            &assoc->extended_assoc_id_tlv.srpag_endpoint.v6, sizeof(struct in6_addr));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.sr_proto_origin =
            (sr_proto_origin_t)assoc->sr_candidate_path_identifier_tlv.proto_origin_;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_asn =
            assoc->sr_candidate_path_identifier_tlv.originator_asn;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_originator_ipv6 = true;
        memcpy(info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v6,
            &assoc->sr_candidate_path_identifier_tlv.originator_address.v6, sizeof(struct in6_addr));
        info->assoc_info[info->num_assoc_info].sr_srpag_t.discriminator =
            assoc->sr_candidate_path_identifier_tlv.discriminator;
        info->assoc_info[info->num_assoc_info].sr_srpag_t.preference_valid =
            assoc->sr_preference;

        if (assoc->sr_preference) {
            info->assoc_info[info->num_assoc_info].sr_srpag_t.preference =
                assoc->sr_preference_tlv.preference;
        }

        inet_ntop(AF_INET6, info->assoc_info[info->num_assoc_info].assoc_source_u.v6, assoc_ip_str,
                sizeof(assoc_ip_str));
        inet_ntop(AF_INET6, &assoc->extended_assoc_id_tlv.srpag_endpoint.v6, end_point_str,
                sizeof(end_point_str));
        inet_ntop(AF_INET6, info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v6,
                originator_ip_str, sizeof(originator_ip_str));

        TRACE_CORE("Set association: 0x%"PRIx64, info->assoc_info[info->num_assoc_info]);
        TRACE_CORE("Set count %d,association Type %d"
            " association id: %u, association source:%s ",info->num_assoc_info,
            info->assoc_info[info->num_assoc_info].assoc_type,
            info->assoc_info[info->num_assoc_info].assoc_grp_id,
            assoc_ip_str);

        TRACE_CORE("set SRPAG association: color: %u, end point: %s, proto origin: %u, "
                "originator asn: %u, originator ip: %s, discriminator: %u, "
                "preference valid: %u, preference: %u",
                info->assoc_info[info->num_assoc_info].sr_srpag_t.color,
                end_point_str,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.sr_proto_origin,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_asn,
                originator_ip_str,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.discriminator,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.preference_valid,
                info->assoc_info[info->num_assoc_info].sr_srpag_t.preference);
    }

     info->num_assoc_info++;
     info->assoc_requested = 1;

     TRACE_FUNCTION_RETURN(0);
 }

static int
pccd_core_parse_bw_req (struct pcep_conn *conn UNUSED,
                        rpd_extctrl_lsp_config_status_info_t *info,
                        const struct pcep_obj_bandwidth *bw,
                        lsp_intended_attr_t *intended_attrs)
{
    TRACE_FUNCTION_ENTRY();
   
    if (bw->bps < 0) {
        TRACE_CORE("Bandwidth value is negative");
        TRACE_FUNCTION_RETURN(-1);
    }
 
    info->bandwidth = (uint64_t) (bw->bps * 8);
    TRACE_CORE("Set bandwidth: %"PRIu64, info->bandwidth);

    intended_attrs->bw = info->bandwidth;
    intended_attrs->bw_valid = TRUE;

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static int
pccd_core_parse_metric(struct pcep_conn *conn UNUSED,
                       rpd_extctrl_lsp_config_status_info_t *info UNUSED,
                       const struct pcep_obj_metric *mt,
                       lsp_intended_attr_t *intended_attrs)
{
    TRACE_FUNCTION_ENTRY();
    struct lsp_metric_s *intended_metric_new = NULL;

    if (mt->value < 0) {
        TRACE_CORE("Metric value is negative");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    TRACE_CORE("Received Metric type:%d", mt->type);

    if ((1 == mt->bound) && (1 == mt->computed)) {
        TRACE_CORE("Ignoring the metric as both b and c flags are set. Type %d, val %f, b %d c %d",
                mt->type, mt->value, mt->bound, mt->computed);
        TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    } else if ((0 == mt->bound) && (0 == mt->computed) && (mt->value != 0)) {
        TRACE_CORE("Ignoring the metric as b flag, c flag is 0 and value is non zero. Type %d, val %f, b %d c %d",
                mt->type, mt->value, mt->bound, mt->computed);
        TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    intended_metric_new = xcalloc(1, sizeof(*intended_metric_new));
    if (!intended_metric_new) {
       TRACE_CORE("Cannot allocate memory for new intended metric....aborting");
       abort();
    }

    intended_metric_new->metric_info.metric_type = mt->type;

    if (mt->value > MAX_METRIC_VALUE) {
        intended_metric_new->metric_info.metric = (uint32_t)MAX_METRIC_VALUE;
        TRACE_CORE("Metric value is greater than unsigned 32 bit integer. Storing metric value as %u",
                intended_metric_new->metric_info.metric);
    } else {
        intended_metric_new->metric_info.metric = (uint32_t) (mt->value);
    }
    intended_metric_new->metric_info.bound_flag = mt->bound;
    intended_metric_new->metric_info.computed_flag = mt->computed;

    SLIST_INSERT_HEAD(&intended_attrs->intended_metric_head, intended_metric_new, metric_next);

    struct lsp_metric_s *intended_metric = NULL, *tmp;
    SLIST_FOREACH_SAFE(intended_metric, &intended_attrs->intended_metric_head, metric_next, tmp) {
        TRACE_CORE("Received metric, type %d, val %d, b %d c %d",
                intended_metric->metric_info.metric_type,
                intended_metric->metric_info.metric,
                intended_metric->metric_info.bound_flag,
                intended_metric->metric_info.computed_flag);
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static int
pccd_core_parse_vendor (struct pcep_conn *conn UNUSED,
			rpd_extctrl_lsp_config_status_info_t *info,
			const struct pcep_obj_vendor *vend)
{
    int	vendor_obj_counter;
    TRACE_FUNCTION_ENTRY();

    if (JNPR_ENTERPRISE_NUMBER != vend->enterprise) {
        TRACE_CORE("Received non-Juniper vendor information object,"
                   " enterprise number %d, ignoring it", vend->enterprise);
        TRACE_FUNCTION_RETURN(0);
    }

    if (0 == vend->size) {
        TRACE_CORE("No vendor objects present");
        TRACE_FUNCTION_RETURN(-1);
    }

    for (vendor_obj_counter = 0; vendor_obj_counter < vend->size;
							vendor_obj_counter ++) {
	switch (vend->info[vendor_obj_counter].type) {
	case PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF:
	    info->relcsi_local_cspf =
				vend->info[vendor_obj_counter].u.pvi_local_cspf;
	    TRACE_CORE("vendor local cspf(%d)", info->relcsi_local_cspf);
	    break;
	case PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE:
        info->metric = vend->info[vendor_obj_counter].u.route_preference;
        info->metric_valid = TRUE;
        TRACE_CORE("route preference (%u)", info->metric);
	    break;
	default:
	    break;
	}
    }

    TRACE_FUNCTION_RETURN(0);
}

static bool
pccd_send_error_with_srp (struct pcep_conn *conn, uint32_t srp_id,
                          uint8_t err_type, uint8_t err_value)
{
    uint32_t obj_index = 0;

    struct pcep_obj_srp *srp = NULL;
    struct pcep_obj_error *err = NULL;
    struct pce_cfg_core *pce = NULL;
    struct pcep_object obj[2];
    bzero(obj, sizeof (obj));

    srp = &obj[obj_index].u.srp;
    obj[obj_index].type = PCEP_OBJ_SRP;
    srp->srp_id = srp_id;

    err = &obj[++obj_index].u.error;
    obj[obj_index].type = PCEP_OBJ_PCEPERROR;
    err->type = err_type;
    err->value = err_value;

    /* Find the PCE this message belongs to */
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce->pc_conn == conn) {
            break;
        }
    }
    /* Add error to statistics */
    if (pce != NULL) {
        pccd_add_key_stat_elem(&pce->pc_statistics.pc_last_err_sent,
                      err->type, err->value);
        pccd_add_key_stat(&pce->pc_statistics.pc_errs_sent, err->type,
                      err->value);
        pce->pc_pce.peer_table->pcePcepPeerNumPCErrSent++;
        pce->pc_pce.sess_table->pcePcepSessNumPCErrSent++;
    }
    return pcep_send_message(conn, PCEP_MSG_ERROR, &obj[0], ++obj_index);
}


/**
 * pccd_core_parse_srp
 *
 * Parse the SRP object in the incoming PCCreate/PCUpdate message
 *
 * Checks for SR LSP's type message, PCE is spring capable
 *
 * @param[in] pce:   : PCE who had send this message.
 *            srp    : PCEP SRP Object
 *       [out] srp_id  : SRP identifier, that is filled after parsing.
 *
 * @return  PCCD_RET_SUCCESS(0), if parsing is successful
 *          PCCD_RET_FAIL(-1)    in failure.
 */
static int
pccd_core_parse_srp (struct pce_cfg_core *pce, const struct pcep_obj_srp *srp,
                     uint32_t *srp_id)
{
    // Remember the SRP ID
    *srp_id = srp->srp_id;

    if (srp->lsp_setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
        // test if PCE is spring capable.
        if (!pccd_core_pce_spring_capability(pce)) {
            pccd_send_error_with_srp(pce->pc_conn, *srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_UNSUP_NUM_SR_ERO);
            return PCCD_RET_FAIL;
        }
    } else if (srp->lsp_setup_type == srv6_pst_type) {
        // test if PCE is srv6 capable
        if (!pccd_core_pce_srv6_capability(pce)) {
            LOGGING_ERR("PCC/ PCE is not SRv6 capable");

            TRACE_CORE("PCC/PCE is not SRv6 capable");
            pccd_send_error_with_srp(pce->pc_conn, *srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_SRV6_UNSUPPORTED);
            return PCCD_RET_FAIL;
        }
    }

    return PCCD_RET_SUCCESS;
}

/**
 * pccd_core_handle_srp_object
 *
 * Handle the SRP object in the incoming PCCreate/PCUpdate message
 *
 * Checks for SRP object in object array pointed by index.
 *
 * @param[in] pce:   : PCE who had send this message.
 *            objs   : PCEP object array
 *            i      : Current index location in object array
 *       [out] srp_id  : SRP identifier, that is filled after parsing.
 *             increment_index: Flag to tell index needs to increment.
 *
 * @return  PCCD_RET_SUCCESS(0), if parsing is successful
 *          PCCD_RET_FAIL(-1)    in failure.
 */
static int
pccd_core_handle_srp_object (struct pce_cfg_core *pce,
                             const struct pcep_object *objs,
                             unsigned i, uint32_t *srp_id, bool *increment_index)
{
    int ret;
    const struct pcep_obj_srp *srp;

    if (objs[i].type != PCEP_OBJ_SRP) {
        LOGGING_ERR("Received invalid message from PCE: '%s'. First "
                    "object is not SRP", pce->pc_pce.pce_id);

        TRACE_CORE("First object is not SRP, index value: %u", i);
        pcep_send_pcerr(pce->pc_conn, PCEP_ERR_TYPE_MOM, PCEP_ERR_VAL_SRP_MISSING);

        return PCCD_RET_FAIL;
    }

    srp = &objs[i].u.srp;

    ret =  pccd_core_parse_srp(pce, srp, srp_id);

    /*
     * Error occured in parsing the SRP object, set flag to increment index.
     * Caller is expected to increment index to correctly procees multiple
     * LSP messages.
     */
    if (ret == PCCD_RET_FAIL) {
       *increment_index = true;
    }

    return ret;
}


static int
pccd_core_parse_association_list(struct pcep_conn *conn,
                               const struct pccd_rpd_lsp_info *rpd_lsp,
                               rpd_extctrl_lsp_config_status_info_t *info,
                               const struct pcep_object *objs, unsigned count,
                               uint32_t srp_id)
{
    int handled_objs = 0;
    int srpag_count  = 0;
    int srpag_ipv6_count  = 0;
    unsigned i = 0;
    struct pcep_object *dag_obj_list[PCCD_MAX_DISJOINT_ASSOC_GROUPS];
    uint32_t dag_obj_count = 0;
    bool dag_obj_isipv6[PCCD_MAX_DISJOINT_ASSOC_GROUPS] = {false, false, false, false, false, false, false, false};

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(objs != NULL);
    INSIST_ERR(info != NULL);

    for (i = 0; i < count; i++) {
        switch (objs[i].type) {
        case PCEP_OBJ_ASSOCIATION_nonRFC:
        case PCEP_OBJ_ASSOCIATION_nonIANA: {
            if (objs[i].type != PCEP_OBJ_ASSOCIATION_VAL) {
                goto out;
            }

            if (pccd_core_parse_assoc_obj_non_rfc(conn, srp_id, info, &objs[i].u.association_non_rfc)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }

            handled_objs++;
            BIT_SET(info->lcs_params_flags, TAG_EXTCTRL_PARAMS_ASSOCIATION);
            break;
        }
        case PCEP_OBJ_ASSOCIATION: {
            if (NULL != rpd_lsp) {
            if (ASSOCIATION_TYPE_DISJOINT == objs[i].u.association.association_type) {
                if (dag_obj_count >= PCCD_MAX_DISJOINT_ASSOC_GROUPS) {
                    TRACE_CORE(" Received more than 8 diveristy association objects in given"
                               " message. Not processing the message");
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
                const struct pcep_object *obja = &objs[i];
                dag_obj_list[dag_obj_count] = (struct pcep_object *) obja;
                dag_obj_isipv6[dag_obj_count] = false;
                dag_obj_count++;
                break;
            }
                if (pccd_core_parse_assoc_obj(conn, srp_id, rpd_lsp, &srpag_count, info, &objs[i].u.association)) {
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }

                handled_objs++;
            } else {
                TRACE_CORE("Cannot find created lsp");
                pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_SYNC_ERR,
                                 PCEP_ERR_VAL_PCC_SYNC_ERR);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            break;
        }
        case PCEP_OBJ_ASSOCIATION_IPV6: {
            if (NULL != rpd_lsp) {
            if (ASSOCIATION_TYPE_DISJOINT == objs[i].u.association_ipv6.association_type) {
                if (dag_obj_count >= PCCD_MAX_DISJOINT_ASSOC_GROUPS) {
                    TRACE_CORE(" Received more than 8 diveristy association objects in given"
                               " message. Not processing the message");
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
                const struct pcep_object *obja = &objs[i];
                dag_obj_list[dag_obj_count] = (struct pcep_object *) obja;
                dag_obj_isipv6[dag_obj_count] = true;
                dag_obj_count++;
                continue;
            }
                if (pccd_core_parse_assoc_ipv6_obj(conn, srp_id, rpd_lsp, &srpag_ipv6_count, info, &objs[i].u.association_ipv6)) {
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }

                handled_objs++;
            } else {
                TRACE_CORE("Cannot find created lsp");
                pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_SYNC_ERR,
                                 PCEP_ERR_VAL_PCC_SYNC_ERR);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            break;
        }
        default:
            break;
        }
    }

    if (dag_obj_count) {
        if (disjoint_association_enabled == false) {
            TRACE_CORE("Received disjoint assoc TLVs eventhough PCC is not capable");
            pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_NSO,
                                     PCEP_ERR_VAL_OBJECT_TYPE);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        if (pccd_core_parse_lsp_diversity_association(conn, info, dag_obj_count,
                                                      dag_obj_isipv6, dag_obj_list, srp_id, true)) {
            TRACE_FUNCTION_RETURN(-1);
        }
        handled_objs += dag_obj_count;
    } else {
        TRACE_CORE("DAG: No diversity association info found");
    }

out:

    TRACE_FUNCTION_RETURN(handled_objs);
}


static int
pccd_core_parse_path_attribute(struct pcep_conn *conn,
                               const struct pccd_rpd_lsp_info *rpd_lsp,
                               rpd_extctrl_lsp_config_status_info_t *info,
                               const struct pcep_object *objs, unsigned count,
                               uint32_t srp_id, lsp_intended_attr_t *intended_attrs,
                               uint32_t plsp_id)
{
    bool lspa_present = false;
    bool bandwidth_present = false;
    int handled_objs = 0;
    unsigned i = 0;
    uint8_t fs_obj_cnt = 0;

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(objs != NULL);
    INSIST_ERR(info != NULL);


    info->relcsi_local_cspf = 0;

    for (i = 0; i < count; i++) {
        switch (objs[i].type) {
        case PCEP_OBJ_LSPA:
            if (lspa_present) {
                TRACE_CORE("Multiple LSPA objects for the same LSP");
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_CNS,
                                         PCEP_ERR_VAL_GENERIC);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            if (pccd_core_parse_lspa(conn, info, &objs[i].u.lspa, false)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            handled_objs++;
            lspa_present = true;
            break;
        case PCEP_OBJ_BANDWIDTH_REQUEST:
            if (bandwidth_present) {
                TRACE_CORE("Multiple BW objects for the same LSP");
                pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_CNS,
                                     PCEP_ERR_VAL_GENERIC);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            if (pccd_core_parse_bw_req(conn, info, &objs[i].u.bandwidth,
                                       intended_attrs)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            handled_objs++;
            bandwidth_present = true;
            BIT_SET(info->lcs_params_flags, TAG_EXTCTRL_PARAMS_BANDWIDTH);
            break;
        case PCEP_OBJ_ASSOCIATION_nonRFC:
        case PCEP_OBJ_ASSOCIATION_nonIANA:
        case PCEP_OBJ_ASSOCIATION:
        case PCEP_OBJ_ASSOCIATION_IPV6: {
            /* Be more liberal in association object order.
            This is to decode association object in old order */
            int ret = PCCD_RET_SUCCESS;

            //Count is 1 as only 1 object needs to be parsed
            ret = pccd_core_parse_association_list(conn, rpd_lsp, info, objs + handled_objs, 1, srp_id);
            if (ret == PCCD_RET_FAIL) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            handled_objs += ret;
            break;
        }
        case PCEP_OBJ_METRIC:
            if (pccd_core_parse_metric(conn, info, &objs[i].u.metric,
                                       intended_attrs)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            handled_objs++;
            break;
        case PCEP_OBJ_VENDOR:
            if (pccd_core_parse_vendor(conn, info, &objs[i].u.vendor)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }

            handled_objs++;
            break;
        case PCEP_OBJ_BANDWIDTH_REOPTIM:
            TRACE_CORE("UNIMPLEMENTED OBJECT TYPE: object: %d",
                        objs[i].type);
            pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_NSO,
                                 PCEP_ERR_VAL_OBJECT_TYPE);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            break;
        case PCEP_OBJ_FLOWSPEC: {

            if (fs_obj_cnt >= MAX_FLOWSPEC_SUPPORTED_PER_LSP) {
                TRACE_CORE("Maximum %d flowspec only can be mapped to lsp",
                            MAX_FLOWSPEC_SUPPORTED_PER_LSP);
                break;
            }

            /* Increment parsed fs object count */
            fs_obj_cnt++;

            /* 
             * For P2P LSP, this will handle flowspec destination prefix processing.
             * For P2MP Multicast flowspec, processing is done at later point
             */
            pccd_core_pcupdate_proc_one_fs_prefix(&objs[i].u.flowspec,
                                plsp_id);

            handled_objs++;
            break;
        }
        default:
            goto out;
        }
    }

out:
    /**
     * Need to always send prefix list to RPD for P2P LSPs with every pc update
     * msg so populate install prefix buffer of lcs info from prefix table
     */
    if (rpd_lsp && !(rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP)) {
        pccd_rpd_update_prefix_in_lcs_info(info, rpd_lsp->prefix_root);
    }

    TRACE_FUNCTION_RETURN(handled_objs);
}

/**
 * @brief
 * parse the ero in PCInit or PCUpd message
 *
 * parses strict-loose, loose-ero & no-ero object.
 *
 * @param[in] info
 * 	object that will be passed to rpd
 * @param[in] ero
 * 	ero which is received via pcep
 * @return
 * 	processing status code
 * 	@li PCCD_RET_SUCCESS - success
 * 	@li PCCD_RET_FAIL - on general failure
 */
static pccd_ret_code_t
pccd_core_parse_ero (rpd_extctrl_lsp_config_status_info_t*  info,
                     const struct pcep_obj_ero*             ero,
                     bool* is_empty_ero)
{
    RouteObj *ro = NULL;
    uint8_t *entry = NULL;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    info->ero_info = NULL;
    info->ero_len = 0;

    if ((NULL == ero ) || (0 == ero->subcount)) {
	/*
	 * FIXME:ramesh
	 * add this stat. currently data structures are bad that it is
	 * hard to back traverse upto pce and then add stats. so this broken
	 * data structure link have to be fixed before adding stats.
	 * if (!pccd_add_timed_stat(&pce->pc_statistics.no_ero_msg)) {
	 *   TRACE_CORE("Adding timed stat for no-ero failed");
	 * }
	 */
	/*
	 * with no-ero make sure to send NULL ero to rpd/tag(not emptry ero)
	 */
	if (is_empty_ero) {
	    *is_empty_ero = TRUE;
	}
	TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    /*
     * we don't want to do realloc for every possible subobject in ERO,
     * so create buffer big enough to hold ero->subcount number of the biggest
     * ro_entry there is.
     */
    ro = xmalloc(sizeof(OBJ_HDR) + ero->subcount *
                           sizeof(*((RouteObj *)NULL)->entry));
    ro->hdr.obj_class = 0; /* OBJC_ERO; */
    ro->hdr.obj_ctype = 0; /* OBJtype_ERO; */
    ro->hdr.obj_length = sizeof(OBJ_HDR);
    entry = (uint8_t*) ro->entry;

    for (i = 0; i < ero->subcount; i++) {
        const struct pcep_obj_ero_sub *sub = &ero->subs[i];
        switch(sub->type) {
        case PCEP_ERO_SUB_IPV4: {
            ro_entry_v4 *ro_v4 = (ro_entry_v4 *) entry;
            if (sub->loose) {
                ro_v4->type = RO_V4_LOOSE;
            } else {
                ro_v4->type = RO_V4_STRICT;
            }
            ro_v4->len = sizeof(*ro_v4);
            memcpy(&ro_v4->node, &sub->data.ipv4_prefix.address,
                   sizeof(ro_v4->node));
            ro_v4->mask = sub->data.ipv4_prefix.prefix_length;
            ro_v4->flags = 0;
            TRACE_CORE("Stored IPV4 %s/%d prefix in ro_entry %p",
                       inet_ntoa(sub->data.ipv4_prefix.address), ro_v4->mask,
                       ro_v4);
            ro->hdr.obj_length += ro_v4->len;
            entry = entry + ro_v4->len;
            break;
        }
        case PCEP_ERO_SUB_UNNUMBERED_IID: {
            ro_entry_unnum *unnum = (ro_entry_unnum *)ro->entry;
            if (sub->loose) {
                unnum->type = RO_UNNUM_LOOSE;
            } else {
                unnum->type = RO_UNNUM_STRICT;
            }
            unnum->len = sizeof(*unnum);
            unnum->reserved = 0;
            unnum->rtr_id = sub->data.unnumbered_iid.router_id;
            unnum->if_id = sub->data.unnumbered_iid.interface_id;
            TRACE_CORE("Stored UNNUM IF IID: rtr:%"PRIu32" if:%"PRIu32,
                       unnum->rtr_id, unnum->if_id);
            ro->hdr.obj_length += unnum->len;
            entry = entry + unnum->len;
            break;
        }
        case PCEP_ERO_SUB_AUTONOMOUS: {
            ro_entry_asn *asn = (ro_entry_asn *)ro->entry;
            if (sub->loose) {
                asn->type = RO_UNNUM_LOOSE;
            } else {
                asn->type = RO_UNNUM_STRICT;
            }
            asn->len = sizeof(*asn);
            asn->system_number = sub->data.autonomous.system_number;
            TRACE_CORE("Stored AUTONOMOUS SYSTEM NUMBER: asn:%"PRIu32,
                       asn->system_number);
            ro->hdr.obj_length += asn->len;
            entry = entry + asn->len;
            break;
        }
        default:
            TRACE_CORE("Received ERO with unsupported subobject: %d",
                       sub->type);
            free(ro);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }

    ro->hdr.obj_length = htons(ro->hdr.obj_length);
    info->ero_info = ro;
    info->ero_len = ntohs(ro->hdr.obj_length);

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static pccd_ret_code_t
pccd_core_parse_spring_ero(struct pcep_conn *conn, 
                           rpd_extctrl_lsp_config_status_info_t *info,
                           const struct pcep_obj_ero *ero, uint32_t srp_id,
                           bool *is_empty_ero)
{
    rpd_sr_ero_list_t *rpd_sr_ero_list = NULL;
    unsigned len = 0;
    unsigned i;

/* TODO Fix for more ERO, now just primary ero is used */
    TRACE_FUNCTION_ENTRY();
    info->ero_info = NULL;
    info->ero_len = 0; 
    if ((NULL == ero ) || (0 == ero->subcount)) {
	/*
	 * with no-ero make sure to send NULL ero to rpd/tag(not emptry ero)
	 */
	if (is_empty_ero) {
	    *is_empty_ero = TRUE;
	}
	TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    /* We don't want to do realloc for every possible subobject in ERO,
     * so create buffer big enough to hold ero->subcount number of the biggest
     * ro_entry there is.
     */

    if (ero->subcount > pcep_get_local_msd(conn) ||
        ero->subcount > PCCD_MAX_SID_DEPTH) {
        LOGGING_ERR("ERO with unsupported number of segment subobjects"
                    "found in Path Update in PCUpd message");
        pccd_send_error_with_srp(conn, srp_id,
                                 PCEP_ERR_TYPE_RIO,
                                 PCEP_ERR_VAL_UNSUP_NUM_SR_ERO);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    len = RPD_SR_ERO_LIST_ESTIMATE_LEN(ero->subcount);
    rpd_sr_ero_list = xmalloc(len);

    rpd_sr_ero_list->rsel_type = RPD_SR_ERO_LIST_SRMPLS;
    rpd_sr_ero_list->rsel_n_eros = ero->subcount;
    rpd_sr_ero_list->rsel_weight = ero->path_attribs.weight;
    rpd_sr_ero_list->rsel_path_id = ero->path_attribs.path_id;
    rpd_sr_ero_list->rsel_op_state = (uint16_t) ero->path_attribs.op_state;
    if (!ero->path_attribs.secondary_path) {
        rpd_sr_ero_list->resel_path_flags = rpd_sr_ero_list->resel_path_flags |
                                                LSP_PATH_TYPE_PRIMARY;
    }

    for (i = 0; i < ero->subcount; i++) {
        const struct pcep_obj_ero_sub_sr* sr_ero =  NULL;
        const struct pcep_obj_ero_sub *sub = &ero->subs[i];

        if (sub->type != PCEP_ERO_SUB_SR) {
            LOGGING_ERR("ERO with non identical segment subobjects"
                        "found in Path Update in PCUpd message");
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_NON_IDENT_SR_ERO);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        rpd_sr_ero_list->rsel_ero[i].rse_loose = sub->loose;
        sr_ero =  &sub->data.sr_ero;

        /**
         * If S_bit is set and F_bit is set, return error
         */
        if (sr_ero->S_bit && sr_ero->F_bit) {
            LOGGING_ERR("ERO segment subobject with both SID and NAI"
                        "absent in Path Update in PCUpd message");
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_SID_NAI_ABST_SR_ERO);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        /**
         * If S_bit is set and either M_bit or C_bit is set, return error
         */
        if (sr_ero->S_bit && (sr_ero->M_bit || sr_ero->C_bit)) {
            LOGGING_ERR("ERO segment subobject: SID is absent");
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_MALFORMED_OBJECT);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        /**
         * If S_bit is set, SID is absent.
         */
        if (sr_ero->S_bit) {
            TRACE_CORE("SID is absent");
        } else if (sr_ero->M_bit) {
            /**
             * M_bit is set, SID represents MPLS label.
             */
            if (sr_ero->C_bit) {
                rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_label_32 = htonl(sr_ero->sid);
                rpd_sr_ero_list->rsel_ero[i].rse_sid.rses_type = RPD_SR_ERO_SID_TYPE_LABEL_32;
                TRACE_CORE("Added SID label-32 is: %d", sr_ero->sid);
            } else {
                rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_label_20 = htonl(sr_ero->sid);
                rpd_sr_ero_list->rsel_ero[i].rse_sid.rses_type = RPD_SR_ERO_SID_TYPE_LABEL_20;
                TRACE_CORE("Added SID label-20 is: %d", sr_ero->sid);
            }
        } else {
            /**
             * M_bit is not set, SID represent index into MPLS label space
             */
            rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_index = htonl(sr_ero->sid);
            rpd_sr_ero_list->rsel_ero[i].rse_sid.rses_type = RPD_SR_ERO_SID_TYPE_INDEX;
            TRACE_CORE("Added SID index from is: %d", sr_ero->sid);
            TRACE_CORE("Added SID index to is: %d", rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_index);
        }
 
        if (sr_ero->F_bit) {
            rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_ABSENT;
        }

        switch (sr_ero->nai_type) {
            case PCEP_SR_ERO_NAI_TYPE_ABSENT: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_ABSENT;
                break;
            }
            case PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID;
                memcpy(&rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_node_ipv4_addr,
                                         &sr_ero->NAI_data.ipv4_node_id.address, 4);
                break;
            }  
#ifdef PCEP_SR_IPV6
            case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_node_ipv6_addr,
                                        &sr_ero->NAI_data.ipv6_node_id.address, 16);
                break;
            }
#endif
            case PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID;
                memcpy(&rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv4.rsen_local_addr,
                                                    &sr_ero->NAI_data.ipv4_adjacency.local, 4);
                memcpy(&rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv4.rsen_remote_addr,
                                                    &sr_ero->NAI_data.ipv4_adjacency.remote, 4);
                break;
            } 
#ifdef PCEP_SR_IPV6 
            case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                                                 &sr_ero->NAI_data.ipv6_adjacency.local, 16);
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                                                 &sr_ero->NAI_data.ipv6_adjacency.remote, 16);
                break;
            }  
#endif
#ifdef PCEP_SR_UNNUMBERED
            case PCEP_SR_ERO_NAI_TYPE_UNNUMBERED: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_UNNUMBERED;
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_unnumbered.rsen_local_node_id =
                                                    htonl(sr_ero->NAI_data.unnum_adj.local_node_id);
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_unnumbered.rsen_local_intf_id =
                                                htonl(sr_ero->NAI_data.unnum_adj.local_interface_id);
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_unnumbered.rsen_remote_node_id =
                                                    htonl(sr_ero->NAI_data.unnum_adj.remote_node_id);
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_unnumbered.rsen_remote_intf_id =
                                                htonl(sr_ero->NAI_data.unnum_adj.remote_interface_id);
                break;
            }
#endif
            default:
                TRACE_CORE("Received ERO with unsupported SPRING subobject: %d",
                       sr_ero->nai_type);
                free(rpd_sr_ero_list);
                TRACE_FUNCTION_RETURN(-1);
        }
    }
    uint32_t counter = 0;
    rpd_sr_ero_list_t *srte_ero_list = info->srte_ero_info;
    TRACE_CORE(" parse SR ERO - LSP %s - existing ero list count %u",
               info->name, info->srte_total_ero_count);
    while (counter < info->srte_total_ero_count) {
        srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
        counter++;
    }
    memcpy(srte_ero_list, rpd_sr_ero_list, len);
    info->srte_total_ero_count += 1;
    TRACE_CORE(" parse SR ERO - LSP %s - Updated ERO list count %u, new ero len %u",
               info->name, info->srte_total_ero_count, len);
    
    pccd_core_print_sr_ero_info(rpd_sr_ero_list);

    free(rpd_sr_ero_list);
    TRACE_FUNCTION_RETURN(0);
}

static pccd_ret_code_t
pccd_core_parse_spring_v6_ero(struct pcep_conn *conn,
                           rpd_extctrl_lsp_config_status_info_t *info,
                           const struct pcep_obj_ero *ero, uint32_t srp_id,
                           bool *is_empty_ero)
{
    rpd_sr_ero_list_t *rpd_sr_ero_list = NULL;
    unsigned len = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    info->ero_info = NULL;
    info->ero_len = 0;
    if ((NULL == ero ) || (0 == ero->subcount)) {
    /*
     * with no-ero make sure to send NULL ero to rpd/tag(not emptry ero)
     */
    if (is_empty_ero) {
        *is_empty_ero = TRUE;
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    /* We don't want to do realloc for every possible subobject in ERO,
     * so create buffer big enough to hold ero->subcount number of the biggest
     * ro_entry there is.
     */

    if (ero->subcount > maximum_srv6_segment_list_depth) {
        LOGGING_ERR("ERO with unsupported number of SRv6 subobjects"
                    "found in Path Update in PCUpd message");
        pccd_send_error_with_srp(conn, srp_id,
                                 PCEP_ERR_TYPE_RIO,
                                 PCEP_ERR_VAL_UNSUP_NUM_SRV6_ERO);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    len = RPD_SR_ERO_LIST_ESTIMATE_LEN(ero->subcount);
    rpd_sr_ero_list = xmalloc(len);

    rpd_sr_ero_list->rsel_type = RPD_SR_ERO_LIST_SRV6;
    rpd_sr_ero_list->rsel_n_eros = ero->subcount;
    rpd_sr_ero_list->rsel_weight = ero->path_attribs.weight;
    rpd_sr_ero_list->rsel_path_id = ero->path_attribs.path_id;
    rpd_sr_ero_list->rsel_op_state = (uint16_t) ero->path_attribs.op_state;
    if (!ero->path_attribs.secondary_path) {
        rpd_sr_ero_list->resel_path_flags = rpd_sr_ero_list->resel_path_flags |
                                                LSP_PATH_TYPE_PRIMARY;
    }

    for (i = 0; i < ero->subcount; i++) {
        const struct pcep_obj_ero_sub_srv6* srv6_ero =  NULL;
        const struct pcep_obj_ero_sub *sub = &ero->subs[i];

        if (sub->type != srv6_ero_subobject_type) {
            LOGGING_ERR("ERO with non identical segment subobjects of type %u"
                        "found in Path Update in PCUpd message", sub->type);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_NON_IDENT_SR_ERO);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        rpd_sr_ero_list->rsel_ero[i].rse_srv6_loose = sub->loose;
        srv6_ero =  &sub->data.srv6_ero;

        if (srv6_ero->nai_type == PCEP_SR_ERO_NAI_TYPE_INVALID) {
            LOGGING_ERR("Received invalid NAI type %d", srv6_ero->nai_type);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_UNSUPPORTED_NAI_TYPE);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        /**
         * If S_bit is set and F_bit is set, return error
         */
        if (srv6_ero->S_bit && srv6_ero->F_bit) {
            LOGGING_ERR("Srv6 ERO segment subobject with both SID and NAI"
                        "absent in Path Update in PCUpd message");
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_SID_NAI_ABST_SR_ERO);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        /**
         * If S_bit is set, SID is absent.
         */
        if (srv6_ero->S_bit) {
            LOGGING_ERR("SRv6 ERO segment subobject: SID is absent");
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_RIO,
                                     PCEP_ERR_VAL_NAI_TO_SID_CONVERSION);
            free(rpd_sr_ero_list);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        } else {
            char sidstr[INET6_ADDRSTRLEN] = "";
            char rpd_sidstr[INET6_ADDRSTRLEN] = "";

            memcpy(rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_addr,
                                                    &srv6_ero->sid, 16);
            rpd_sr_ero_list->rsel_ero[i].rse_sid.rses_type = RPD_SR_ERO_SID_TYPE_SRV6;


            inet_ntop(AF_INET6, &srv6_ero->sid, sidstr, sizeof(sidstr));
            inet_ntop(AF_INET6, &rpd_sr_ero_list->rsel_ero[i].rse_sid.u.rses_addr, rpd_sidstr, sizeof(rpd_sidstr));

            TRACE_CORE("Added SID index from is: %s", sidstr);
            TRACE_CORE("Added SID index to is: %s", rpd_sidstr);
        }

        if (srv6_ero->F_bit) {
            rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_ABSENT;
        }
        rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_verification = srv6_ero->V_bit;
        rpd_sr_ero_list->rsel_ero[i].rse_srv6_endpoint_behavior = srv6_ero->endpoint_behavior;

        switch (srv6_ero->nai_type) {
            case PCEP_SR_ERO_NAI_TYPE_ABSENT: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_ABSENT;
                break;
            }
            case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_node_ipv6_addr,
                                        &srv6_ero->NAI_data.ipv6_node_id.address, 16);
                break;
            }
            case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                                                 &srv6_ero->NAI_data.ipv6_adjacency.local, 16);
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                                                 &srv6_ero->NAI_data.ipv6_adjacency.remote, 16);
                break;
            }
            case PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ: {
                rpd_sr_ero_list->rsel_ero[i].rse_nai.rsen_type = RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr,
                                                 &srv6_ero->NAI_data.ipv6_linklocal_adj.local_ipv6_addr, 16);
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id =
                                                srv6_ero->NAI_data.ipv6_linklocal_adj.local_interface_id;
                memcpy(rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr,
                                                 &srv6_ero->NAI_data.ipv6_linklocal_adj.remote_ipv6_addr, 16);
                rpd_sr_ero_list->rsel_ero[i].rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id =
                                                srv6_ero->NAI_data.ipv6_linklocal_adj.remote_interface_id;
                break;
            }
            default:
                TRACE_CORE("Received ERO with unsupported SPRING V6 subobject: %d",
                       srv6_ero->nai_type);
                free(rpd_sr_ero_list);
                TRACE_FUNCTION_RETURN(-1);
        }

        if (srv6_ero->T_bit) {
            uint16_t sid_structure_sizes_sum = (srv6_ero->sid_structure.lb_length +
                                                srv6_ero->sid_structure.ln_length +
                                                srv6_ero->sid_structure.fun_length +
                                                srv6_ero->sid_structure.arg_length);
            if (sid_structure_sizes_sum > MAX_SUM_OF_SIZES_IN_SRV6_SID_STRUCTURE) {
                LOGGING_ERR("SRv6 SID structure is invalid, sum of sizes in sid structure is %d",
                                sid_structure_sizes_sum);
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_RIO,
                                         PCEP_ERR_VAL_INVALID_SID_STRUCTURE);
                free(rpd_sr_ero_list);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure_valid = true;
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure.lb_length = srv6_ero->sid_structure.lb_length;
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure.ln_length = srv6_ero->sid_structure.ln_length;
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure.fun_length = srv6_ero->sid_structure.fun_length;
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure.arg_length = srv6_ero->sid_structure.arg_length;
        } else {
            rpd_sr_ero_list->rsel_ero[i].rse_srv6_sid_structure_valid = false;
        }
    }
    uint32_t counter = 0;
    rpd_sr_ero_list_t *srte_ero_list = info->srte_ero_info;
    TRACE_CORE(" parse SRv6 ERO - LSP %s - existing ero list count %u",
               info->name, info->srte_total_ero_count);
    while (counter < info->srte_total_ero_count) {
        srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
        counter++;
    }
    memcpy(srte_ero_list, rpd_sr_ero_list, len);
    info->srte_total_ero_count += 1;
    TRACE_CORE(" parse SRv6 ERO - LSP %s - Updated ERO list count %u, new ero len %u",
               info->name, info->srte_total_ero_count, len);
    pccd_core_print_srv6_ero_info(rpd_sr_ero_list);

    free(rpd_sr_ero_list);
    TRACE_FUNCTION_RETURN(0);
}

/**
 * @brief
 * 	parse the path attributes in PCUpdate message
 *
 * @param[in] conn
 * 	pcep connection object
 * @param[in] info
 * 	information object that is going to be passed to rpd
 * @param[in] objs
 * 	the message which is received from pcep
 * @param[in] count
 * 	number of objects pending to be parsed
 * @param[in] srp_id
 * 	srp id
 * @param[out]
 * 	number of objects parsed in this routine
 *
 * @return
 * 	processing status code
 * 	@li PCCD_RET_SUCCESS - success
 * 	@li PCCD_RET_FAIL - on general failure
 */
static pccd_ret_code_t
pccd_core_handle_path(struct pce_cfg_core *pce,
                      const struct pccd_rpd_lsp_info *rpd_lsp,
                      rpd_extctrl_lsp_config_status_info_t *info,
                      const struct pcep_object *objs, size_t count,
                      uint32_t srp_id, unsigned *handled_objs,
                      bool *is_ero_empty, lsp_intended_attr_t *intended_attrs,
                      uint32_t plsp_id)
{
    const struct pcep_obj_ero	*ero;
    struct pcep_conn* conn = NULL;
    daemon_trace_file_options_t *dtfo = NULL;
    char name_rec[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    struct lsp_vector* lsp_vec = NULL;

    uint8_t err_type = 0;
    uint8_t err_value = 0;
    int fs_obj_cnt = 0;
    uint32_t fs_obj_start = 0;
    int ret = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(info != NULL);

    conn = pce->pc_conn;

    dtfo = pccd_core_pce_get_traceoptions(pce);

    /* If there was no ERO for this LSP, send PCErr 6.4 */
    if (!objs || !count || objs->type != PCEP_OBJ_ERO) {
	TRACE_CORE("%s - ERO object is missing in PCUpd message", info->name);
        pccd_send_error_with_srp(conn, srp_id,
                                 PCEP_ERR_TYPE_MOM,
                                 PCEP_ERR_VAL_ERO_MISSING);
	TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    ero = &objs->u.ero;
    if ((info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
        if (PCCD_RET_SUCCESS != pccd_core_parse_ero(info, ero, is_ero_empty)) {
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    } else if (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
        info->srte_total_ero_count = 0;
        info->srte_ero_len = (sizeof(rpd_sr_ero_list_t)) +
                                    ((objs->u.ero.subcount) * sizeof(rpd_sr_ero_t));
        info->srte_ero_info = xmalloc(info->srte_ero_len);
        if (PCCD_RET_SUCCESS != pccd_core_parse_spring_ero(conn, info, ero, srp_id, is_ero_empty)) {
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    } else if (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
        info->srte_total_ero_count = 0;
        info->srte_ero_len = (sizeof(rpd_sr_ero_list_t)) +
                                    ((objs->u.ero.subcount) * sizeof(rpd_sr_ero_t));
        info->srte_ero_info = xmalloc(info->srte_ero_len);
        if (PCCD_RET_SUCCESS != pccd_core_parse_spring_v6_ero(conn, info, ero, srp_id, is_ero_empty)) {
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }
    (*handled_objs)++;

    objs++; /* Move to next pcep object in incoming message */
    count--;

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(plsp_id);
    if (!lsp_vec) {
        TRACE_CORE("Unexpected behaviour, lsp vector not found for plsp id:%u",
                            plsp_id);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    fs_obj_cnt = pccd_core_pcupdate_validate_fs_obj(pce, lsp_vec, objs, count,
                                      &fs_obj_start, &err_type, &err_value);
    if (fs_obj_cnt < 0) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot update LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot update LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                             err_type, err_value);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

     if (fs_obj_cnt > 0 && !pce->pc_pce.pce_flowspec_capability) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot update LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot update LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_NSO,
                                 PCEP_ERR_VAL_OBJECT_CLASS);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    ret = pccd_core_parse_path_attribute(conn, rpd_lsp, info, objs, count, srp_id,
                                         intended_attrs, plsp_id);
    if (ret < 0) {
	pccd_core_rpd_extctrl_lcs_info_cleanup(info, 0, 0);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    *handled_objs += ret;
    count -= ret;

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 * pccd_core_multipath_parse_path_attr_and_ero
 *
 * Process the incoming PCUpdate message and save the path attributes
 * and multi-ero information in the rpd_extctrl_lsp_config_status_info_t
 * structure
 *
 * @param[in] pce:   : PCE who had send this message.
 *            rpd_lsp: Structure where multiero and path attributes are saved
 *            info   : Structure where multiero and path attributes are saved
 *            objs   : PCEP object array
 *            count  : Current index location in object array
 *            srp_id  : SRP identifier
 *            is_empty_ero : ero availability
 *            intended_attrs : LSP attributes
 *            plsp_id : plsp_id of the LSP
 *
 * @return  Number of processed objects, if parsing is successful
 *          PCCD_RET_FAIL(-1)    in failure.
 */
static int
pccd_core_multipath_parse_path_attr_and_ero (struct pce_cfg_core                  *pce,
                                             const struct pccd_rpd_lsp_info       *rpd_lsp,
                                             rpd_extctrl_lsp_config_status_info_t *info,
                                             const struct pcep_object             *objs,
                                             size_t                                count,
                                             uint32_t                              srp_id,
                                             bool                                 *is_empty_ero,
                                             lsp_intended_attr_t                  *intended_attrs,
                                             uint32_t                              plsp_id)
{
    uint32_t              pa_count = 0, ero_count = 0, fs_obj_start = 0, k = 0;
    struct pcep_object   *ero_obj_list[128], *pa_obj_list[128];
    bool                  pa_present = false;
    int                   ero_entries_count = 0, objs_handled = 0;
    struct pcep_obj_ero  *ero = NULL;
    struct lsp_vector    *lsp_vec = NULL;
    int                   fs_obj_cnt = 0, ret = 0;;
    uint8_t               err_type = 0, err_value = 0;

    TRACE_FUNCTION_ENTRY();
    while (objs->type == PCEP_OBJ_PATH_ATTRIBUTE) {
        pa_present = true;
        pa_obj_list[pa_count] = (struct pcep_object *) objs;
        pa_count++;
        objs++;
        if (objs->type != PCEP_OBJ_ERO) {
            TRACE_CORE(" ERO Object is not found after PATH-ATTRIBUTE object");
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        ero_obj_list[ero_count] = (struct pcep_object *) objs;
        ero_count++;
        objs++;
    }
    if (!pa_present) {
        if (objs->type != PCEP_OBJ_ERO) {
            TRACE_CORE(" ERO Object is not found in PCUpd message");
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        ero_obj_list[ero_count] = (struct pcep_object *) objs;
        ero_count++;
        objs++;
    }
    if (ero_count > PCCD_PLATFORM_MAX_ERO_COUNT) {
        TRACE_CORE(" Received %d number of EROs. The current platform limit is %d. "
                   "Sending PCErr to the PCE",
                   ero_count, PCCD_PLATFORM_MAX_ERO_COUNT);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_PCCREATE,
                                 PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
#if 0
    if (ero_count > rpd_lsp->max_segment_list) {
        TRACE_CORE(" Received %u number of EROs. The maximum segment list for the lsp %s is %u. "
                   "Sending PCErr to the PCE", ero_count, rpd_lsp->lsp_name,
                   rpd_lsp->max_segment_list);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_PCCREATE,
                                 PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
#endif
    TRACE_CORE(" PCUpd message - Path Attribute obj processing - Total path attributes %d "
               "Total ero count %d", pa_count, ero_count);
    if (ero_count>1) {
        for (k = 0; k < ero_count; k++) {
            ero_entries_count += ero_obj_list[k]->u.ero.subcount;
            ero_obj_list[k]->u.ero.path_attribs.path_id = pa_obj_list[k]->u.path_attr.path_id;
            ero_obj_list[k]->u.ero.path_attribs.weight = pa_obj_list[k]->u.path_attr.weight;
        }
    } else {
        ero_entries_count += ero_obj_list[0]->u.ero.subcount;
        ero_obj_list[0]->u.ero.path_attribs.path_id = 0;
        ero_obj_list[0]->u.ero.path_attribs.weight = 1;
    }
    info->srte_ero_info = xmalloc(((ero_count) * sizeof(rpd_sr_ero_list_t)) +
                                  ((ero_entries_count) * sizeof(rpd_sr_ero_t)));
    for (k = 0; k < ero_count; k++) {
        if (ero_obj_list[k]->type == PCEP_OBJ_ERO) {
            ero = &ero_obj_list[k]->u.ero;
            if (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
                if (PCCD_RET_SUCCESS != pccd_core_parse_spring_ero(pce->pc_conn,
                                                                   info, ero, srp_id, is_empty_ero)){
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
            } else if (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
                if (PCCD_RET_SUCCESS != pccd_core_parse_spring_v6_ero(pce->pc_conn,
                                                                      info, ero, srp_id, is_empty_ero)) {
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
            }
        } else {
            TRACE_CORE(" Invalid pcep obj type");
        }
    }
    objs_handled = objs_handled + ero_count + pa_count;
    count -= objs_handled;
    TRACE_CORE(" Parse path attributes - objs handled %u obj count %u",
               objs_handled, count);
    
    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(plsp_id);
    if (!lsp_vec) {
        TRACE_CORE(" Unexpected behaviour, lsp vector not found for plsp id:%u", plsp_id);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    fs_obj_cnt = pccd_core_pcupdate_validate_fs_obj(pce, lsp_vec, objs, count,
                                                    &fs_obj_start, &err_type, &err_value);
    if (fs_obj_cnt < 0) {
        pccd_send_error_with_srp(pce->pc_conn, srp_id, err_type, err_value);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    if (fs_obj_cnt > 0 && !pce->pc_pce.pce_flowspec_capability) {
        pccd_send_error_with_srp(pce->pc_conn, srp_id, PCEP_ERR_TYPE_NSO,
                                 PCEP_ERR_VAL_OBJECT_CLASS);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    ret = pccd_core_parse_path_attribute(pce->pc_conn, rpd_lsp, info, objs, count, srp_id,
                                         intended_attrs, plsp_id);
    if (ret < 0) {
        TRACE_CORE(" Failed to parse path attributes in PCUpd message");
        pccd_core_rpd_extctrl_lcs_info_cleanup(info, 0, 0);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    objs_handled += ret;
    count -= ret;
    TRACE_CORE(" parse multipath attribs - objs handled:%u pending objects:%u",
               objs_handled, count);
    TRACE_FUNCTION_RETURN(objs_handled);
}

/**
 * Take parameters from objects from incoming PCUpdate msg and fill
 * rpd_extctrl_lsp_config_status_info_t with them.
 * @param conn
 * @param info
 * @param objs
 * @param count
 * @param srp_id
 * @param[out] is_empty_ero
 *  indicate to the caller why the function failed.
 * @return
 */
static int
pccd_core_update_lsp_params (struct pce_cfg_core *pce,
                             const struct pccd_rpd_lsp_info *rpd_lsp,
                             rpd_extctrl_lsp_config_status_info_t *info,
                             const struct pcep_object *objs, size_t count,
                             uint32_t srp_id, bool *is_empty_ero,
                             lsp_intended_attr_t *intended_attrs,
                             uint32_t plsp_id)
{
    int objs_handled = 0;
    u_int16_t p_num_assoc_info = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(info != NULL);
    INSIST_ERR(objs != NULL);
    INSIST_ERR(count != 0);

    /* The first object must point to start of Update Request, which
     * is LSP object */
    INSIST_ERR(objs->type == PCEP_OBJ_LSP);

    /* If there are more objects in the message, check whether next message is
     * related to this LSP, and parse it. If there is also backup
     * path(s), parse it/them too. */
    count--;
    objs++;
    TRACE_CORE("count:%d", objs_handled);

    if (count > 0) {
        objs_handled = pccd_core_parse_association_list(pce->pc_conn, rpd_lsp, info, objs, count,
                                        srp_id);
        if (objs_handled == PCCD_RET_FAIL){
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

         TRACE_CORE("Handled %d objects for assoc list", objs_handled);
         INSIST_ERR((unsigned) objs_handled <= count);
         count -= objs_handled;
         objs += objs_handled;
     }

    objs_handled = 0;
    if (multipath_enabled && 
        ((rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
         (rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {
         return pccd_core_multipath_parse_path_attr_and_ero(
                                                        pce, rpd_lsp, info, objs, count, srp_id,
                                                        is_empty_ero, intended_attrs, plsp_id);
    } else {
        if (objs->type == PCEP_OBJ_PATH_ATTRIBUTE) {
            TRACE_CORE("Multipath Capability is disabled. Received path attributes in the PCUpdate message. "
                       "Sending PCErr to the PCE");
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_CNS,
                                     PCEP_ERR_VAL_GENERIC);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }
    if (objs->type != PCEP_OBJ_ERO) {
        LOGGING_ERR("Received invalid PCUpd message from pce '%s'. ERO "
                    "is not present", pce->pc_pce.pce_id);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_MOM,
                                 PCEP_ERR_VAL_ERO_MISSING);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    if ((count > 0) && (objs->type == PCEP_OBJ_ERO)) {
        if (PCCD_RET_SUCCESS != pccd_core_handle_path(pce, rpd_lsp, info, objs, count,
                                       srp_id, &objs_handled, is_empty_ero,
                                       intended_attrs, plsp_id)) {
            TRACE_FUNCTION_RETURN(-1);
        }
        INSIST_ERR(objs_handled >= 0);

        TRACE_CORE("Handled %d objects for path", objs_handled);
        INSIST_ERR((unsigned) objs_handled <= count);
        count -= objs_handled;
        objs += objs_handled;
    }

    TRACE_FUNCTION_RETURN(objs_handled + p_num_assoc_info);
}

static void
pccd_core_fill_deleted_lsp (struct pcep_obj_lsp *lsp,
                            uint32_t lsp_id, bool pce_created,
                            const char symbolic_name[MAX_SYMB_NAME_SIZE],
                            bool p2mp_lsp, bool is_ipv6_endpoints)
{
    uint16_t rsvp_lsp_id = 0;
    uint16_t rsvp_tunnel_id = 0;
    uint32_t srcaddr = 0;
    uint32_t extended_tunnel_id = 0;
    uint32_t dstaddr = 0;

    INSIST_ERR(lsp != NULL);

    lsp->remove = true;
    lsp->plsp_id = lsp_id;
    lsp->delegated = false;
    lsp->pce_created = pce_created;
    lsp->p2mp_branch = p2mp_lsp;
    strncpy(lsp->symbolic_name, symbolic_name, sizeof(lsp->symbolic_name));
    lsp->symbolic_name[sizeof(lsp->symbolic_name) - 1] = '\0';


    rsvp_lsp_id = htons(0);
    rsvp_tunnel_id = htons(0);

    if (!is_ipv6_endpoints) {
        lsp->lsp_identifiers_len = 16; /* IPV4-LSP-IDENTIFIERS TLV length */
        memcpy(lsp->lsp_identifiers,     &srcaddr, sizeof(uint32_t));
        memcpy(lsp->lsp_identifiers + 4, &rsvp_lsp_id, sizeof(uint16_t));
        memcpy(lsp->lsp_identifiers + 6, &rsvp_tunnel_id, sizeof(uint16_t));
        memcpy(lsp->lsp_identifiers + 8, &extended_tunnel_id, sizeof(uint32_t));
        memcpy(lsp->lsp_identifiers + 12, &dstaddr, sizeof(uint32_t));
    } else {
        lsp->lsp_identifiers_len = 52; /* IPV6-LSP-IDENTIFIERS TLV length */
        memset(lsp->lsp_identifiers,     0, 16);
        memset(lsp->lsp_identifiers + 16, 0, sizeof(uint16_t));
        memset(lsp->lsp_identifiers + 18, 0, sizeof(uint16_t));
        memset(lsp->lsp_identifiers + 20, 0, 16);
        memset(lsp->lsp_identifiers + 36, 0, 16);
    }
}

static int
pccd_core_report_deleted_p2mp_lsp (struct pce_cfg_core *pce,
                                   const struct pccd_p2mp_lsp_info *p2mp_lsp,
                                   uint32_t srp_id)
{
    struct pcep_object obj[4];
    struct pcep_obj_srp *srp = NULL;
    struct pcep_obj_lsp *lsp = NULL;
    struct pcep_obj_p2mp_endpoints_ipv4 *ep = NULL;
    struct pcep_obj_s2ls *s2ls = NULL;
    uint32_t obj_index = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    INSIST_ERR(p2mp_lsp != NULL);

    memset(&obj, 0, sizeof(obj));

    srp = &obj[obj_index].u.srp;
    obj[obj_index].type = PCEP_OBJ_SRP;
    srp->srp_id = srp_id;
    srp->remove = true;

    lsp = &obj[++obj_index].u.lsp;
    obj[obj_index].type = PCEP_OBJ_LSP;
    pccd_core_fill_deleted_lsp(lsp, p2mp_lsp->plsp_id,
                               p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED,
                               p2mp_lsp->p2mp_name, true, false);

    ep = &obj[++obj_index].u.p2mp_endpoints_ipv4;
    obj[obj_index].type = PCEP_OBJ_P2MP_ENDPOINTS_IPV4;
    ep->leaftype = OLD_LEAVE_MUST_UNCHAGED;

    s2ls = &obj[++obj_index].u.s2ls;
    obj[obj_index].type = PCEP_OBJ_S2LS_VAL;
    s2ls->lsp_oper_state = lsp_oper_down;

    if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, obj, ++obj_index)) {
        LOGGING_ERR("Could not send PCRpt message to pce '%s'",
                    pce->pc_pce.pce_id);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

int
pccd_core_report_deleted_lsp (struct pce_cfg_core *pce,
                              const struct pccd_rpd_lsp_info *rpd_lsp,
                              uint32_t srp_id)
{
    struct pcep_object obj[3];
    struct pcep_obj_srp *srp = NULL;
    struct pcep_obj_lsp *lsp = NULL;
    struct pcep_obj_ero *ero = NULL;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    uint32_t obj_index = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    INSIST_ERR(rpd_lsp != NULL);

    memset(&obj, 0, sizeof(obj));

    srp = &obj[obj_index].u.srp;
    obj[obj_index].type = PCEP_OBJ_SRP;
    srp->srp_id = srp_id;
    srp->remove = true;

    if(RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == rpd_lsp->setup_type) {
        srp->lsp_setup_type = srv6_pst_type;
    } else {
        srp->lsp_setup_type = rpd_lsp->setup_type;
    }

    lsp = &obj[++obj_index].u.lsp;
    obj[obj_index].type = PCEP_OBJ_LSP;

	pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
		rpd_lsp->lsp_name, rpd_lsp->path_name);

    pccd_core_fill_deleted_lsp(lsp, rpd_lsp->id,
                               rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED,
                               lsp_full_name,
                               ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) == LSP_PATH_TYPE_P2MP),
                               rpd_lsp->is_lsp_src_dst_addr_type_ipv6);

    /* ERO is mandatory in PCRpt, even in case of deleted lsp*/
    ero = &obj[++obj_index].u.ero;
    obj[obj_index].type = PCEP_OBJ_ERO;
    if (pccd_core_fill_ero(ero, rpd_lsp, 0) < 0)
    {
        LOGGING_ERR("Could not create ERO object for PCRpt message for deleted lsp");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    if (pccd_core_send_message(pce, PCEP_MSG_PC_REPORT, obj, ++obj_index)) {
        LOGGING_ERR("Could not send PCRpt message to pce '%s'",
                    pce->pc_pce.pce_id);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static bool
pccd_core_get_p2mp_branch_name (rpd_extctrl_lsp_config_status_info_t *info, char *name)
{
    struct in_addr dst_addr;
    char p2mp_name[49];
    
    memset(p2mp_name, '\0', sizeof(p2mp_name));
    dst_addr.s_addr = (in_addr_t) info->dstaddr_u.v4;

    if (!pccd_core_validate_p2mp_symbolic_name(info->p2mp_name, p2mp_name)) {
        TRACE_CORE("P2mp name validation failed, name %s size %d",
            info->p2mp_name, strlen(info->p2mp_name));
        return false;
    }

    bzero(name, (RPD_LSP_NAME_SIZE +1));
    snprintf(name, RPD_LSP_NAME_SIZE+1, "%s_%s", p2mp_name, inet_ntoa(dst_addr));
    return true;
}

static int
pccd_core_report_deleted_p2mp_branch(struct pce_cfg_core *pce,
                                    const struct pcep_obj_p2mp_endpoints_ipv4 *endpoints,
                                    uint32_t srp_id, struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    daemon_trace_file_options_t *dtfo = NULL;
    char name_rec[RPD_LSP_NAME_SIZE +1];
    rpd_extctrl_lsp_config_status_info_t info;
    u_int32_t subcount = 0;
    unsigned loop = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    INSIST_ERR(p2mp_lsp != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));

    subcount = endpoints->subcount;
    snprintf(info.p2mp_name, sizeof(info.p2mp_name), "%s", p2mp_lsp->p2mp_name);

    for (loop = 0; loop < subcount; loop++) {
        const struct pccd_rpd_lsp_info *rpd_lsp = NULL;

        info.dstaddr_u.v4 = (u_int32_t)endpoints->destinations[loop].s_addr;

        if(!pccd_core_get_p2mp_branch_name(&info, name_rec)) {
             /* Fixme : get proper error for this scenario */
             pccd_send_error_with_srp(pce->pc_conn, srp_id,
                 PCEP_ERR_TYPE_RIP, PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);
             continue;
         }

        /* Check if LSP with this name doesn't exist */
        rpd_lsp = pccd_rpd_get_specific_lsp(name_rec, SETUP_TYPE_RSVP, RSVP_P2MP_LEAF);
        if (rpd_lsp) {
            /* Succesfully deleted */
            /* Report deleted LSP to other PCEs */
            struct pce_cfg_core *pce_tmp = NULL;
            struct pce_cfg_core *temp = NULL;
            SLIST_FOREACH_SAFE(pce_tmp, &pce_cfg_head, pc_next, temp) {
                if (PCE_IS_STATEFUL(pce_tmp)) {
                    if (pce_tmp->pc_state > PCE_STATE_CONNECTED) {
                        pccd_core_report_lsp(pce_tmp, rpd_lsp, true,
                                             pce_tmp->pc_state >= PCE_STATE_SYNC,
                                             (pce == pce_tmp) ? srp_id : SRP_ID_RESV1,
                                             OLD_LEAVES_TO_REMOVE,
                                             (pce == pce_tmp) ? (loop != (subcount -1)) : false);
                        } else {
                        TRACE_PCEP(dtfo, "PCE '%s' is currently in state %s, can't send"
                                   " PCRpt messages", pce_tmp->pc_pce.pce_id,
                                   pccd_core_get_pce_state_str(pce_tmp->pc_state));
                    }
                }
            }

            pccd_core_provisioned_lsps_decrease_counter();
        }
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static int
pccd_core_report_deleted_provisioned_lsp (struct pce_cfg_core *pce,
                                          struct lsp_vector *lsp_vec,
                                          const struct pccd_rpd_lsp_info *rpd_lsp)
{
    daemon_trace_file_options_t *dtfo = NULL;
    struct pce_cfg_core *pce_tmp = NULL;
    struct pce_cfg_core *temp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    INSIST_ERR(lsp_vec != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    SLIST_FOREACH_SAFE(pce_tmp, &pce_cfg_head, pc_next, temp) {
        if (pce_tmp != pce) {
            if (PCE_IS_STATEFUL(pce_tmp)) {
                if (pce_tmp->pc_state > PCE_STATE_CONNECTED) {
                    pccd_core_report_deleted_lsp(pce_tmp, rpd_lsp, SRP_ID_RESV1);
                } else {
                    TRACE_PCEP(dtfo, "PCE '%s' is currently in state %s, can't send"
                               " PCRpt messages", pce_tmp->pc_pce.pce_id,
                               pccd_core_get_pce_state_str(pce_tmp->pc_state));
                }
            }
        }
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 *@brief
 * Handle the case where a message from controller had empty-ero. today
 * this function is called only for pcupdate message.
 *
 * On the receiption of emtpy-ero, based on the configured empty-ero-action
 * parameters, we will either send error or ask rpd/tag to tear down the
 * path or let RPD decide the course of action(i.e local cspf or IGP path).
 * In send-err config, we are sending the same error (6.9) that is used to
 * indicate the absence of ERO object itself. This is because 1. the scenario
 * of empty-ero is undefined in draft and hence we choose to do this way, 2.
 * and to be backward compatible with earlier junos version.
 *
 *@param[in] pce
 * pce config object
 *@param[in] info
 * the info object which stores all the information by parsing the message
 *@param[in] srp_id
 * srp id of the lsp
 *
 *@return none
 */
static void
pccd_core_rx_empty_ero (struct pccd_rpd_lsp_info *rpd_lsp,
                        struct pce_cfg_core* pce,
                        rpd_extctrl_lsp_config_status_info_t* info,
                        uint32_t srp_id, bool is_p2mp_upd)
{
    struct pcep_conn *conn = pce->pc_conn;

    TRACE_FUNCTION_ENTRY();

    TRACE_CORE("lsp(%s/%s) with empty ero, determining the action", info->name,
               info->path_name);

    if (RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE == info->lsp_type_info.setup_type) {
	if ((TRUE == is_p2mp_upd) || (TRUE == pce->pc_pce.pce_opts.pco_empty_ero_send_err)) {
	    TRACE_CORE("        send err");
	    pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_MOM,
                                     PCEP_ERR_VAL_ERO_MISSING);
	    pce->pc_statistics.pcupdate_action_stats.ppeeas_send_err++;
	} else if (TRUE == pce->pc_pce.pce_opts.pco_empty_ero_path_tear_down) {
	    TRACE_CORE("        tear down lsp");
	    pccd_rpd_rsvp_tear_down_lsp(info->name, info->path_name, info->type, rpd_lsp->context);
	    pce->pc_statistics.pcupdate_action_stats.ppeeas_tear_down_path++;
	} else {
	    TRACE_CORE("        by default let RPD take action");
	    if (!pccd_rpd_pcupdate(rpd_lsp, info)) {
		pce->pc_statistics.pcupdate_action_stats.ppeeas_routing_decision_failed++;
		TRACE_CORE("	could not send PCUpdate to RPD");
	    } else {
		pce->pc_statistics.pcupdate_action_stats.ppeeas_routing_decision++;
	    }
	}
    }  else  if (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == info->lsp_type_info.setup_type) {
        if (!pccd_rpd_pcupdate(rpd_lsp, info)) {
            pce->pc_statistics.pcupdate_action_stats.ppeeas_routing_decision_failed++;
            TRACE_CORE("	could not send PCUpdate to RPD");
        }
    } else {
	TRACE_CORE("        BYPASS LSP - empty-ero is not expected, send err");
	pccd_send_error_with_srp(conn, srp_id,
                                 PCEP_ERR_TYPE_MOM,
                                 PCEP_ERR_VAL_ERO_MISSING);
	pce->pc_statistics.pcupdate_action_stats.ppeeas_send_err++;
    }

    TRACE_FUNCTION_RETURN();
}

static void
pccd_core_p2mp_frag_inst_timer_cb(evContext ctx UNUSED, void *uap,
                                    struct timespec due UNUSED,
                                    struct timespec inter UNUSED)
{
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    struct lsp_vector *lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    p2mp_lsp = uap;
    /* Clear lsp fragmentation timer */
    if (evTestID(p2mp_lsp->msg_fragment_tid)) {
        evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
        evInitID(&p2mp_lsp->msg_fragment_tid);
    }

    lsp = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
    if (lsp) {
        // send error to pce
        TRACE_CORE("Could not receive all fragmented Instantiation message in bound duration");
        pccd_send_error_with_srp(lsp->lv_pce->pc_conn, lsp->srp_id,
                                 PCEP_ERR_TYPE_P2MP_FRAG,
                                 PCEP_ERR_VAL_FRAGMENTED_INST);

        if (evTestID(lsp->lv_lsp_cleanup_tid)) {
            struct pccd_rpd_lsp_info *rpd_lsp= NULL;
            struct pccd_rpd_lsp_info *tmp_lsp = NULL;
            SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
                rpd_lsp->is_orphan = true;
            }
        } else {
            struct pccd_rpd_lsp_info *rpd_lsp= NULL;
            struct pccd_rpd_lsp_info *tmp = NULL;
            SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
                if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                    /* Succesfully deleted */
                    TRACE_CORE("LSP with lsp_name '%s' path_name '%s' is deleted from RPD",
                    rpd_lsp->lsp_name, rpd_lsp->path_name);
                    pccd_core_provisioned_lsps_decrease_counter();
                } else {
                    /* Error deleting created LSP */
                    LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
                    rpd_lsp->lsp_name, rpd_lsp->path_name);
                }
            }

            /* Report deleted LSP to other PCEs */
            pccd_core_report_deleted_provisioned_p2mp_lsp(lsp->lv_pce, lsp, p2mp_lsp);

            /* Report deleted LSP to the provisioning LSP. Reflect
             * SRP */
            pccd_core_report_deleted_p2mp_lsp(lsp->lv_pce, p2mp_lsp, SRP_ID_RESV1);
        }
    }

    TRACE_FUNCTION_EXIT();
}

static void
pccd_core_p2mp_frag_upd_timer_cb (evContext ctx UNUSED, void *uap,
                                  struct timespec due UNUSED,
                                  struct timespec inter UNUSED)
{
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    struct lsp_vector *lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(uap != NULL);

    p2mp_lsp = uap;
    /* Clear lsp fragmentation timer */
    if (evTestID(p2mp_lsp->msg_fragment_tid)) {
        evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
        evInitID(&p2mp_lsp->msg_fragment_tid);
    }

    lsp = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
    if (lsp) {
        // send error to pce
        TRACE_CORE("Could not receive all fragmented update message in bound duration");
        pccd_send_error_with_srp(lsp->lv_pce->pc_conn, lsp->srp_id,
                                 PCEP_ERR_TYPE_P2MP_FRAG,
                                 PCEP_ERR_VAL_FRAGMENTED_UPDATE);
    }

    /*
     * Mark the p2mp no mbb needed and clear all
     * update info
     */
    pccd_rpd_clear_p2mp_pcupdate_params(p2mp_lsp);

    TRACE_FUNCTION_EXIT();
}

static void
pccd_core_store_p2mp_attrib (rpd_extctrl_lsp_config_status_info_t *lcs_info,
                             struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    p2mp_lsp->setup_prio = lcs_info->setup_prio;
    p2mp_lsp->hold_prio = lcs_info->hold_prio;
    p2mp_lsp->bandwidth = lcs_info->bandwidth;
    p2mp_lsp->admin_grp_exclude_any = lcs_info->relcsi_admin_grp_exclude_any;
    p2mp_lsp->admin_grp_include_all = lcs_info->relcsi_admin_grp_include_all;
    p2mp_lsp->admin_grp_include_any = lcs_info->relcsi_admin_grp_include_any;
}

static bool
pccd_core_compare_p2mp_attrib (rpd_extctrl_lsp_config_status_info_t *lcs_info,
                               struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    if (p2mp_lsp->setup_prio != lcs_info->setup_prio) { return false; }

    if (p2mp_lsp->hold_prio != lcs_info->hold_prio) { return false; }

    if (p2mp_lsp->bandwidth != lcs_info->bandwidth) { return false; }

    if (p2mp_lsp->admin_grp_exclude_any != lcs_info->relcsi_admin_grp_exclude_any) { return false; }

    if (p2mp_lsp->admin_grp_include_all != lcs_info->relcsi_admin_grp_include_all) { return false; }

    if (p2mp_lsp->admin_grp_include_any != lcs_info->relcsi_admin_grp_include_any) { return false; }

    return true;
}

bool
pccd_core_validate_p2mp_symbolic_name (char *received_name, char* p2mp_name)
{
    char *lsp_name = NULL;
    char *cp = NULL;
    bool name_valid = true;
    u_int32_t size= 0;

    cp = strdup(received_name);
    lsp_name = strtok(cp,"/");

    size = strlen(lsp_name);

    if (size > (RPD_LSP_NAME_SIZE - 16)) {
        name_valid = false;
    } else {
        memcpy (p2mp_name, lsp_name, size);
    }

    /*Free the memory allocated by strdup*/
    free (cp);
    return name_valid;
}

/*
 * Copy recevied intended attributes into our local struct
 */
void
pccd_core_copy_intended_attributes (struct lsp_intended_attr_s *intended_attrs,
                                    const struct pccd_rpd_lsp_info *rpd_lsp)
{
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    const pccd_rpd_name_tree_key *name_tree_key = NULL;
    struct pccd_rpd_lsp_info *lsp = NULL;
    struct lsp_metric_s *metric_itr = NULL;
    
    if (!rpd_lsp) {
        return;
    }

    name_tree_key = &rpd_lsp->name_tree_key;
    if (!name_tree_key) {
        return;
    }

	pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
		rpd_lsp->lsp_name, rpd_lsp->path_name);

    /* This is required to remove const of *rpd_lsp */
    lsp = pccd_rpd_get_specific_lsp(lsp_full_name, 
          name_tree_key->type, name_tree_key->sub_type);
    if (!lsp) {
        return;
    }

    pccd_rpd_free_intended_metric(lsp);
    pccd_rpd_free_actual_metric(lsp);

    if(!intended_attrs) {
        return;
    }

    /* Copy the metric object flags *
    memcpy(&lsp->intended_attrs, intended_attrs, sizeof(lsp_intended_attr_t));*/

    lsp->intended_attrs.bw = intended_attrs->bw;
    lsp->intended_attrs.bw_valid = intended_attrs->bw_valid;

    while (!SLIST_EMPTY(&intended_attrs->intended_metric_head)) {
        metric_itr = SLIST_FIRST(&intended_attrs->intended_metric_head);
        SLIST_REMOVE(&intended_attrs->intended_metric_head, metric_itr,
                lsp_metric_s, metric_next);

        if (0 == metric_itr->metric_info.computed_flag) {
            //Add metric in intended metric list
            SLIST_INSERT_HEAD(&lsp->intended_attrs.intended_metric_head, metric_itr, metric_next);
        } else {
            //Add metric in actual metric list
            SLIST_INSERT_HEAD(&lsp->actual_metric_head, metric_itr, metric_next);
        }
    }
}

/*
 * Check if PCE proposed ERO is different from the local cache
 * This is for RSVP p2p/p2mp LSP
 */
static bool
pccd_core_is_ero_changed(const RouteObj *ero_update,
		const RouteObj *ero_local)
{
    uint16_t ero_len = 0;

    TRACE_FUNCTION_ENTRY();

    if (!ero_update && !ero_local)
        TRACE_FUNCTION_RETURN(false);

    if ((!ero_update && ero_local) || (ero_update && !ero_local))
        TRACE_FUNCTION_RETURN(true);

	/*
	 * Compare header
	 */
    if (ero_update->hdr.obj_length != ero_local->hdr.obj_length) {
    	TRACE_CORE("ERO header mismatch");
    	TRACE_FUNCTION_RETURN(true);
    }

    ero_len = ntohs(ero_update->hdr.obj_length) - sizeof(OBJ_HDR);
    if (memcmp(ero_update->entry, ero_local->entry, ero_len)) {
    	TRACE_CORE("ERO body doesn't match");
    	TRACE_FUNCTION_RETURN(true);
    }

    TRACE_FUNCTION_RETURN(false);
}

static int
pccd_core_received_p2mp_pcupdate (struct pce_cfg_core *pce,
                                  const struct pcep_object *objs,
                                  size_t count, uint32_t *p2mp_objs_handled)
{
    uint8_t lsp_setup_type = 0;
    uint32_t srp_id = 0;
    int fs_obj_cnt = 0;
    uint32_t fs_obj_start = 0;
    int ret_attr, arg_count, objs_index;
    bool fragmented = false;
    bool trig_mbb = false;
    unsigned i = 0;
    
    struct pcep_conn *conn = NULL;
    daemon_trace_file_options_t *dtfo = NULL;
    lsp_intended_attr_t intended_attrs;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    struct lsp_vector *lsp = NULL;
    rpd_extctrl_lsp_config_status_info_t info;

    u_int32_t endpoint_obj_count = 0;
    u_int32_t ero_count = 0;
    u_int32_t endpoint_count = 0;    
    unsigned loop = 0;
    
    char name_rec[RPD_LSP_NAME_SIZE +1];
    uint8_t err_type = 0;
    uint8_t err_value = 0;

    rpd_extctrl_lsp_config_status_info_t *lcs_info = NULL;
    u_int32_t j = 0;
    u_int32_t lcs_count = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);
    conn = pce->pc_conn;
    dtfo = pccd_core_pce_get_traceoptions(pce);


    srp_id = objs[i].u.srp.srp_id;
    lsp_setup_type = objs[i].u.srp.lsp_setup_type;

    i++; // Move to LSP object

    p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(objs[i].u.lsp.plsp_id);
    if (!p2mp_lsp) {
        const struct pccd_rpd_lsp_info *rpd_lsp = 
            pccd_rpd_get_lsp_by_id(objs[i].u.lsp.plsp_id);
        if (rpd_lsp) {
            LOGGING_ERR("PCE is trying to update LSP ID: %d, which is not "
                "externally controlled", objs[i].u.lsp.plsp_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP);
        } else {
            LOGGING_ERR("PCE is trying to update unknown LSP ID: %d",
                        objs[i].u.lsp.plsp_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
        }
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    /* If the LSP from RPD is set as locally(CLI) controlled, or its
     * current control state is local control, do not allow PCE to modify
     * its parameters */
    if (!(((p2mp_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED) ||
            (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED)) &&
            p2mp_lsp->control_status == LSP_EXTERNALLY_CONTROLLED)) {
        LOGGING_ERR("PCE is trying to update LSP ID: %d, which is not "
                "externally controlled", p2mp_lsp->plsp_id);
        if (pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
            pccd_core_set_new_main_pce_timer(pce);
            pccd_core_pce_disconnect(pce);
            pccd_core_pce_schedule_reconnect(pce);
        }
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    lsp = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);

    if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED ||
        p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
        if (lsp && (lsp->lv_pce != pce)) {
            /* PCE is trying to update LSP which owns another PCE */
            TRACE_PCEP(dtfo, "PCE '%s' is trying to update LSP '%s' which owns PCE '%s'",
                       pce->pc_pce.pce_id, p2mp_lsp->p2mp_name,
                       lsp->lv_pce ? lsp->lv_pce->pc_pce.pce_id : "NULL");
            if (pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_INVALID_OPERATION,
                                         PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
                pccd_core_set_new_main_pce_timer(pce);
                pccd_core_pce_disconnect(pce);
                pccd_core_pce_schedule_reconnect(pce);
            }
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }

    /* retrieve our internal lsp object */
    if (lsp == NULL) {
        LOGGING_ERR("Could not retrieve LSP in internal list");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    if ((SRP_ID_RESV1 != p2mp_lsp->mbb_id) && (srp_id != p2mp_lsp->mbb_id)) {
        TRACE_PCEP(dtfo, "SRP ID do not match in fragmented packets, trigger new mbb in rpd");
        trig_mbb = true;
        /* reset mbb id */
        p2mp_lsp->mbb_id = SRP_ID_RESV1;
    }

    lsp->lv_ack_delegated = objs[i].u.lsp.delegated;
    lsp->srp_id = srp_id;

    /* Returning delegation of provisioned LSP */
    if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED &&
        (objs[i].u.lsp.delegated == false)) {
        struct pccd_rpd_lsp_info *rpd_lsp= NULL;
        struct pccd_rpd_lsp_info *tmp = NULL;
        struct pccd_rpd_lsp_info *last = NULL;

        TRACE_PCEP(dtfo, "PCE returning delegation if PCE provisoned '%s'", p2mp_lsp->p2mp_name);
        lsp->lv_ack_delegated = false;
        lsp->lv_want_to_delegate = false;

        SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
            if (NULL == last) {
                last = rpd_lsp;
                continue;
            }
            
            if (pccd_core_report_lsp(pce, rpd_lsp, true,
                                     pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                     OLD_LEAVE_MUST_UNCHAGED, true)) {
                LOGGING_ERR("Could not send PCRpt to pce '%s'",
                             pce->pc_pce.pce_id);
                TRACE_FUNCTION_RETURN(-1);
            }
        }

        if (last) {
            if (pccd_core_report_lsp(pce, last, true,
                                     pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                     OLD_LEAVE_MUST_UNCHAGED, false)) {
                LOGGING_ERR("Could not send PCRpt to pce '%s'",
                             pce->pc_pce.pce_id);
                TRACE_FUNCTION_RETURN(-1);
            }
        }
        
        /* Start lsp cleanup timer. Default value is 60 seconds */
        if (!evTestID(lsp->lv_lsp_cleanup_tid)) {
            /* NSR Begin */
            pccd_core_start_lsp_cleanup_tid(pce, lsp);
            /* NSR End */
            /* set orphan flag in all branches */
            SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
                rpd_lsp->is_orphan = true;
            }                        
        }
        
        *p2mp_objs_handled = i;
        TRACE_FUNCTION_RETURN(0);
    }

    memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));

    memset(&intended_attrs, 0, sizeof(lsp_intended_attr_t));

    info.path_flags |= LSP_PATH_TYPE_P2MP;
    if (true == objs[i].u.lsp.fragment) {
        /* start fragmentation timer when first time fragmented msg received */
        fragmented = true;
        if (!evTestID(p2mp_lsp->msg_fragment_tid)) {
            if (evSetTimer(pccd_core_ev_ctx, pccd_core_p2mp_frag_upd_timer_cb,
                           p2mp_lsp, evAddTime(evNowTime(),
                           evConsTime(120, 0)),
                           evConsTime(0,0), &p2mp_lsp->msg_fragment_tid) == -1) {
                LOGGING_ERR("evSetTimer failed");
                exit(EX_SOFTWARE);
            }
            TRACE_CORE("Fragmentation timer set for LSP '%s' with value %d [s]",
                      p2mp_lsp->p2mp_name, 120);
        }
    } else {
        /* stop the fragmentation timer if running */
        fragmented = false;
        if (evTestID(p2mp_lsp->msg_fragment_tid)) {
            evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
            evInitID(&p2mp_lsp->msg_fragment_tid);
            TRACE_CORE("Stopped Fragmentation timer for P2MP LSP id: %u",
                                        p2mp_lsp->plsp_id);
        }
    }
    snprintf(info.p2mp_name, sizeof(info.p2mp_name), "%s", p2mp_lsp->p2mp_name);

    info.lsp_type_info.setup_type = lsp_setup_type;
    info.type = p2mp_lsp->type;

    i++; //Move to P2mp End Point Object
    loop = i;

    for(; loop < count; loop++) {
        pcep_obj_type_t t = objs[loop].type;
        switch (t) {            
        case PCEP_OBJ_P2MP_ENDPOINTS_IPV4:
            endpoint_obj_count++;
            endpoint_count += objs[loop].u.p2mp_endpoints_ipv4.subcount;
            TRACE_CORE("EP: EPOC %d EPC %d SC %d", 
                endpoint_obj_count, endpoint_count, objs[loop].u.p2mp_endpoints_ipv4.subcount);
            break;
        case PCEP_OBJ_ERO:
            ero_count++;
            TRACE_CORE("ERO: EC %d", ero_count);
            break;
        default:
            TRACE_CORE("OBJ: %d", t);
            break;
        }
    }

    fs_obj_cnt = pccd_core_pcupdate_validate_fs_obj(pce, lsp, &objs[i], (count - i), 
                                      &fs_obj_start, &err_type, &err_value);
    if (fs_obj_cnt < 0) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot create LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                             err_type, err_value);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    
    if (fs_obj_cnt > 0 && !pce->pc_pce.pce_flowspec_capability) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot create LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_NSO,
                                 PCEP_ERR_VAL_OBJECT_CLASS);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    
    fs_obj_start += i; /* Move fs object start to correct index */
    
    arg_count = count - (i + endpoint_obj_count + ero_count);
    objs_index = i + endpoint_obj_count + ero_count;

    ret_attr = pccd_core_parse_path_attribute(conn, NULL, &info, &objs[objs_index],
                     arg_count, srp_id, &intended_attrs, lsp->lv_lsp_id);
    if (ret_attr < 0) {
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    if (SRP_ID_RESV1 != p2mp_lsp->mbb_id) {
        /* validate attributes */
        if (!pccd_core_compare_p2mp_attrib(&info, p2mp_lsp)) {
            TRACE_PCEP(dtfo, "attributes are not matching in consecutive fragmented update msg");
            /* send internal error */
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_PCCREATE,
                                     PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    } else {
        /* store attributes */
        if (!BIT_ISSET(p2mp_lsp->flags, IS_MBB_NEEDED))
            if (!pccd_core_compare_p2mp_attrib(&info, p2mp_lsp))
                BIT_SET(p2mp_lsp->flags, IS_MBB_NEEDED);
        pccd_core_store_p2mp_attrib(&info, p2mp_lsp);
        p2mp_lsp->mbb_id = fragmented ? srp_id : SRP_ID_RESV1;
    }

    lcs_info = xmalloc(sizeof(rpd_extctrl_lsp_config_status_info_t) * endpoint_count);

    memset(lcs_info, 0, (sizeof(rpd_extctrl_lsp_config_status_info_t) * endpoint_count));

    for (j = 0; j < endpoint_obj_count; j++) {
        const struct pcep_object *objs_endpoint = &objs[i];
        LeafType leaftype;
        u_int32_t subcount = 0;

        if (PCEP_OBJ_P2MP_ENDPOINTS_IPV4 != objs_endpoint->type) {
            LOGGING_ERR("Received invalid P2MP PCUpd message from pce '%s'. Fourth "
                        "object is not END-Point", pce->pc_pce.pce_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_MOM,
                                     PCEP_ERR_VAL_EP_MISSING);
            pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);

            // Cleaning memory leaks
            if (info.install_prefix_info) {
                xfree(info.install_prefix_info);
                info.install_prefix_info = NULL;
            }

            free(lcs_info);
            lcs_info = NULL;
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        leaftype =  objs_endpoint->u.p2mp_endpoints_ipv4.leaftype;
        subcount = objs_endpoint->u.p2mp_endpoints_ipv4.subcount;
        info.srcaddr_u.v4 = (u_int32_t)objs_endpoint->u.p2mp_endpoints_ipv4.source.s_addr;
        info.is_lsp_src_dst_addr_type_ipv6 = false;

        i++; // Cross End Point Object, next can be End Point or ERO object based on leaf type
        loop = 0;
        for (loop = 0; loop < subcount; loop++) {
            struct pccd_rpd_lsp_info *rpd_lsp = NULL;

            memcpy(&lcs_info[lcs_count], &info, sizeof(rpd_extctrl_lsp_config_status_info_t));
            lcs_info[lcs_count].dstaddr_u.v4 = (u_int32_t)objs_endpoint->u.p2mp_endpoints_ipv4.destinations[loop].s_addr;

            if(!pccd_core_get_p2mp_branch_name(&lcs_info[lcs_count], name_rec)) {
                /* Fixme : get proper error for this scenario */
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                    PCEP_ERR_TYPE_RIP, PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);
                continue;
            }
            /* Check if LSP with this name doesn't exist in p2mp branch name tree*/
            rpd_lsp = pccd_rpd_get_specific_lsp(name_rec, SETUP_TYPE_RSVP, RSVP_P2MP_LEAF);

            if (rpd_lsp) {
                pccd_core_copy_intended_attributes(&intended_attrs, rpd_lsp);
            }

            switch (leaftype) {
                case OLD_LEAVES_TO_REMOVE:
                {
                    if ((!rpd_lsp) || (rpd_lsp->p2mp_lsp != p2mp_lsp)) {
                        LOGGING_ERR("PCE is trying to delete unknown LSP Name: %s", name_rec);

                        /* Fixme : get proper error for this scenario */
                        pccd_send_error_with_srp(conn, srp_id,
                                                 PCEP_ERR_TYPE_INVALID_OPERATION,
                                                 PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, (endpoint_count - 1));
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }

                    if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                        TRACE_CORE("LSP with lsp_name '%s' path?_name '%s' is deleted from RPD",
							rpd_lsp->lsp_name, rpd_lsp->path_name);
                    } else {
                        /* Error deleting created LSP */
                        LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
                        rpd_lsp->lsp_name, rpd_lsp->path_name);
                    }
                    pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, lcs_count, lcs_count);
                    lcs_count++;

                    if (loop == (subcount - 1)) {
                        /* all branch delete has been processed, send report to controller */
                        pccd_core_report_deleted_p2mp_branch(pce,
                                                             &objs_endpoint->u.p2mp_endpoints_ipv4,
                                                             srp_id, p2mp_lsp);
                    }

                    break;
                }
                case NEW_LEAVES_TO_ADD:
                {
                    /* Check if LSP with this name doesn't exist in all name trees as name is unique 
                    in pcep */
                    char name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE+1)];
                    const struct pccd_rpd_lsp_info *rpd_lsp_created = NULL;
                    const struct pccd_rpd_lsp_info *rpd_lsp_check = 
                        pccd_rpd_get_lsp_by_name(name_rec);

                    if (rpd_lsp_check) {
                        TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - name exists",
                                   pce->pc_pce.pce_id, name_rec);

                        /* Fixme : get proper error for this scenario */
                        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                            PCEP_ERR_TYPE_RIP, PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }

                    /* If there was no ERO for this LSP, send PCErr */
                    if (objs[i].type != PCEP_OBJ_ERO) {
                        TRACE_CORE("%s - ERO object is missing in PCUpd message", name_rec);
                        pccd_send_error_with_srp(conn, srp_id, PCEP_ERR_TYPE_MOM,
                                                 PCEP_ERR_VAL_ERO_MISSING);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }
                    lcs_info[lcs_count].state = LSP_STATE_CREATION_PENDING;

                    if (lcs_info[lcs_count].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
                        if (PCCD_RET_SUCCESS != pccd_core_parse_ero(&lcs_info[lcs_count], &objs[i].u.ero, NULL)) {
                            TRACE_PCEP(dtfo, "LSP(%s/%s) ERO object parsing failed", lcs_info[lcs_count].name,
                                       lcs_info[lcs_count].path_name);
                            pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, lcs_count, lcs_count);
                            i++;
                            lcs_count++;
                            break;
                        }
                    }

                    i++; // ERO object processed

                    /* Check for max provisioning lsps limit */
                    if (pccd_provisioned_lsps.limit > 0) {
                        if (pccd_provisioned_lsps.counter >= pccd_provisioned_lsps.limit) {
                            /* max number of provisioned lsps reached */
                            TRACE_PCEP(dtfo, "Maximum limit Provisioned LSPs reached");
                            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                                     PCEP_ERR_VAL_PCE_EXCEED_RES_LIMIT);
                            pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                            free(lcs_info);
                            lcs_info = NULL;
                            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                        } else {
                            pccd_core_provisioned_lsps_increase_counter();
                        }
                    }

                    TRACE_PCEP(dtfo, "Creating LSP name: '%s'",  name_rec);

                    bzero(lcs_info[lcs_count].name, sizeof(lcs_info[lcs_count].name));
                    bzero(lcs_info[lcs_count].path_name, sizeof(lcs_info[lcs_count].path_name));
                    snprintf(lcs_info[lcs_count].name, sizeof(lcs_info[lcs_count].name), "%s", name_rec);

                    if (trig_mbb) {
                        lcs_info[lcs_count].p2mp_mbb_flag = TAG_EXTCTRL_P2MP_MBB_TRIGGER;
                        trig_mbb = false;
                    }

                    if (!pccd_rpd_pccreate(&lcs_info[lcs_count])) {
                        TRACE_PCEP(dtfo, "Could not send PCCreate to RPD");
                        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                                 PCEP_ERR_TYPE_PCCREATE,
                                                 PCEP_ERR_VAL_INTERNAL_ERROR);

                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }
                    lcs_info[lcs_count].ero_info = NULL;
                    lcs_info[lcs_count].srte_ero_info = NULL;

                    bzero(name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));
                    snprintf(name, sizeof(name), "%s", lcs_info[lcs_count].name);
                    TRACE_RPD("LSP '%s'", name);
   
                    rpd_lsp_created = pccd_rpd_get_specific_lsp(name, SETUP_TYPE_RSVP,
                                      RSVP_P2MP_LEAF);
                    if (!rpd_lsp_created) {
                        LOGGING_ERR("Created LSP '%s' not found in LSP tree", lcs_info[lcs_count].name);

                        /* Fixme : get proper error for this scenario */
                        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                                 PCEP_ERR_TYPE_PCCREATE,
                                                 PCEP_ERR_VAL_INTERNAL_ERROR);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }

                    pccd_core_store_lsp(pce, rpd_lsp_created->id, srp_id,
                                        true, LSP_VECTOR_P2MP_EXTERNALLY_PROV);

                    TRACE_PCEP(dtfo, "PCE: '%s' created provisioned LSP with lsp_name '%s' "
                        "path_name '%s' id: %d", pce->pc_pce.pce_id,
                        rpd_lsp_created->lsp_name, rpd_lsp_created->path_name, rpd_lsp_created->id);

                    lcs_count++;
                    break;
                }
                case OLD_LEAVES_CAN_MODIFIED:
                {
                    bool is_empty_ero = FALSE;
                    bool ero_changed = FALSE;
                    if ((!rpd_lsp) || (rpd_lsp->p2mp_lsp != p2mp_lsp)) {
                        LOGGING_ERR("PCE is trying to update unknown LSP Name: %s", name_rec);

                        /* Fixme : get proper error for this scenario */
                        pccd_send_error_with_srp(conn, srp_id,
                                                 PCEP_ERR_TYPE_INVALID_OPERATION,
                                                 PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }

                    /* If there was no ERO for this LSP, send PCErr */
                    if (objs[i].type != PCEP_OBJ_ERO) {
                        TRACE_CORE("%s - ERO object is missing in PCUpd message", name_rec);
                        pccd_send_error_with_srp(conn, srp_id,
                                                 PCEP_ERR_TYPE_MOM,
                                                 PCEP_ERR_VAL_ERO_MISSING);
                        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                        free(lcs_info);
                        lcs_info = NULL;
                        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                    }

                    strncpy(lcs_info[lcs_count].name, rpd_lsp->lsp_name, sizeof(lcs_info[lcs_count].name));
                    lcs_info[lcs_count].name[sizeof(lcs_info[lcs_count].name) - 1] = '\0';

                    if (lcs_info[lcs_count].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
                        if (PCCD_RET_SUCCESS != pccd_core_parse_ero(&lcs_info[lcs_count], &objs[i].u.ero, &is_empty_ero)) {
                            TRACE_PCEP(dtfo, "LSP(%s/%s) ERO object parsing failed", lcs_info[lcs_count].name,
                                       lcs_info[lcs_count].path_name);
                            pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, lcs_count, lcs_count);
                            i ++;
                            lcs_count++;
                            break;
                        }
                    }

                    /*
                     * Check if the ERO has changed
                     */
                    ero_changed = pccd_core_is_ero_changed((const RouteObj *)(lcs_info[lcs_count].ero_info),
                                  (const RouteObj *)(rpd_lsp->ero_info));

                    if (!BIT_ISSET(p2mp_lsp->flags, IS_MBB_NEEDED))
                        if (ero_changed)
                            BIT_SET(p2mp_lsp->flags, IS_MBB_NEEDED);

                    if (BIT_ISSET(p2mp_lsp->flags, IS_MBB_NEEDED)) {
                    	/*
                    	 * If MBB is needed then store the incoming p2mp attributes
                    	 * in the local cache which will be sent to RPD later
                    	 * when all the fragmented p2mp LSP branches comes
                    	 */
                    	if (p2mp_lsp->lcs_pce) {
                            memcpy(p2mp_lsp->lcs_pce, &info, sizeof(info));
                    	} else {
                    	    p2mp_lsp->lcs_pce = (rpd_extctrl_lsp_config_status_info_t *)xmalloc(sizeof(rpd_extctrl_lsp_config_status_info_t));
                    	    memcpy(p2mp_lsp->lcs_pce, &info, sizeof(info));
                    	}
                    }

                    if (trig_mbb) {
                        lcs_info[lcs_count].p2mp_mbb_flag = TAG_EXTCTRL_P2MP_MBB_TRIGGER;
                        trig_mbb = false;
                    }

                    /* NSR Begin */
                    if (TRUE == is_empty_ero) {
                        pccd_core_rx_empty_ero(rpd_lsp, pce, &lcs_info[lcs_count], srp_id, true);
                    } else if (ero_changed || (rpd_lsp->pce_proposed_ero_info == NULL)) {
            	        pccd_rpd_update_pce_proposed_info(&lcs_info[lcs_count]);
            		TRACE_CORE("Updated ERO of p2mp branch");
                    }
                    /* NSR End */
                   i ++;// ERO object processed
                   lcs_count++;
                   break;
                }
                default:
                {
                    TRACE_PCEP(dtfo, "Leaf type %d not supported", leaftype);
                    pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count -1);
                    free(lcs_info);
                    lcs_info = NULL;
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
            }
        }
    	/*
    	 * Process in the case of old leaves modified:
    	 * If there is any change in any branch,
    	 * send update of the entire p2mp tree to rpd
    	 * else don't send the update
    	 */
    	if (leaftype == OLD_LEAVES_CAN_MODIFIED) {
    		if (fragmented) {
    			/*
    		 * wait till the last fragment comes
    		 */
    			TRACE_CORE("Wait for the last fragment");
    		} else if (!BIT_ISSET(p2mp_lsp->flags, IS_MBB_NEEDED)) {
    			/*
    		 * Update Came without any changes
    		 * Send LSP report to PCE
    		 */
    			TRACE_CORE("PCUpdate came without any atrribute changes, so no update will be sent to RPD");
    			if (pccd_core_report_p2mp_lsp(pce, p2mp_lsp,
    										  pce->pc_state >= PCE_STATE_SYNC, srp_id,
    										  OLD_LEAVE_MUST_UNCHAGED)) {
    				LOGGING_ERR("Could not send P2mp PCRpt to pce '%s'",
    							 pce->pc_pce.pce_id);
    				TRACE_FUNCTION_RETURN(-1);
    			}
    		p2mp_lsp->mbb_id = SRP_ID_RESV1;
    		} else {
    			/*
    		 * Send update for the p2mp tree
    		 */
    			TRACE_CORE("Sending p2mp tree to RPD for Update");
    		   pccd_rpd_p2mp_pcupdate(p2mp_lsp);
    			   p2mp_lsp->mbb_id = SRP_ID_RESV1;
    		}
    	}
    }

    /**
     * For this PCUpdate msg, associate FlowSpec (if any),
     * to the lsp
     */
    pccd_core_pcupdate_map_fs_to_lsp(lsp->lv_lsp_id, &objs[fs_obj_start], fs_obj_cnt);

    *p2mp_objs_handled = i + (unsigned int)ret_attr;
    if (lcs_info) {
        free(lcs_info);
        lcs_info = NULL;
    }

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_core_received_pcupdate (struct pce_cfg_core *pce,
                             const struct pcep_object *objs, size_t count)
{
    lsp_intended_attr_t intended_attrs;
    struct pcep_conn *conn = NULL;
    daemon_trace_file_options_t *dtfo = NULL;

    int     objs_handled = 0;
    bool    is_empty_ero = FALSE;
    uint32_t srp_id = 0;
    bool increment_index;
    uint32_t plsp_id = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);

    conn = pce->pc_conn;

    dtfo = pccd_core_pce_get_traceoptions(pce);

    if (!objs || !count) {
        LOGGING_ERR("Invalid number of objects received (%zu) or invalid"
                " objects pointer %p", count, objs);
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_MOM,
                        PCEP_ERR_VAL_LSP_MISSING);
        TRACE_FUNCTION_RETURN(0);
    }

    for (i = 0; i < count;) {

        struct pccd_rpd_lsp_info *rpd_lsp = NULL;
        struct lsp_vector *lsp = NULL;
        rpd_extctrl_lsp_config_status_info_t info;

        increment_index = false;

        // Get the SRP ID from SRP object. If any failure occur, proceed to next message.
        if (pccd_core_handle_srp_object(pce, objs, i, &srp_id, &increment_index)) {
            // Move to next object as error occured in current SRP object.
            if (increment_index) {
               i++;
            }

            // Proceed to next LSP processing.
            goto next_message;
        }

        if (((i + 1) >= count ) ||
	    ((i + 1) < count && objs[i + 1].type != PCEP_OBJ_LSP)) {
            LOGGING_ERR("Received invalid PCUpd message from pce '%s'. Second "
                        "object is not LSP", pce->pc_pce.pce_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_MOM,
                                     PCEP_ERR_VAL_LSP_MISSING);
            goto next_message;
        }

        if (pce->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_STATEFULACTIVE) {
            TRACE_PCEP(dtfo, "Non active stateful PCE '%s' trying to update LSP",
                       pce->pc_pce.pce_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP);
            goto next_message;
        }

        if (true == objs[i + 1].u.lsp.p2mp_branch){
            unsigned int p2mp_objs_handled = 0;
            int ret = 0;

            if (pce->pc_pce.pce_p2mp_lsp_update_capability != true) {
                LOGGING_ERR("Non p2mp-lsp update allowed PCE '%s' trying to "
                            "update P2MP-LSP",
                            pce->pc_pce.pce_id);
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_INVALID_OPERATION,
                                         PCEP_ERR_VAL_NOT_ADV_P2MP_UPDATE);
                goto next_message;
            }
            if (((i + 2) >= count) ||
		((i + 2) < count && objs[i + 2].type != PCEP_OBJ_P2MP_ENDPOINTS_IPV4)) {
                LOGGING_ERR("Received invalid P2MP PCUpd message from pce '%s'. Third "
                            "object is not P2MP End-Point", pce->pc_pce.pce_id);
                pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_EP_MISSING);
                goto next_message;
            }


            ret = pccd_core_received_p2mp_pcupdate(pce, objs, count, &p2mp_objs_handled);
            if (PCCD_RET_FAIL == ret) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            } else {
                i += p2mp_objs_handled;
                // Proceed to next LSP processing.
                goto next_message;
            }
        }

        i++; // Move to LSP object

        plsp_id = objs[i].u.lsp.plsp_id;
        rpd_lsp = pccd_rpd_get_lsp_by_id(objs[i].u.lsp.plsp_id);
        if (!rpd_lsp) {
            LOGGING_ERR("PCE is trying to update unknown LSP ID: %d",
                        objs[i].u.lsp.plsp_id);
            pccd_send_error_with_srp(conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
            goto next_message;
        }

        pccd_rpd_update_instance(rpd_lsp, LAST_PC_UPD_CRT);

        TRACE_PCEP(dtfo, "switch_delegation?  type:%d, flags:%0x, delegate:%d, control_status:%d",
                   rpd_lsp->type, rpd_lsp->lsp_flags, objs[i].u.lsp.delegated,
                   rpd_lsp->control_status);

        /* If the LSP from RPD is set as locally(CLI) controlled, or its
         * current control state is local control, do not allow PCE to modify
         * its parameters */
        if (!(((rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED) ||
                (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED)) &&
                rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED)) {
            LOGGING_ERR("PCE is trying to update LSP ID: %d, which is not "
                        "externally controlled", rpd_lsp->id);
            if (pccd_send_error_with_srp(conn, srp_id,
                                         PCEP_ERR_TYPE_INVALID_OPERATION,
                                         PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
                pccd_core_set_new_main_pce_timer(pce);
                pccd_core_pce_disconnect(pce);
                pccd_core_pce_schedule_reconnect(pce);
            }
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED ||
            rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
            struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);

            if (lsp_vec && (lsp_vec->lv_pce != pce)) {
                /* PCE is trying to update LSP which owns another PCE */
                TRACE_PCEP(dtfo, "PCE '%s' is trying to update LSP with lsp_name '%s' "
                "path_name '%s' which owns PCE '%s'",
                           pce->pc_pce.pce_id, rpd_lsp->lsp_name, rpd_lsp->path_name,
                           lsp_vec->lv_pce ? lsp_vec->lv_pce->pc_pce.pce_id : "NULL");
                if (pccd_send_error_with_srp(conn, srp_id,
                                             PCEP_ERR_TYPE_INVALID_OPERATION,
                                             PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
                    pccd_core_set_new_main_pce_timer(pce);
                    pccd_core_pce_disconnect(pce);
                    pccd_core_pce_schedule_reconnect(pce);
                }
                // Proceed to next LSP processing.
                goto next_message;
            }
        }

        /*
         * check for the delegate flag values in the update message and in the
         * internal lsp object. find out if the delegation is accepted by the
         * PCE or not. if the delegation is not accepted, stop the timer, and
         * report to RPD.
         */

        /* retrieve our internal lsp object */
        lsp = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        if (lsp == NULL) {
            LOGGING_ERR("Could not retrieve LSP in internal list");
            goto next_message;
        }

	if (!lsp->ack && lsp->srp_id == 0xFFFFFFFF) {
	    TRACE_PCEP(dtfo, "send PCRpt message for srp_id wrapping");
	    if (pccd_core_report_lsp(pce, rpd_lsp, true,
                                     pce->pc_state >= PCE_STATE_SYNC, lsp->srp_id,
                                     OLD_LEAVE_MUST_UNCHAGED, false)) {
                LOGGING_ERR("Could not send PCRpt to pce '%s'",
                            pce->pc_pce.pce_id);
                goto next_message;
            }  
	}
	lsp->ack = false;
        /* stop the delegation message timer */
        if (evTestID(lsp->lv_delegation_setup_tid)) {
            evClearTimer(pccd_core_ev_ctx, lsp->lv_delegation_setup_tid);
            evInitID(&lsp->lv_delegation_setup_tid);
        }
        lsp->lv_ack_delegated = objs[i].u.lsp.delegated;
        if (lsp->lv_want_to_delegate && lsp->lv_ack_delegated) {
            /* check if the retry delegation timer is running stop the timer */
            pccd_core_clear_lsp_delegation_retry_tid(lsp);
        }
        if ( rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED &&
             lsp->lv_want_to_delegate && !lsp->lv_ack_delegated) {
            TRACE_PCEP(dtfo, "upd msg for LSP with lsp_name %s path_name %s ,D=0, but lv_want_to_delegate=1",
                             rpd_lsp->lsp_name, rpd_lsp->path_name);
            /* Handling msg from PCE right now, therefore the PCE must be
             * connected */
            INSIST_ERR(pce->pc_state > PCE_STATE_CONNECTED);
            lsp->lv_pce->pc_statistics.delegation_failures++; /* Delegation failures counter */
            {
                /* 
                 * set the delegation failure flag. In case of delegation
                 * failure, does PCC have to give control back to RPD? 
                 * One of the reasons, to give control back is, there is
                 * no clear indication of delegation failure and re-delegation
                 * of LSP from PCE. So, D=0 just give the control back and
                 * in the redelegation timeout handler request RPD for
                 * control.  Will this cause IPC channel to be busy?
                 */

                /* lv_retry_delegation should be true as delegation can be retried via CLI*/
                lsp->lv_retry_delegation = true;

                /* Increase delegation failed count for LSP, after PCEP_MAX_DELEG_RETRY session
                with controller will be disconnected and session will be established with
                new controller */
                lsp->lv_delegation_failed++;

                /* NSR Begin */
                pccd_core_return_control(rpd_lsp);
                /* NSR End */
                /* start delegation retry timer */
                if (pce->pc_pce.pce_opts.pco_lsp_retry_delegation &&
                    pce->pc_pce.pce_opts.pco_delegation_retry_timeout &&
                    !evTestID(lsp->lv_lsp_delegation_retry_tid)) {
                    /* Start the delegation_setup timer */
                    TRACE_CORE("Arming delegation_retry_tid for PCE: %s and LSP id: %u",
                                                     pce->pc_pce.pce_id, lsp->lv_lsp_id);
                    if (evSetTimer(pccd_core_ev_ctx, pccd_core_delegation_retry_timedout,
                        lsp, evAddTime(evNowTime(),
                        evConsTime(pce->pc_pce.pce_opts.pco_delegation_retry_timeout, 0)),
                                   evConsTime(0,0),
                                   &lsp->lv_lsp_delegation_retry_tid) == -1) {
                        LOGGING_ERR("Failed to initialise delegation retry timer: %s",
                                                           strerror(errno));
                    }
                }

            }
            TRACE_FUNCTION_RETURN(0);
        } else {
            lsp->lv_delegation_failed = 0;
            // Remember SRP-ID
            lsp->srp_id = srp_id;
        }
        /* Returning delegation of provisioned LSP */
        if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED &&
            (objs[i].u.lsp.delegated == false)) {
            TRACE_PCEP(dtfo, "PCE returning delegation if PCE provisoned lsp with lsp_name '%s' "
				"path_name '%s'", rpd_lsp->lsp_name, rpd_lsp->path_name);
            lsp->lv_ack_delegated = false;
            lsp->lv_want_to_delegate = false;

            /* Clear metrics sent by PCE as LSP is no longer controlled by PCE */
            TRACE_CORE("Clear metrics sent by PCE");
            pccd_rpd_free_intended_metric(rpd_lsp);
            pccd_rpd_free_actual_metric(rpd_lsp);

            if (pccd_core_report_lsp(pce, rpd_lsp, true,
                                     pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                     OLD_LEAVE_MUST_UNCHAGED, true)) {
                LOGGING_ERR("Could not send PCRpt to pce '%s'",
                             pce->pc_pce.pce_id);
                TRACE_FUNCTION_RETURN(-1);
            }
            /* Start lsp cleanup timer. Default value is 60 seconds */
            if (!evTestID(lsp->lv_lsp_cleanup_tid)) {
                /* NSR Begin */
                pccd_core_start_lsp_cleanup_tid(pce, lsp);
                /* NSR End */
            }
            break;
        }
#if 0
        /* Returning delegation of delegated LSP */
        if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED) {
            /* find if the delgation is given back to PCC from PCE */
            if ((rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED) && 
                (objs[i].u.lsp.delegated == false)) {
                // switch_delegation = true;
                TRACE_PCEP(dtfo, "PCE returning delegation of PCE delegated '%s'", rpd_lsp->name);
                lsp->lv_switch_delegation = true;
                pccd_rpd_lsp_return_control(rpd_lsp);
                if (pce->pc_pce.pce_opts.pco_lsp_retry_delegation &&
                    pce->pc_pce.pce_opts.pco_delegation_retry_timeout &&
                    !evTestID(lsp->lv_lsp_delegation_retry_tid)) {
                    /* Start the delegation_setup timer */
                    TRACE_CORE("Arming delegation_retry_tid for re-delegation to PCE: %s and LSP id: %u",
                                                     pce->pc_pce.pce_id, lsp->lv_lsp_id);
                    if (evSetTimer(pccd_core_ev_ctx, pccd_core_delegation_retry_timedout,
                        lsp, evAddTime(evNowTime(),
                        evConsTime(pce->pc_pce.pce_opts.pco_delegation_retry_timeout, 0)),
                                   evConsTime(0,0),
                                   &lsp->lv_lsp_delegation_retry_tid) == -1) {
                        LOGGING_ERR("Failed to initialise re-delegation timer: %s",
                                                           strerror(errno));
                    }
                }
            }
            break;
        }
#endif

        memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));

        memset(&intended_attrs, 0, sizeof(lsp_intended_attr_t));

        strncpy(info.name, rpd_lsp->lsp_name, sizeof(info.name));
	info.name[sizeof(info.name) - 1] = '\0';

	if (rpd_lsp->path_name[0]) {
	    strncpy(info.path_name, rpd_lsp->path_name, sizeof(info.path_name));
	    info.path_name[sizeof(info.path_name) - 1] = '\0';

	}
        if (sizeof(info.name) < sizeof(rpd_lsp->lsp_name) &&
                strlen(rpd_lsp->lsp_name) >= sizeof(info.name)) {
            LOGGING_ERR("LSP name buffer not big enough to store LSP name");
            abort();
        }
	if (sizeof(info.path_name) < sizeof(rpd_lsp->path_name) &&
	    strlen(rpd_lsp->path_name) >= sizeof(info.path_name)) {
            LOGGING_ERR("LSP path name buffer not big enough to store LSP name");
            abort();
        }

        /* NSR Begin */
        /* clear the cleanup timer if running */
        pccd_core_clear_lsp_cleanup_tid(lsp);
        /* NSR End */

        if (!rpd_lsp->is_lsp_src_dst_addr_type_ipv6) {
            info.dstaddr_u.v4 = rpd_lsp->dstaddr.v4;
            info.srcaddr_u.v4 = rpd_lsp->srcaddr.v4;
            info.is_lsp_src_dst_addr_type_ipv6 = false;
        } else {
            memcpy(info.dstaddr_u.v6, rpd_lsp->dstaddr.v6, 16);
            memcpy(info.srcaddr_u.v6, rpd_lsp->srcaddr.v6, 16);
            info.is_lsp_src_dst_addr_type_ipv6 = true;
        }
        info.lsp_type_info.setup_type = rpd_lsp->setup_type;
        info.srte_ero_info = NULL;
        info.ero_info = NULL;
        info.ero_len = 0;
        info.type = rpd_lsp->type;

        is_empty_ero = FALSE;
        objs_handled = pccd_core_update_lsp_params(pce, rpd_lsp, &info, &objs[i],
                                                   (count - i), srp_id,
                                                   &is_empty_ero, &intended_attrs,
                                                   plsp_id);
        if (objs_handled < 0) {
            TRACE_PCEP(dtfo, "LSP(%s/%s) updating lsp params failed", info.name,
                       info.path_name);
            pccd_core_rpd_extctrl_lcs_info_cleanup(&info, 0, 0);
            goto next_message;
        } else if (TRUE == is_empty_ero) {
            pccd_core_rx_empty_ero(rpd_lsp, pce, &info, srp_id, false);
        } else if (!pccd_rpd_pcupdate(rpd_lsp, &info)) {
            TRACE_PCEP(dtfo, "Could not send PCUpdate to RPD");
            /*
             * even thought this message failed, continue to process the next
             * message
             */
        }

        pccd_core_copy_intended_attributes(&intended_attrs, rpd_lsp);

        pccd_core_rpd_extctrl_lcs_info_cleanup(&info, 0, 0);
        i += objs_handled - 1;
next_message:
	i = pccd_core_find_next_srp(objs, i, count);
	if (i >= count) {
	    TRACE_CORE("Reached end of PCUpdate list");
	    // coverity[leaked_storage]
	    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
	}
    // coverity[leaked_storage]
	continue;
    }
    TRACE_FUNCTION_RETURN(0);
}

/* If no endpoint object is present, derive endpoints from eros
 * if not possible to derive it from eros
 * return 0 on success
 * else return -1
 */
static int
pccd_core_derive_endpoint_from_ero (struct pce_cfg_core *pce,
                                    rpd_extctrl_lsp_config_status_info_t *lcs_info,
                                    const struct pcep_object *objs)
{
    struct in_addr src;
    const struct pcep_obj_ero *ero = NULL;

    TRACE_FUNCTION_ENTRY();
    if (!lcs_info || !objs || objs->type != PCEP_OBJ_ERO) {
	    TRACE_CORE("No ERO Object");
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    /**
     * If PCEP Session is IPv6 then dont send local address as source
     * address of lsp instead set it 0
     */
    if (pce->pc_pce.is_ipv6_session ) {
        src.s_addr = 0;
    } else {
        src = pccd_core_pce_get_local_ip_addr(pce);
    }

    ero = &objs->u.ero;

    if (ero->subcount == 0) {
	TRACE_CORE("No endpoint and empty ERO in PCInitiate");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    if (ero->subs[ero->subcount - 1].type == PCEP_ERO_SUB_IPV4) {
        const struct pcep_obj_ero_sub_ipv4_prefix *ipv4 = &ero->subs[ero->subcount - 1].data.ipv4_prefix;
        lcs_info->dstaddr_u.v4 = ipv4->address.s_addr;
        lcs_info->srcaddr_u.v4 = src.s_addr;
        lcs_info->is_lsp_src_dst_addr_type_ipv6 = false;
	TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    } else if (ero->subs[ero->subcount - 1].type == PCEP_ERO_SUB_SR) {
        if (ero->subs[ero->subcount - 1].data.sr_ero.nai_type == PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID) {
             const struct pcep_obj_ero_sub_sr_ipv4_node_id *sr_ipv4_node_id =
                                       &ero->subs[ero->subcount - 1].data.sr_ero.NAI_data.ipv4_node_id;
             lcs_info->dstaddr_u.v4 = sr_ipv4_node_id->address.s_addr;
             lcs_info->srcaddr_u.v4 = src.s_addr;
             lcs_info->is_lsp_src_dst_addr_type_ipv6 = false;
             TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
        } else if (ero->subs[ero->subcount - 1].data.sr_ero.nai_type == PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ) {
             const struct pcep_obj_ero_sub_sr_ipv4_adj *sr_ipv4_adj =
                                       &ero->subs[ero->subcount - 1].data.sr_ero.NAI_data.ipv4_adjacency;
             lcs_info->dstaddr_u.v4 = sr_ipv4_adj->remote.s_addr;
             lcs_info->srcaddr_u.v4 = src.s_addr;
             lcs_info->is_lsp_src_dst_addr_type_ipv6 = false;
             TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
	}
        TRACE_CORE("SR-ERO object's last subobject is not PCEP_SR_ERO_TYPE_IPV4_NODE_ID");
    } else if (ero->subs[ero->subcount - 1].type == srv6_ero_subobject_type) {
        TRACE_CORE("Don't derive ENDPOINTS from ERO for SRv6 LSPs");
        /* SRTE will get the source address from infra/ipv6-router id when src address is set to 0::0 */
        memset(lcs_info->srcaddr_u.v6, 0, 16);
        /* Default route will be created as destination address is 0::0 */
        memset(lcs_info->dstaddr_u.v6, 0, 16);
        lcs_info->is_lsp_src_dst_addr_type_ipv6 = true;
    }
    TRACE_CORE("ERO object's last subobject is not PCEP_ERO_SUB_IPV4 or PCEP_ERO_SUB_SR or PCEP_ERO_SUB_SRV6");
    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
}

/**
 * Take parameters from objects from incoming PCCreate msg and fill
 * extctrl_lsp_params_info_t with them.
 * @param conn
 * @param info
 * @param objs
 * @param count
 * @return
 */
static int
pccd_core_parse_lsp_instantion(struct pce_cfg_core *pce,
                               rpd_extctrl_lsp_config_status_info_t *info,
                               rpd_extctrl_lsp_config_status_info_t *lcs_info,
                               const struct pcep_object *objs, size_t count,
                               uint32_t srp_id, lsp_intended_attr_t *intended_attrs,
                               struct pccd_flowspec_info_head  *tmp_lv_fs_info_head,
                               radix_root_t *tmp_lsp_prefix_tree_root)
{
    bool bandwidth_present = false;
    bool association_present = false;
    bool lspa_present = false;
    bool flowspec_present = false;
    int endpoint_count = 0;
    int objs_handled = 0;
    int j= 0;
    int ero_count = 0;
    int pa_count = 0, ero_index = 0, k = 0;
    uint32_t ero_entries_count = 0;
    bool path_attribute_present = false, list_init = false;
    const struct pcep_object *obj_endpoint = NULL;
    struct pcep_object *ero_obj_list[128], *pa_obj_list[128], *ero_obj = NULL;
    struct pcep_object *dag_obj_list[PCCD_MAX_DISJOINT_ASSOC_GROUPS];
    bool dag_obj_isipv6[PCCD_MAX_DISJOINT_ASSOC_GROUPS] = {false, false, false, false, false, false, false, false};
    int srpag_count  = 0;
    int srpag_ipv6_count  = 0;
    uint8_t fs_obj_cnt = 0;
    uint32_t dag_obj_count = 0;
    unsigned i;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(info != NULL);
    INSIST_ERR(objs != NULL);
    INSIST_ERR(count != 0);

    if (info->path_flags & LSP_PATH_TYPE_P2MP) {
        INSIST_ERR(objs->type == PCEP_OBJ_P2MP_ENDPOINTS_IPV4);
    }

    if ((objs[0].type == PCEP_OBJ_ENDPOINTS_IPV4) || (objs[0].type == PCEP_OBJ_ENDPOINTS_IPV6)
            || (objs[0].type == PCEP_OBJ_P2MP_ENDPOINTS_IPV4))
        obj_endpoint = &objs[0];

    if (obj_endpoint && (obj_endpoint->type == PCEP_OBJ_P2MP_ENDPOINTS_IPV4)){
        endpoint_count = obj_endpoint->u.p2mp_endpoints_ipv4.subcount;
    } else {
        endpoint_count = 1;
    }

    info->ero_info = NULL;
    info->srte_ero_info = NULL;
    info->ero_len = 0;
    info->type = LSP_TYPE_EXTERNALLY_PROVISIONED;
    info->state = LSP_STATE_CREATION_PENDING;
    info->relcsi_local_cspf = 0;

    if (objs[0].type == PCEP_OBJ_ERO) {
        objs_handled = 0;
    } else {
        objs_handled = 1;
    }

    i = objs_handled;
    for (i = objs_handled; i < count; i++) {
        const struct pcep_object *obj = &objs[i];
        switch(obj->type) {
        case PCEP_OBJ_ERO: {
        		if (!ero_count) {
                    ero_obj = (struct pcep_object *) obj;
        			ero_obj_list[ero_index] = (struct pcep_object *) obj;
                    ero_index++;
                } else {
                    ero_obj_list[ero_index] = (struct pcep_object *) obj;
                    ero_index++;
                }
            ero_count++;
            break;
        }
          case PCEP_OBJ_LSPA: {
              if (lspa_present) {
                  TRACE_CORE("Multiple LSPA objects for the same LSP");
              }		
              if (pccd_core_parse_lspa(pce->pc_conn, info, &objs[i].u.lspa, true)) {
                  TRACE_FUNCTION_RETURN(-1);
              }
              objs_handled++;
              lspa_present = true;
              break;
          }
        case PCEP_OBJ_BANDWIDTH_REQUEST: {
            if (bandwidth_present) {
                TRACE_CORE("Multiple BW objects for the same LSP");
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_CNS,
                                         PCEP_ERR_VAL_GENERIC);
                TRACE_FUNCTION_RETURN(-1);
            }
            if (pccd_core_parse_bw_req(pce->pc_conn, info, &objs[i].u.bandwidth,
                                       intended_attrs)) {
                TRACE_FUNCTION_RETURN(-1);
            }
            objs_handled++;
            bandwidth_present = true;
            BIT_SET(info->lcs_params_flags, TAG_EXTCTRL_PARAMS_BANDWIDTH);
            break;
        }
        case PCEP_OBJ_ASSOCIATION_nonRFC:
        case PCEP_OBJ_ASSOCIATION_nonIANA: {
		    if (obj->type != PCEP_OBJ_ASSOCIATION_VAL) {
                        goto out;
                    }
            if (association_present) {
                TRACE_CORE("Got multiple ASSOC objects for the same LSP");
            } else {
		info->num_assoc_info = 0;
	    }

            if (pccd_core_parse_assoc_obj_non_rfc(pce->pc_conn, srp_id, info, &objs[i].u.association_non_rfc)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }

            objs_handled++;
            association_present = true;
            BIT_SET(info->lcs_params_flags, TAG_EXTCTRL_PARAMS_ASSOCIATION);
            break;
        }
        case PCEP_OBJ_ASSOCIATION: {
            if (association_present) {
                TRACE_CORE("Got multiple ASSOC objects for the same LSP");
            } else {
		        info->num_assoc_info = 0;
	        }
            if (ASSOCIATION_TYPE_DISJOINT == objs[i].u.association.association_type) {
                if (dag_obj_count >= PCCD_MAX_DISJOINT_ASSOC_GROUPS) {
                    TRACE_CORE(" Received more than 8 diveristy association objects in given"
                               " message. Not processing the message");
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
                const struct pcep_object *obja = &objs[i];
                dag_obj_list[dag_obj_count] = (struct pcep_object *) obja;
                dag_obj_isipv6[dag_obj_count] = false;
                dag_obj_count++;
                continue;
            }

            if (ASSOCIATION_TYPE_SRPAG == objs[i].u.association.association_type) {

                /**
                 * In PCInit message, PCE should send following association IDs for requesting
                 * SRPAG association.
                 * 1 - as per draft-ietf-pce-segment-routing-policy-cp-05
                 */
                if (objs[i].u.association.association_id != 1) {

                    struct in_addr assoc_source;
                    memcpy(&assoc_source.s_addr,
                        &objs[i].u.association.ipv4_association_source.s_addr,
                        sizeof(assoc_source.s_addr));

                    TRACE_CORE("Ignoring association object as received parameter(s) "
                        "are not expected. Received association id:%u, "
                        "is extended association id present:%d, Received association source:%s",
                        objs[i].u.association.association_id,
                        objs[i].u.association.extended_assoc_id,
                        inet_ntoa(assoc_source) );
                    break;
                }
            }

            if (pccd_core_parse_assoc_obj(pce->pc_conn, srp_id, NULL, &srpag_count ,info,
                    &objs[i].u.association)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }

            objs_handled++;
            association_present = true;
            break;
        }
        case PCEP_OBJ_ASSOCIATION_IPV6: {

            if (association_present) {
                TRACE_CORE("Got multiple ASSOC objects for the same LSP");
            } else {
                info->num_assoc_info = 0;
            }
            if (ASSOCIATION_TYPE_DISJOINT == objs[i].u.association_ipv6.association_type) {
                if (dag_obj_count >= PCCD_MAX_DISJOINT_ASSOC_GROUPS) {
                    TRACE_CORE(" Received more than 8 diveristy association objects in given"
                               " message. Not processing the message");
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
                const struct pcep_object *obja = &objs[i];
                dag_obj_list[dag_obj_count] = (struct pcep_object *) obja;
                dag_obj_isipv6[dag_obj_count] = true;
                dag_obj_count++;
                continue;
            }

            if (ASSOCIATION_TYPE_SRPAG == objs[i].u.association_ipv6.association_type) {

                /**
                 * In PCInit message, PCE should send following association IDs for requesting
                 * SRPAG association.
                 * 1 - as per draft-ietf-pce-segment-routing-policy-cp-05
                 */
                if (objs[i].u.association_ipv6.association_id != 1) {

                    char assoc_source_ip_addr[INET6_ADDRSTRLEN] = "";
                    inet_ntop(AF_INET6, &objs[i].u.association_ipv6.ipv6_association_source, assoc_source_ip_addr,
                              sizeof(assoc_source_ip_addr));

                    TRACE_CORE("Ignoring association object as received parameter(s) "
                        "are not expected. Received association id:%u, "
                        "is extended association id present:%d, Received association source:%s",
                        objs[i].u.association_ipv6.association_id,
                        objs[i].u.association_ipv6.extended_assoc_id,
                        assoc_source_ip_addr);
                    break;
                }
            }

            if (pccd_core_parse_assoc_ipv6_obj(pce->pc_conn, srp_id, NULL, &srpag_ipv6_count ,info,
                    &objs[i].u.association_ipv6)) {
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }

            objs_handled++;
            association_present = true;
            break;
        }

        case PCEP_OBJ_METRIC: {
            if (pccd_core_parse_metric(pce->pc_conn, info, &objs[i].u.metric,
                                       intended_attrs)) {
                TRACE_FUNCTION_RETURN(-1);
            }
            objs_handled++;
            break;
        }

        case PCEP_OBJ_VENDOR: {
            if (pccd_core_parse_vendor(pce->pc_conn, info, &objs[i].u.vendor)) {
                TRACE_FUNCTION_RETURN(-1);
            }
            objs_handled++;
            break;
        }

        case PCEP_OBJ_FLOWSPEC: {

            if (fs_obj_cnt >= MAX_FLOWSPEC_SUPPORTED_PER_LSP) {
                TRACE_CORE("Maximum %d flowspec only can be mapped to lsp",
                            MAX_FLOWSPEC_SUPPORTED_PER_LSP);
                break;
            }

            /* Increment parsed fs object count */
            fs_obj_cnt++;

            /*
             * For P2P LSP, this will handle flowspec destination prefix processing.
             * For P2MP, Multicast flowspec processing is done at later point
             */
            pccd_core_process_new_fs_prefix(&objs[i].u.flowspec,
                        tmp_lv_fs_info_head,
                        tmp_lsp_prefix_tree_root);

            TRACE_CORE("FS: PC create adding new FS %u", objs[i].u.flowspec.fs_id);

            flowspec_present = true;

            objs_handled++;
            break;
        }
        case PCEP_OBJ_PATH_ATTRIBUTE: {
            if (!multipath_enabled) {
                TRACE_CORE("Multipath Capability is disabled. Received path attributes object in the PCInit message. "
                           "Sending PCErr to the PCE");
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_CNS,
                                         PCEP_ERR_VAL_GENERIC);
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
            TRACE_CORE(" LSP %s - Saving path attributes - path_id %u "
                       "weight %u op_state %u", info->name,
                       obj->u.path_attr.path_id, obj->u.path_attr.weight,
                       obj->u.path_attr.op_state);
            int local_counter = 0;
            while (local_counter < pa_count) {
                if (pa_obj_list[local_counter]->u.path_attr.path_id == obj->u.path_attr.path_id) {
                    TRACE_CORE("Redundant path_id %u found in the message", obj->u.path_attr.path_id);
                    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_RIO,
                                             PCEP_ERR_VAL_CONFLICTING_PATHID);
                    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
                }
                local_counter++;
            }
            pa_obj_list[pa_count] = (struct pcep_object *) obj;
            pa_count++;
            objs_handled++;
            path_attribute_present = true;
            break;
        }

        default:
            /* Other objects mean end of this lsp update block */
            goto out;
        }
    }
    if (dag_obj_count) {
        if (disjoint_association_enabled == false) {
            TRACE_CORE("Received disjoint assoc TLVs eventhough PCC is not capable");
            pccd_send_error_with_srp(pce->pc_conn, srp_id, PCEP_ERR_TYPE_NSO,
                                     PCEP_ERR_VAL_OBJECT_TYPE);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        if (pccd_core_parse_lsp_diversity_association(pce->pc_conn, info, dag_obj_count,
                                                      dag_obj_isipv6, dag_obj_list, srp_id, false)) {
            TRACE_FUNCTION_RETURN(-1);
        }
        objs_handled += dag_obj_count;
    } else {
        TRACE_CORE("DAG: No diversity association info found");
    }

out:
    if (flowspec_present) {
        /* Populate install prefix buffer of lcs info from prefix table */
        pccd_rpd_update_prefix_in_lcs_info(info, tmp_lsp_prefix_tree_root);
    }

    if (!multipath_enabled ||
        ((info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) ||
         (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE))) {
        if (ero_count != endpoint_count) {
            TRACE_CORE("ERO object count is not same as End Point Count, ERO count= %d", ero_count);
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_MOM,
                                     PCEP_ERR_VAL_ERO_MISSING);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }
    if (multipath_enabled && 
        ((info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
         (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {
        if ((ero_count>1) && (ero_count != pa_count)) {
            TRACE_CORE(" ERO object count is not same as path attribute count, "
                       "ERO count=%d, pa_count=%d",
                       ero_count, pa_count);
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_MOM,
                                     PCEP_ERR_VAL_ERO_MISSING);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
       if (ero_count > PCCD_PLATFORM_MAX_ERO_COUNT) {
            TRACE_CORE(" Received %u number of EROs. The current platform limit is %u. "
                       "Sending PCErr to the PCE",
                       ero_count, PCCD_PLATFORM_MAX_ERO_COUNT);
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_PCCREATE,
                                     PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
    }

    for (j = 0; j < endpoint_count; j++) {
        memcpy(&lcs_info[j], info, sizeof(rpd_extctrl_lsp_config_status_info_t));
        if (!obj_endpoint) {
            if (PCCD_RET_SUCCESS != pccd_core_derive_endpoint_from_ero(pce, &lcs_info[j], ero_obj)) {
                TRACE_FUNCTION_RETURN(-1);
            }
        } else if (obj_endpoint && obj_endpoint->type == PCEP_OBJ_ENDPOINTS_IPV4){
            lcs_info[j].srcaddr_u.v4 = (u_int32_t)obj_endpoint->u.endpoints_ipv4.source.s_addr;
            lcs_info[j].dstaddr_u.v4 = (u_int32_t)obj_endpoint->u.endpoints_ipv4.destination.s_addr;
            lcs_info[j].is_lsp_src_dst_addr_type_ipv6 = false;
        } else if (obj_endpoint && obj_endpoint->type == PCEP_OBJ_P2MP_ENDPOINTS_IPV4){
            lcs_info[j].srcaddr_u.v4 = (u_int32_t)obj_endpoint->u.p2mp_endpoints_ipv4.source.s_addr;
            lcs_info[j].dstaddr_u.v4 = (u_int32_t)obj_endpoint->u.p2mp_endpoints_ipv4.destinations[j].s_addr;
            lcs_info[j].is_lsp_src_dst_addr_type_ipv6 = false;
        } else if (obj_endpoint && obj_endpoint->type == PCEP_OBJ_ENDPOINTS_IPV6){
            memcpy(lcs_info[j].srcaddr_u.v6,
                                    &obj_endpoint->u.endpoints_ipv6.source, 16);
            memcpy(lcs_info[j].dstaddr_u.v6,
                                    &obj_endpoint->u.endpoints_ipv6.destination, 16);
            lcs_info[j].is_lsp_src_dst_addr_type_ipv6 = true;
        }

        if (!multipath_enabled ||
            ((lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) ||
            (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE))) {
            if (PCEP_OBJ_ERO == ero_obj[j].type) {
                if ((lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
                    || (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
                    if (PCCD_RET_SUCCESS != pccd_core_parse_ero(&lcs_info[j],
                                                                &ero_obj[j].u.ero, NULL)) {
                        for(int x=0; x<j; x++) {
                            if (lcs_info[x].srte_ero_info) {
                                free(lcs_info[x].srte_ero_info);
                            }
                        }
                        TRACE_FUNCTION_RETURN(-1);
                    }
                } else if (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
                    lcs_info[j].srte_total_ero_count = 0;
                    lcs_info[j].srte_ero_len = (sizeof(rpd_sr_ero_list_t)) +
                                                  ((ero_obj_list[0]->u.ero.subcount) * sizeof(rpd_sr_ero_t));
                    lcs_info[j].srte_ero_info = xmalloc(lcs_info[j].srte_ero_len);
                    if (PCCD_RET_SUCCESS != pccd_core_parse_spring_ero(pce->pc_conn, &lcs_info[j],
                                                                       &ero_obj[j].u.ero, srp_id, NULL)) {
                        TRACE_FUNCTION_RETURN(-1);
                    }
                } else if (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
                    lcs_info[j].srte_total_ero_count = 0;
                    lcs_info[j].srte_ero_len = (sizeof(rpd_sr_ero_list_t)) +
                                                  ((ero_obj_list[0]->u.ero.subcount) * sizeof(rpd_sr_ero_t));
                    lcs_info[j].srte_ero_info = xmalloc(lcs_info[j].srte_ero_len);
                    if (PCCD_RET_SUCCESS != pccd_core_parse_spring_v6_ero(pce->pc_conn, &lcs_info[j],
                                                                          &ero_obj[j].u.ero, srp_id, NULL)) {
                        TRACE_FUNCTION_RETURN(-1);
                    }
                }
                objs_handled++;
            } else {
                break;
            }
        } else {
            list_init = false;
            ero_entries_count = 0;
            if (ero_index>1) {
                if (pa_count > 0) {
                    for (k = 0; k < ero_index; k++) {
                        ero_entries_count += ero_obj_list[k]->u.ero.subcount;
                        ero_obj_list[k]->u.ero.path_attribs.path_id =
                                                pa_obj_list[k]->u.path_attr.path_id;
                        ero_obj_list[k]->u.ero.path_attribs.weight =
                                                pa_obj_list[k]->u.path_attr.weight;
                    }
                } else {
                    TRACE_CORE(" pccd_core - Invalid path attributes count when"
                               " multiple ERO is found");
                    TRACE_FUNCTION_RETURN(-1);
                }
            } else {
                ero_entries_count += ero_obj_list[0]->u.ero.subcount;
                ero_obj_list[0]->u.ero.path_attribs.path_id = 0;
                ero_obj_list[0]->u.ero.path_attribs.weight = 1;
            }
            TRACE_CORE(" pccd_core - ero_count: %u ero_entries count: %u",
                       ero_index, ero_entries_count);
            for (k = 0; k < ero_index; k++) {
                if (PCEP_OBJ_ERO == ero_obj_list[k]->type) {
                    if ((lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
                        || (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
                        if (PCCD_RET_SUCCESS != pccd_core_parse_ero(&lcs_info[j],
                                                                    &ero_obj_list[k]->u.ero, NULL)) {
                            TRACE_FUNCTION_RETURN(-1);
                        }
                    } else if (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
                        if (!list_init) {
                            lcs_info[j].srte_total_ero_count = 0;
                            lcs_info[j].srte_ero_len = ((ero_index) * sizeof(rpd_sr_ero_list_t)) +
                                                       ((ero_entries_count) * sizeof(rpd_sr_ero_t));
                            lcs_info[j].srte_ero_info = xmalloc(((ero_index) * sizeof(rpd_sr_ero_list_t)) +
                                                                ((ero_entries_count) * sizeof(rpd_sr_ero_t)));
                            list_init = true;
                        }
                        if (PCCD_RET_SUCCESS != pccd_core_parse_spring_ero(
                                                                pce->pc_conn, &lcs_info[j],
                                                                &ero_obj_list[k]->u.ero, srp_id, NULL)) {
                            TRACE_FUNCTION_RETURN(-1);
                        }
                    } else if (lcs_info[j].lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
                        if (!list_init) {
                            lcs_info[j].srte_total_ero_count = 0;
                            lcs_info[j].srte_ero_len = ((ero_index) * sizeof(rpd_sr_ero_list_t)) +
                                                       ((ero_entries_count) * sizeof(rpd_sr_ero_t));
                            lcs_info[j].srte_ero_info = xmalloc(((ero_index) * sizeof(rpd_sr_ero_list_t)) +
                                                                ((ero_entries_count) * sizeof(rpd_sr_ero_t)));
                            list_init = true;
                        }
                        if (PCCD_RET_SUCCESS != pccd_core_parse_spring_v6_ero(
                                                                pce->pc_conn, &lcs_info[j],
                                                                &ero_obj_list[k]->u.ero, srp_id, NULL)) {
                            TRACE_FUNCTION_RETURN(-1);
                        }
                    }
                }
            }
        }
    }

    TRACE_FUNCTION_RETURN(objs_handled);
}

static void pccd_core_get_lsp_name_path_name(char *received_name)
{
    char *tok, *cp;
    char * lsp_name = NULL;
    char * path_name = NULL;

    tok = NULL;
    cp = NULL;
    cp = strdup(received_name);
    tok = strtok(cp,"/");
    lsp_name = tok;

    tok = strtok(NULL,"/");
    if(tok) {
		path_name = tok;
		tok = strtok(NULL,"/");
    }
    bzero(received_name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));
    snprintf(received_name, RPD_LSP_NAME_SIZE, "%s",lsp_name);
    if (path_name && strlen(path_name)) {
        snprintf(received_name+strlen(received_name),
                 (RPD_LSP_NAME_SIZE+1), "/%s", path_name);
        received_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1) - 1] = '\0';
    }
    free(cp);
}


static int
pccd_core_received_p2mp_pcdelete (struct pce_cfg_core *pce,
                                  const struct pcep_object *objs,
                                  uint32_t srp_id)
{
    struct lsp_vector *lsp_vec = NULL;
    struct pccd_rpd_lsp_info *rpd_lsp= NULL;
    struct pccd_rpd_lsp_info *tmp = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(objs->u.lsp.plsp_id);

    if (!p2mp_lsp) {
        LOGGING_ERR("PCE is trying to delete unknown LSP ID: %d",
                                                                                    objs->u.lsp.plsp_id);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_INVALID_OPERATION,
                                 PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
    /* Delete LSP from RPD */
    if (!lsp_vec) {
        LOGGING_ERR("Could not delete LSP '%s': not found",
                     p2mp_lsp->p2mp_name);
        if (pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
            pccd_core_set_new_main_pce_timer(pce);
            pccd_core_pce_disconnect(pce);
            pccd_core_pce_schedule_reconnect(pce);
        }
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    /* Delete flowspec associated with lsp */
    pccd_core_send_lsp_fs_delete(lsp_vec, 0, false);
    pccd_core_delete_flowspec_info(lsp_vec, 0, false);

    if (lsp_vec->lv_ack_delegated == false) {
        LOGGING_ERR("Cannot delete non delegated LSP: '%s' id: %d",
                    p2mp_lsp->p2mp_name, lsp_vec->lv_lsp_id);
        if (pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
            pccd_core_set_new_main_pce_timer(pce);
            pccd_core_pce_disconnect(pce);
            pccd_core_pce_schedule_reconnect(pce);
        }
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
        if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
            /* Succesfully deleted */
            TRACE_CORE("LSP with lsp_name '%s' path_name '%s' is deleted from RPD",
            rpd_lsp->lsp_name, rpd_lsp->path_name);
            pccd_core_provisioned_lsps_decrease_counter();
        } else {
            /* Error deleting created LSP */
            LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
            rpd_lsp->lsp_name, rpd_lsp->path_name);
        }
    }

    /* Report deleted LSP to other PCEs */
    pccd_core_report_deleted_provisioned_p2mp_lsp(pce, lsp_vec, p2mp_lsp);

    /**
     * Don't report deleted LSP now to the provisioning PCE. Store SRP id
     * temporarily until RPD responds the delete message sent above
     */
    if (lsp_vec->srp_id == SRP_ID_RESV1) {
        lsp_vec->srp_id = srp_id;
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static bool
pccd_core_delete_all_externally_provisioned_lsps (struct pce_cfg_core *pce,
						  uint32_t srp_id,
						  extctrl_setup_type setup_type)
{
    struct lsp_vector *lsp = NULL;
    struct lsp_vector *tmp = NULL;
    TRACE_FUNCTION_ENTRY();

    SLIST_FOREACH_SAFE(lsp, &pce->pc_lsps, lv_pce_lsps, tmp) {
	if (setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE &&
	    lsp->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
	    const struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);
	    if (p2mp_lsp && p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
		struct pccd_rpd_lsp_info *rpd_lsp= NULL;
		struct pccd_rpd_lsp_info *tmp_lsp = NULL;

		/* Change srp id to the current delete all message */
		lsp->srp_id = srp_id;


		SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
		    if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
			pccd_core_provisioned_lsps_decrease_counter();
		    }
		}
		pccd_core_report_deleted_p2mp_lsp(pce, p2mp_lsp, srp_id);
		pccd_core_report_deleted_provisioned_p2mp_lsp(pce, lsp, p2mp_lsp);
		pccd_core_delete_lsp(lsp);
	    }
	} else {
	    const struct pccd_rpd_lsp_info *rpd_lsp =
	    pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);

	    if (rpd_lsp && rpd_lsp->setup_type == setup_type &&
                rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
		/* Change srp id to the current delete all message */
		lsp->srp_id = srp_id;
		if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
		    /* Report deleted LSP to other PCEs */
		    pccd_core_report_deleted_lsp(pce, rpd_lsp, srp_id);
		    pccd_core_report_deleted_provisioned_lsp(pce, lsp, rpd_lsp);
		    pccd_core_delete_lsp(lsp);
		    pccd_core_provisioned_lsps_decrease_counter();
		}
	    }
	}
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static bool
pccd_core_delete_all_provisioned_lsps_for_pce (struct pce_cfg_core *pce)
{
    struct lsp_vector *lsp = NULL;
    struct lsp_vector *tmp = NULL;

    TRACE_FUNCTION_ENTRY();

    SLIST_FOREACH_SAFE(lsp, &pce->pc_lsps, lv_pce_lsps, tmp) {
        if (lsp->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
            const struct pccd_p2mp_lsp_info *p2mp_lsp =
                                pccd_rpd_get_p2mp_lsp_by_id(lsp->lv_lsp_id);
            if (p2mp_lsp && p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                struct pccd_rpd_lsp_info *rpd_lsp= NULL;
                struct pccd_rpd_lsp_info *tmp_lsp = NULL;

                /* Need to use SRP Id as 0 for Unsolicited Reports */
                lsp->srp_id = SRP_ID_RESV1;


                SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps,
                            lv_p2mp_lsps, tmp_lsp) {
                    if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                        pccd_core_provisioned_lsps_decrease_counter();
                    }
                }
                /* Report deleted P2MP LSP to other PCEs */
                pccd_core_report_deleted_provisioned_p2mp_lsp(pce, lsp, p2mp_lsp);
                pccd_core_delete_lsp(lsp);
            }
        } else {
            const struct pccd_rpd_lsp_info *rpd_lsp =
            pccd_rpd_get_lsp_by_id(lsp->lv_lsp_id);

            if (rpd_lsp && rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                /* Need to use SRP Id as 0 for Unsolicited Reports */
                lsp->srp_id = SRP_ID_RESV1;
                if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                    /* Report deleted LSP to other PCEs */
                    pccd_core_report_deleted_provisioned_lsp(pce, lsp, rpd_lsp);
                    pccd_core_delete_lsp(lsp);
                    pccd_core_provisioned_lsps_decrease_counter();
                }
            }
        }
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}


static int
pccd_core_received_pccreate(struct pce_cfg_core *pce,
                            const struct pcep_object *objs, size_t count)
{
    lsp_intended_attr_t intended_attrs;
    int fs_obj_cnt = 0;
    uint32_t fs_obj_start = 0;

    rpd_extctrl_lsp_config_status_info_t info;
    rpd_extctrl_lsp_config_status_info_t *lcs_info = NULL;
    unsigned i;
    int handled_objects;
    bool p2mp_flag = false;
    unsigned int endpoint_count = 0;
    unsigned int j;
    bool fragmented = false;
    uint32_t vec_plsp_id = 0;

    uint32_t srp_id = 0;
    bool increment_index;

    daemon_trace_file_options_t *dtfo = NULL;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(pce != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    TRACE_CORE("Received object count in message: %u", count);
    if (pce->pc_pce.pce_lsp_provisioning != true) {
        LOGGING_ERR("Non lsp provisioning allowed PCE '%s' trying to "
                    "create LSP",
                   pce->pc_pce.pce_id);
        pcep_send_pcerr(pce->pc_conn,
                        PCEP_ERR_TYPE_INVALID_OPERATION,
                        PCEP_ERR_VAL_NON_DELEGATED_LSP);

        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

    if (!objs || !count) {
        LOGGING_ERR("Invalid number of objects received (%zu) or invalid"
                " objects pointer %p", count, objs);
        pcep_send_pcerr(pce->pc_conn,
                        PCEP_ERR_TYPE_PCCREATE,
                        PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);

        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }


    for (i = 0; i < count; ) {
        char symbolic_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
        char name_rec[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
        char p2mp_name[49];
        struct pccd_flowspec_info_head  tmp_lv_fs_info_head;
        radix_root_t *tmp_lsp_prefix_tree_root = NULL;
        const struct pcep_obj_lsp *obj_lsp = NULL;
        struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
        uint8_t remove_lsp = 0;
        uint8_t err_type = 0;
        uint8_t err_value = 0;
        bool find_next_srp = false;

        memset(symbolic_name, 0, RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1));
        /* clear lsp info */
        memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));

        increment_index = false;

        if (lcs_info) {
            free(lcs_info);
            lcs_info = NULL;
        }

        // Get the SRP ID from SRP object. If any failure occur, proceed to next message.
        if (pccd_core_handle_srp_object(pce, objs, i, &srp_id, &increment_index)) {
            // Move to next object as error occured in current SRP object.
            if (increment_index) {
               i++;
            }

            // Proceed to next LSP processing.
            goto next_message;
        }

        remove_lsp = objs[i].u.srp.remove;
        if (objs[i].u.srp.lsp_setup_type != srv6_pst_type) {
            info.lsp_type_info.setup_type = objs[i].u.srp.lsp_setup_type;
        } else {
            info.lsp_type_info.setup_type = RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE;
        }

        // Move to LSP object index
        i++;

        if (i< count) {
            if (objs[i].type != PCEP_OBJ_LSP) {
                LOGGING_ERR("Received invalid PCCreate message from pce '%s'. Second "
                            "object is not LSP", pce->pc_pce.pce_id);
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_LSP_MISSING);
                goto next_message;
            }
        } else {
            LOGGING_ERR("PCInitiate parsing incomplete.");
            pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_INVALID_OPERATION,
                                     PCEP_ERR_VAL_NON_DELEGATED_LSP);
            TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }

        obj_lsp = &objs[i].u.lsp;
        p2mp_flag = obj_lsp->p2mp_branch;

        if (obj_lsp->symbolic_name_tlv) {
            strncpy(symbolic_name, obj_lsp->symbolic_name,
                    (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)-1));
            symbolic_name[sizeof(symbolic_name) - 1] = '\0';
            pccd_core_get_lsp_name_path_name(symbolic_name);
            TRACE_PCEP(dtfo, "Copying LSP name: '%s' from TLV", symbolic_name);
        } else {
            if (!remove_lsp) {
                LOGGING_ERR("Received invalid PCCreate message from pce '%s'. Second "
                            " Symbolic name is missing", pce->pc_pce.pce_id);
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_SYMB_NAME_MISSING);
                goto next_message;
            }
        }

        fragmented = false;

        if (p2mp_flag){
            if (pce->pc_pce.pce_p2mp_lsp_init_capability != true) {
                LOGGING_ERR("Non p2mp-lsp provisioning allowed PCE '%s' trying to "
                            "create P2MP-LSP",
                            pce->pc_pce.pce_id);
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_INVALID_OPERATION,
                                         PCEP_ERR_VAL_NOT_ADV_P2MP_INSTANT);
                goto next_message;
            }

            memset(p2mp_name, 0, sizeof(p2mp_name));
            if (!pccd_core_validate_p2mp_symbolic_name(symbolic_name, p2mp_name)) {
                TRACE_PCEP(dtfo, "P2mp name validation failed, name %s size %d",
                                 symbolic_name, strlen(symbolic_name));

                /* send internal error */
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_PCCREATE,
                                         PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
                goto next_message;
            }

            info.path_flags |= LSP_PATH_TYPE_P2MP;

            if (true == obj_lsp->fragment){
                /* start fragmentation timer when first time fragmented msg received */
                fragmented = true;
            } else {
                /* stop the fragmentation timer if running */
                fragmented = false;
            }
        }

        /* If LSP has set remove flag to true, delete LSP from RPD */
        if (remove_lsp == true) {
            const struct pccd_rpd_lsp_info *rpd_lsp = NULL;
            TRACE_CORE("PCCreate with remove flag = true");

            if (objs[i].u.lsp.plsp_id == 0) {
                /*Delete all the externally controlled lsps */
                if (pccd_core_delete_all_externally_provisioned_lsps(pce,
                                                                     srp_id,
                                                                     info.lsp_type_info.setup_type)) {
                    goto next_message;
		}

		TRACE_CORE("Deleted all ext provisioned lsps for requested setup type %d",
                           info.lsp_type_info.setup_type);
		goto next_message;
            }

            if (p2mp_flag) {
                (void)pccd_core_received_p2mp_pcdelete(pce, &objs[i], srp_id);

                goto next_message;
            }

            rpd_lsp = pccd_rpd_get_lsp_by_id(objs[i].u.lsp.plsp_id);

            /* check provisioning status of pce */
            if (pce->pc_pce.pce_lsp_provisioning == true) {
                struct lsp_vector *lsp_vec = NULL;

                if (!rpd_lsp) {
                    LOGGING_ERR("PCE is trying to update unknown LSP ID: %d",
                                objs[i].u.lsp.plsp_id);
                    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_INVALID_OPERATION,
                                             PCEP_ERR_VAL_UNKNOWN_PLSP_ID);
                    goto next_message;
                }

                if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED) {
                    LOGGING_ERR("Cannot delete externally controlled LSP with lsp_name '%s' "
						"path_name '%s'", rpd_lsp->lsp_name, rpd_lsp->path_name);
                    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_INVALID_OPERATION,
                                             PCEP_ERR_VAL_LSP_NOT_PCE_INITIATED);
                    goto next_message;
                }

                lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);

                /* Delete LSP from RPD */
                if (lsp_vec) {
                    if (lsp_vec->lv_ack_delegated == false) {
                        LOGGING_ERR("Cannot delete non delegated LSP with lsp_name '%s' "
							"path_name '%s' id: %d",
                                    rpd_lsp->lsp_name, rpd_lsp->path_name, lsp_vec->lv_lsp_id);
                        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                                 PCEP_ERR_TYPE_INVALID_OPERATION,
                                                 PCEP_ERR_VAL_NON_DELEGATED_LSP);
                        goto next_message;
                    }

                    if (pccd_rpd_delete_lsp(rpd_lsp) == true) {
                        /* Succesfully deleted */
                        /* Report deleted LSP to other PCEs */
                        pccd_core_report_deleted_provisioned_lsp(pce, lsp_vec, rpd_lsp);
                        /* Report deleted LSP to the provisioning LSP. Reflect
                         * SRP */
                        pccd_core_report_deleted_lsp(pce, rpd_lsp, srp_id);
                        /* Delete the local cached copy of LSP information */
                        pccd_core_delete_lsp(lsp_vec);
                        pccd_core_provisioned_lsps_decrease_counter();
                    } else {
                        /* Error deleting created LSP */
                        LOGGING_ERR("Error in deleting LSP with lsp_name '%s' path_name '%s'",
                        rpd_lsp->lsp_name, rpd_lsp->path_name);
                        goto next_message;
                    }
                    TRACE_CORE("LSP with lsp_name '%s' path_name '%s' is deleted from RPD",
                        rpd_lsp->lsp_name, rpd_lsp->path_name);
                } else {
                    LOGGING_ERR("Could not delete LSP with lsp_name '%s' path_name '%s' not found",
                                 rpd_lsp->lsp_name, rpd_lsp->path_name);
                    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_INVALID_OPERATION,
                                             PCEP_ERR_VAL_NON_DELEGATED_LSP);
                    goto next_message;
                }
            } else {
                /* PCE does not provision LSP. Send Error */
                if (rpd_lsp) {
                    LOGGING_ERR("PCE '%s' does not provision this LSP:lsp_name '%s' "
                        "path_name '%s'", pce->pc_pce.pce_id, rpd_lsp->lsp_name,
                        rpd_lsp->path_name);
                } else {
                    const char *lsp_name = (const char *)&objs[i].u.lsp.symbolic_name;
                    LOGGING_ERR("PCE '%s' does not provision this LSP '%s'",
                             pce->pc_pce.pce_id, lsp_name);
                }
                if (pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_INVALID_OPERATION,
                                             PCEP_ERR_VAL_NON_DELEGATED_LSP)) {
                    pccd_core_set_new_main_pce_timer(pce);
                    pccd_core_pce_disconnect(pce);
                    pccd_core_pce_schedule_reconnect(pce);
                }
            }
            goto next_message;
        }

        i++;

        if (i < count) {
            if ((p2mp_flag) && (objs[i].type != PCEP_OBJ_P2MP_ENDPOINTS_IPV4)) {
                LOGGING_ERR("Received invalid PCCreate message from pce '%s'. Third "
                            "object of p2mp lsp is not ENDPOINT", pce->pc_pce.pce_id);
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_EP_MISSING);
                goto next_message;
            }
        } else {
            if (p2mp_flag) {
                LOGGING_ERR("Received invalid PCCreate message from pce '%s'. Third "
                            "object of p2mp lsp is not ENDPOINT", pce->pc_pce.pce_id);
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_EP_MISSING);

                goto next_message;
            } else {
                LOGGING_ERR("PCInitiate parsing incomplete.");
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_MOM,
                                         PCEP_ERR_VAL_ERO_MISSING);

                goto next_message;
            }
        }

	if (objs[i].type == PCEP_OBJ_P2MP_ENDPOINTS_IPV4) {
	    endpoint_count = objs[i].u.p2mp_endpoints_ipv4.subcount;
	} else {
	    endpoint_count = 1;
	}

	if(p2mp_flag) {
	    struct pccd_rpd_lsp_info *p2p_lsp_exist = NULL;
	    snprintf(info.p2mp_name, sizeof(info.p2mp_name), "%s", p2mp_name);

	    p2mp_lsp = pccd_get_p2mp_lsp_by_name(info.p2mp_name);
	    if ((p2mp_lsp) && (p2mp_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED)) {
                    TRACE_PCEP(dtfo, "PCE: '%s' cannot create P2MP LSP(%s) - locally provisioned P2MP LSP name exists",
                               pce->pc_pce.pce_id, info.p2mp_name);
                    LOGGING_ERR("PCE: '%s' cannot create P2MP LSP(%s) - locally provisioned P2MP LSP name exists",
                               pce->pc_pce.pce_id, info.p2mp_name);
		pccd_send_error_with_srp(pce->pc_conn, srp_id,
					 PCEP_ERR_TYPE_RIP, PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);
		goto next_message;
	    }

	    /* Search all p2p lsp's with p2mp name if exist report error to PCE */
	    p2p_lsp_exist = pccd_rpd_get_lsp_by_name(info.p2mp_name);
	    if (p2p_lsp_exist) {
                    TRACE_PCEP(dtfo, "PCE: '%s' cannot create P2MP LSP(%s) - P2P LSP name exists",
                               pce->pc_pce.pce_id, info.p2mp_name);
                    LOGGING_ERR("PCE: '%s' cannot create P2MP LSP(%s) - P2P LSP name exists",
                               pce->pc_pce.pce_id, info.p2mp_name);
		pccd_send_error_with_srp(pce->pc_conn, srp_id,
					 PCEP_ERR_TYPE_RIP,
                                         PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);

		goto next_message;
	    }

	    if ((p2mp_lsp) && (SRP_ID_RESV1 != p2mp_lsp->mbb_id) &&
		(srp_id != p2mp_lsp->mbb_id)) {
	        TRACE_PCEP(dtfo, "SRP ID do not match in fragmented packets");
		/* send internal error */
		pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_PCCREATE,
                                         PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);

		goto next_message;
	     }
        vec_plsp_id = p2mp_lsp ? p2mp_lsp->plsp_id : 0;
	} else {
	    struct pccd_p2mp_lsp_info *p2mp_lsp_exist = NULL;

	    snprintf(name_rec, sizeof(name_rec), "%s", symbolic_name);

	    /* Search p2mp lsp with p2p name if exist report error to PCE */
	    p2mp_lsp_exist = pccd_get_p2mp_lsp_by_name(name_rec);
	    if (p2mp_lsp_exist) {
                    TRACE_PCEP(dtfo, "PCE: '%s' cannot create P2P LSP(%s) - P2MP LSP name exists",
                               pce->pc_pce.pce_id, name_rec);
                    LOGGING_ERR("PCE: '%s' cannot create P2P LSP(%s) - P2MP LSP name exists",
                               pce->pc_pce.pce_id, name_rec);
		pccd_send_error_with_srp(pce->pc_conn, srp_id,
					 PCEP_ERR_TYPE_RIP,
                                         PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);

		goto next_message;
	    }
	}

    fs_obj_cnt = pccd_core_pccreate_validate_fs_obj(pce, &objs[i], (count - i), 
                        &fs_obj_start, &err_type, &err_value, vec_plsp_id);
    if (fs_obj_cnt < 0) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot create LSP(%s) - FS obj validation failed",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                             err_type, err_value);
        goto next_message;
    }
            
    if (fs_obj_cnt > 0 && (!pce->pc_pce.pce_flowspec_capability)) {
        TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        LOGGING_ERR("PCE: '%s' cannot create LSP(%s) - FS capability not supported",
                   pce->pc_pce.pce_id, name_rec);
        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 PCEP_ERR_TYPE_NSO,
                                 PCEP_ERR_VAL_OBJECT_CLASS);
        goto next_message;
    }

    /**
     * tmp_lv_fs_info_head will be populated with dest-prefix flowspec info if
     * any coming in pc initiate and all the prefixes will be added to
     * tmp_lsp_prefix_tree_root and later will be moved to
     * lsp_vec->lv_flowspec_info_head and rpd_lsp->prefix_root resepctively.
     *
     * Reason: These 2 holders are created here cause at this point while parsing
     * pc initiate rpd_lsp and lsp_vec doesn't exist, it will be created after
     * sending pcupdate to rpd so these two holders are created here and later
     * moved to actual tree root and lv_fs_head.
     *
     */
    memset(&tmp_lv_fs_info_head, 0, sizeof(struct pccd_flowspec_info_head));

    fs_obj_start += i; /* Move fs object start to correct index */

	lcs_info = xmalloc(sizeof(rpd_extctrl_lsp_config_status_info_t) * endpoint_count);
	memset(lcs_info, 0, (sizeof(rpd_extctrl_lsp_config_status_info_t) * endpoint_count));

	memset(&intended_attrs, 0, sizeof(lsp_intended_attr_t));

    if (p2mp_flag) {
    handled_objects = pccd_core_parse_lsp_instantion(pce, &info, lcs_info,
                                                         &objs[i], (count - i), srp_id,
                                                         &intended_attrs,
                                                         NULL,
                                                         NULL);
    } else {
    tmp_lsp_prefix_tree_root = PCCD_RADIX_ROOT_INIT(NULL);
    SLIST_INIT(&tmp_lv_fs_info_head);

    handled_objects = pccd_core_parse_lsp_instantion(pce, &info, lcs_info,
                                                         &objs[i], (count - i), srp_id,
                                                         &intended_attrs,
                                                         &tmp_lv_fs_info_head,
                                                         tmp_lsp_prefix_tree_root);
    }

	if (handled_objects <= 0) {
	    LOGGING_ERR("Error while paring LSP ERO, LSPA, BW,Assoc or Metric obj in PCInitiate msg.");

	    if (lcs_info) {
		free(lcs_info);
		lcs_info = NULL;
	    }

        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);

	    goto next_message;
	}

	i = i + (unsigned int)handled_objects;

        if ((p2mp_lsp) && (SRP_ID_RESV1 != p2mp_lsp->mbb_id)) {
	    /* validate attributes */
            if (!pccd_core_compare_p2mp_attrib(&info, p2mp_lsp)) {
                TRACE_PCEP(dtfo, "attributes are not matching in consecutive fragmented initiate msg");
                /* send internal error */
                pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_PCCREATE,
                                         PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
                if (lcs_info) {
                    free(lcs_info);
                    lcs_info = NULL;
                }

		goto next_message;
	    }
	}

	vec_plsp_id = 0;

	for (j = 0; j < endpoint_count; j++) {
	struct pccd_rpd_lsp_info *rpd_lsp_exist = NULL;
	char *lsp_name = NULL;
	char *path_name = NULL;
	char *path_priority = NULL;
	struct pccd_rpd_lsp_info *rpd_lsp_created = NULL;
	char name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE+1)];

	char *tok, *cp;
	tok = NULL;
	cp = NULL;

	if(p2mp_flag) {
            if(!pccd_core_get_p2mp_branch_name(&lcs_info[j], name_rec)) {
                 /* Fixme : get proper error for this scenario */
                 pccd_send_error_with_srp(pce->pc_conn, srp_id,
                     PCEP_ERR_TYPE_RIP, PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);

                 free(lcs_info);
                 lcs_info = NULL;

                 goto next_message;
             }
	}

	/* Check if LSP with this name doesn't exist */
	rpd_lsp_exist = pccd_rpd_get_lsp_by_name(name_rec);
	if (rpd_lsp_exist) {
	    struct lsp_vector *lsp = NULL;
	    /* LSP already exists */
	    if (p2mp_flag) {
	        if ((!BIT_ISSET(rpd_lsp_exist->path_flags, LSP_PATH_TYPE_P2MP)) ||
                    (NULL == rpd_lsp_exist->p2mp_lsp) ||
                    (p2mp_lsp != rpd_lsp_exist->p2mp_lsp)) {

                    TRACE_PCEP(dtfo, "PCE: '%s' cannot create P2MP Sub-LSP(%s) - P2P LSP name exists",
                               pce->pc_pce.pce_id, name_rec);
                    LOGGING_ERR("PCE: '%s' cannot create P2MP Sub-LSP(%s) - P2P LSP name exists",
                                pce->pc_pce.pce_id, name_rec);

		    if (p2mp_lsp) {
			struct pccd_rpd_lsp_info *rpd_lsp_orphan= NULL;
			struct pccd_rpd_lsp_info *tmp_lsp_orphan = NULL;
			SLIST_FOREACH_SAFE(rpd_lsp_orphan, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp_orphan) {
			    rpd_lsp_orphan->is_orphan = true;
			}
		    }

		    pccd_send_error_with_srp(pce->pc_conn, srp_id,
					     PCEP_ERR_TYPE_PCCREATE,
                                             PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);

		    pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);
		    find_next_srp = true;
		    break;
		}
	    } else {
		if (BIT_ISSET(rpd_lsp_exist->path_flags, LSP_PATH_TYPE_P2MP)) {
                            TRACE_PCEP(dtfo, "PCE: '%s' cannot create P2P LSP(%s) - P2MP Sub-LSP name exists",
                                       pce->pc_pce.pce_id, name_rec);
                            LOGGING_ERR("PCE: '%s' cannot create P2P LSP(%s) - P2MP Sub-LSP name exists",
                                       pce->pc_pce.pce_id, name_rec);
		    pccd_send_error_with_srp(pce->pc_conn, srp_id,
					     PCEP_ERR_TYPE_RIP,
                                             PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);

		    pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);

            /* Delete temporary data structure created for lsp prefix info */
            pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                                tmp_lsp_prefix_tree_root);
		    find_next_srp = true;
		    break;
		}
	    }

	    /* retrieve our internal lsp object */
	    lsp = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp_exist->id);
            if (lsp == NULL) {
		LOGGING_ERR("Could not retrieve LSP in internal list");
		pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);

        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);
		find_next_srp = true;
		break;
	    }

	    if (evTestID(lsp->lv_lsp_cleanup_tid)) {
		if (!p2mp_flag) {
		    /* Check for different endpoints: existing LSP <-> PCCreate msg*/
		    bool is_endpoint_same = true;
		    if (!rpd_lsp_exist->is_lsp_src_dst_addr_type_ipv6) {
		        if ((lcs_info[j].srcaddr_u.v4 != rpd_lsp_exist->srcaddr.v4) ||
		                    (lcs_info[j].dstaddr_u.v4 != rpd_lsp_exist->dstaddr.v4)) {
		            is_endpoint_same = false;
		        }
		    } else {
		        if (memcmp(lcs_info[j].srcaddr_u.v6, rpd_lsp_exist->srcaddr.v6, 16) ||
		            memcmp(lcs_info[j].dstaddr_u.v6, rpd_lsp_exist->dstaddr.v6, 16)) {
		            is_endpoint_same = false;
		        }
		    }

		    if (!is_endpoint_same) {
			TRACE_PCEP(dtfo, "Endpoints differs in existed LSP and PCCreate message");
			pccd_send_error_with_srp(pce->pc_conn, srp_id,
						 PCEP_ERR_TYPE_PCCREATE,
                                                 PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);

			pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);

            /* Delete temporary data structure created for lsp prefix info */
            pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                                tmp_lsp_prefix_tree_root);
			find_next_srp = true;
			break;
		    }
		    /* LSP has cleanup timer, delegate to this pce */
		    pccd_core_clear_lsp_cleanup_tid(lsp);
		    TRACE_CORE("Stopped IdleTimer for lsp cleanup timeout of LSP id: %u",
			       lsp->lv_lsp_id);

		    pccd_core_lsp_transfer(lsp->lv_pce, pce, lsp);
		    lsp->lv_want_to_delegate = true;
		    lsp->lv_ack_delegated = true;
		    lsp->lv_pce = pce;
		    pccd_core_report_lsp(pce, rpd_lsp_exist, true, true,
					 srp_id, OLD_LEAVE_MUST_UNCHAGED, false);
		} else {
		    if (lsp->lv_pce != pce) {
			pccd_core_lsp_transfer(lsp->lv_pce, pce, lsp);
			lsp->lv_pce = pce;
		    }

		    lsp->lv_want_to_delegate = true;
		    lsp->lv_ack_delegated = true;
		    rpd_lsp_exist->is_orphan = false;

		    if ((!fragmented) && (j == (endpoint_count - 1))) {
                        pccd_core_pccreate_map_fs_to_lsp(lsp->lv_lsp_id,
                                                         &objs[fs_obj_start],
                                                         fs_obj_cnt, true);

			pccd_core_p2mp_lsp_cleanup(lsp, srp_id);
		    }
		}

		TRACE_PCEP(dtfo, "PCE: '%s' now has claimed provisioned LSP with lsp_name '%s' "
			"path_name '%s'"
			   "id: %d", pce->pc_pce.pce_id,
			    rpd_lsp_exist->lsp_name, rpd_lsp_exist->path_name, rpd_lsp_exist->id);

        if (!p2mp_flag) {
            pccd_core_pccreate_map_fs_prefix_to_lsp(rpd_lsp_exist, &tmp_lv_fs_info_head,
                                            tmp_lsp_prefix_tree_root);
        }

		pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, j, j);
		continue;
	    } else {
		TRACE_PCEP(dtfo, "PCE: '%s' cannot create LSP(%s) - name exists",
		           pce->pc_pce.pce_id, name_rec);
                        LOGGING_ERR("PCE: '%s' cannot create LSP(%s) - name exists",
                                    pce->pc_pce.pce_id, name_rec);

		if (!p2mp_flag) {
		    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_RIP,
                                             PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE);
            /* Delete temporary data structure created for lsp prefix info */
            pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                                tmp_lsp_prefix_tree_root);
		} else {
		    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                             PCEP_ERR_TYPE_PCCREATE,
                                             PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM);
		}

		pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);
		find_next_srp = true;
		break;
	    }
	}

	/* Check for max provisioning lsps limit */
	if (pccd_provisioned_lsps.limit > 0) {
	    if (pccd_provisioned_lsps.counter >= pccd_provisioned_lsps.limit) {
		/* max number of provisioned lsps reached */
		TRACE_PCEP(dtfo, "Maximum limit Provisioned LSPs reached");
		pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                         PCEP_ERR_TYPE_INVALID_OPERATION,
                                         PCEP_ERR_VAL_PCE_EXCEED_RES_LIMIT);

        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);
        free(lcs_info);
        lcs_info = NULL;

        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);

        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	    }

	    pccd_core_provisioned_lsps_increase_counter();
	}

	TRACE_PCEP(dtfo, "Creating LSP name: '%s'",  name_rec);

	cp = strdup(name_rec);
	tok = strtok(cp,"/");
	lsp_name = tok;

	tok = strtok(NULL,"/");
	if(tok) {
	    path_name = tok;
	    tok = strtok(NULL,"/");
	    if(tok) {
		path_priority = tok;
	    }
	}
	TRACE_PCEP(dtfo, "Got LSP name: '%s', Path name: '%s' and priority: '%s'",
		   lsp_name, path_name, path_priority);

	bzero(lcs_info[j].name, sizeof(lcs_info[j].name));
	bzero(lcs_info[j].path_name, sizeof(lcs_info[j].path_name));
	snprintf(lcs_info[j].name, sizeof(lcs_info[j].name), "%s", lsp_name);
	if(path_name) {
	    snprintf(lcs_info[j].path_name, sizeof(lcs_info[j].path_name), "%s", path_name);
	}

	if(path_priority)
	    lcs_info[j].path_priority = (u_int32_t)atoi((const char*)path_priority);

	/*Free the memory allocated by strdup*/
	free (cp);

    /**
     * Temporary workaround till sr multi-segment RLI is implemented
     * Send Error if multiple PCE-Init subcandidate paths/Candidate paths are
     * created with same SR policy and candidate path identifiers
     * except preference.
     * . Currently only 1 PCE-Init candidate path can be created for a
     *    specific tuple of (color,end-point,proto-origin,originator ip,asn)
     * . Multiple PCE-Init sub-candidate paths cannot be configured
     */
    if (pccd_rpd_handle_pce_init_sr_cpath (&lcs_info[j])) {
        TRACE_RPD("SR color LSP is already present with same/similar identifiers: '%s'", lcs_info[j].name);

        pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_PCCREATE,
                                     PCEP_ERR_VAL_INTERNAL_ERROR);

        pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);
        free(lcs_info);
        lcs_info = NULL;

        goto next_message;
    }
    lcs_info[j].max_segment_list = pcep_get_remote_max_segment_list(pce->pc_conn);

	if (!pccd_rpd_pccreate(&lcs_info[j])) {
	    TRACE_PCEP(dtfo, "Could not send PCCreate to RPD");
	    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_PCCREATE,
                                     PCEP_ERR_VAL_INTERNAL_ERROR);

	    pccd_core_rpd_extctrl_lcs_info_cleanup(lcs_info, 0, endpoint_count - 1);
	    free(lcs_info);
	    lcs_info = NULL;

        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);

	    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	}
	lcs_info[j].ero_info = NULL;
    lcs_info[j].srte_ero_info = NULL;
	bzero(name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));

	if(strlen(lcs_info[j].path_name)) {
	    snprintf(name, sizeof(name), "%s/%s", lcs_info[j].name, lcs_info[j].path_name);
	    TRACE_RPD("LSP '%s'", name);
	} else {
	    snprintf(name, sizeof(name), "%s", lcs_info[j].name);
	    TRACE_RPD("LSP '%s'", name);
	}
	TRACE_RPD("LSP '%s'", name);

	rpd_lsp_created = pccd_rpd_get_lsp_by_name(name);
	if (!rpd_lsp_created) {
	    LOGGING_ERR("Created LSP '%s' not found in LSP tree", lcs_info[j].name);
	    pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                     PCEP_ERR_TYPE_PCCREATE,
                                     PCEP_ERR_VAL_INTERNAL_ERROR);
	    free(lcs_info);
	    lcs_info = NULL;

        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);

	    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	} else if ((p2mp_flag) && (!p2mp_lsp)) {
	    p2mp_lsp = rpd_lsp_created->p2mp_lsp;
	}
	pccd_rpd_update_instance(rpd_lsp_created, LAST_PC_UPD_CRT);
	pccd_core_store_lsp(pce, rpd_lsp_created->id, srp_id, true,
	p2mp_flag ? LSP_VECTOR_P2MP_EXTERNALLY_PROV : LSP_VECTOR_P2P);
	TRACE_PCEP(dtfo, "PCE: '%s' created provisioned LSP with lsp_name '%s' path_name '%s'"
		    "id: %d", pce->pc_pce.pce_id,
		    rpd_lsp_created->lsp_name, rpd_lsp_created->path_name, rpd_lsp_created->id);

        pccd_core_copy_intended_attributes(&intended_attrs, rpd_lsp_created);
    vec_plsp_id = rpd_lsp_created->id;

        if (!p2mp_flag) {
            pccd_core_pccreate_map_fs_prefix_to_lsp(rpd_lsp_created, &tmp_lv_fs_info_head,
                                            tmp_lsp_prefix_tree_root);
        }
	}

    /* Error case: cleaning up memory allocated */
    if (!p2mp_flag && endpoint_count == 0) {
        /* Delete temporary data structure created for lsp prefix info */
        pccd_core_tmp_prefix_data_cleanup(&tmp_lv_fs_info_head,
                            tmp_lsp_prefix_tree_root);
    }

	if (find_next_srp) {
	    if (lcs_info) {
		free(lcs_info);
		lcs_info = NULL;
	    }
	    goto next_message;
	}

    if (p2mp_flag) {
        pccd_core_pccreate_map_fs_to_lsp(vec_plsp_id, &objs[fs_obj_start],
                           fs_obj_cnt, false);
    }

        if (p2mp_flag) {
            p2mp_lsp = NULL;
            p2mp_lsp = pccd_get_p2mp_lsp_by_name(symbolic_name);
            if (!p2mp_lsp) {
                TRACE_CORE("Can not find P2MP LSP %s", symbolic_name);
            } else {
                /* store attributes */
                pccd_core_store_p2mp_attrib(&info, p2mp_lsp);

                if (fragmented) {
                    if (!evTestID(p2mp_lsp->msg_fragment_tid)) {
                        if (evSetTimer(pccd_core_ev_ctx, pccd_core_p2mp_frag_inst_timer_cb,
                                       p2mp_lsp, evAddTime(evNowTime(),
                                       evConsTime(120, 0)),
                                       evConsTime(0,0), &p2mp_lsp->msg_fragment_tid) == -1) {
                            LOGGING_ERR("evSetTimer failed");
                            exit(EX_SOFTWARE);
                        }
                        TRACE_CORE("Fragmentation timer set for LSP '%s' with value %d [s]",
                                  symbolic_name, 120);
                    }
                    p2mp_lsp->mbb_id = srp_id;
                } else {
                    if (evTestID(p2mp_lsp->msg_fragment_tid)) {
                        evClearTimer(pccd_core_ev_ctx, p2mp_lsp->msg_fragment_tid);
                        evInitID(&p2mp_lsp->msg_fragment_tid);
                        TRACE_CORE("Stopped Fragmentation timer for P2MP LSP id: %u",
                                                    p2mp_lsp->plsp_id);
                    }
                    p2mp_lsp->mbb_id = SRP_ID_RESV1;
                }
            }
        }

        if (lcs_info) {
            free(lcs_info);
            lcs_info = NULL;
        }
next_message:
        i = pccd_core_find_next_srp(objs, i, count);
        if (i >= count) {
            TRACE_CORE("Reached end of PCCreate list");
            TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
        }
        continue;
    }

    if (lcs_info) {
        free(lcs_info);
        lcs_info = NULL;
    }

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

static void
pccd_pcep_onmessage_cb(struct pcep *pcep UNUSED, void *ctx,
                       struct pcep_conn *conn, pcep_conn_state_t state,
                       pcep_msg_t msg_type, const struct pcep_object *objs,
                       size_t count)
{
    struct pce_cfg_core *pce = NULL;
    daemon_trace_file_options_t *dtfo = NULL;

    TRACE_FUNCTION_ENTRY();

    /* Find the PCE this message belongs to */
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce->pc_conn == conn) {
            break;
        }
    }
    INSIST_ERR(pce != NULL);

    dtfo = pccd_core_pce_get_traceoptions(pce);

    TRACE_PCEP(dtfo, "onmessage objp: %p objc: %d msg_type:%d pce:'%s'", objs,
               count, msg_type, pce->pc_pce.pce_id);
    if (!ctx) {
        LOGGING_ERR("Received on_message event form libpcep but pcep_conn "
                "pointer was empty - can't handle PCEP message");
        TRACE_FUNCTION_RETURN();
    }
    if (pccd_add_msg_rate() == true) {
        pcep_temporary_ignore_close();
        TRACE_FUNCTION_RETURN();
    }

    if (state != PCEP_CONN_SESSIONUP) {
        /* PCCD receives messages from session negotiation. Don't process
         * them until the PCE session is in UP state */
        TRACE_PCEP(dtfo, "PCEP connection is not in sessionup state but: %d", state);
        TRACE_FUNCTION_RETURN();
    }

    switch (msg_type) {
    case PCEP_MSG_OPEN:
    case PCEP_MSG_KEEPALIVE:
        LOGGING_INFO("PCCD received message '%s' from libpcep",
                    msg_type == PCEP_MSG_OPEN ?
                            "PCEP_MSG_OPEN" : "PCEP_MSG_KEEPALIVE");
        break;
    case PCEP_MSG_PC_REQUEST:
        LOGGING_ERR("PCReq received from PCE");
        break;
    case PCEP_MSG_PC_REPLY:
        if (!pccd_add_timed_stat( &pce->pc_statistics.pc_reps)) {
	    LOGGING_ERR("Adding timed stat for PCRep failed");
	}
        LOGGING_ERR("PCRep UNIMPLEMENTED");
        break;
    case PCEP_MSG_NOTIFICATION:
        LOGGING_ERR("PCNtf UNIMPLEMENTED");
        break;
    case PCEP_MSG_ERROR:
        LOGGING_ERR("PCErr UNIMPLEMENTED");
        break;
    case PCEP_MSG_CLOSE:
        {
            struct pce_cfg_core *new_pce = NULL;
            LOGGING_INFO("PCClose received from PCE. Switching to new main PCE");
            new_pce = pccd_core_select_new_main_pce(pce);
            INSIST_ERR(new_pce != NULL);
            TRACE_PCEP(dtfo, "PCClose received from PCE: '%s', switching to new PCE: '%s'",
                       pce->pc_pce.pce_id, new_pce->pc_pce.pce_id);
            if (pccd_core_set_new_main_pce (new_pce)) {
                LOGGING_ERR("Unable to set new main pce");
            }
            break;
        }
    case PCEP_MSG_PC_UPDATE:
        if (pccd_add_upd_rate() == true) {
            TRACE_FUNCTION_RETURN();
        }
        if (!pccd_add_timed_stat(&pce->pc_statistics.pc_updates)) {
            LOGGING_ERR("Adding timed stat for PCUpd failed");
        }
        if (pccd_core_received_pcupdate(pce, objs, count)) {
            TRACE_PCEP(dtfo, "Handling of PCUpdate failed");
            TRACE_FUNCTION_RETURN();
        }
        break;
    case PCEP_MSG_PC_REPORT:
        LOGGING_ERR("PCRpt received from PCE");
        break;
    case PCEP_MSG_PC_CREATE:
        if (!pccd_add_timed_stat(&pce->pc_statistics.pc_creates)) {
            LOGGING_ERR("Adding timed stat for PCUpd failed");
        }
        if (pccd_core_received_pccreate(pce, objs, count)) {
            TRACE_PCEP(dtfo, "Handling of PCCreate failed");
            TRACE_FUNCTION_RETURN();
        }
        break;
    default:
        LOGGING_ERR("Unknown PCEP message type: %d", msg_type);
        pcep_send_pcerr(pce->pc_conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        break;
    }

    TRACE_FUNCTION_EXIT();
}

/* NSR Begin */
void
pccd_core_return_control(const struct pccd_rpd_lsp_info *rpd_lsp)
{
    if (!pccd_nsr_master()) {
        return;
    }

    if (rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED) {
        if (!pccd_rpd_lsp_return_control(rpd_lsp)) {
            LOGGING_ERR("Failed to return control of LSP with lsp_name '%s' path_name '%s' to RPD",
                      rpd_lsp->lsp_name, rpd_lsp->path_name);
        }
    }
}
/* NSR End */

static void
pccd_core_rpd_state_change_cb(bool up)
{
    struct pce_cfg_core *pce = NULL;
    boolean is_master;

    TRACE_FUNCTION_ENTRY();
    TRACE_CORE("pccd_rpd subsystem reports state as %s", up ? "up" : "down");
    
    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_FUNCTION_RETURN();
    }

    /* NSR Begin */
    is_master = pccd_nsr_master();
    /* NSR End */
    if (up) {
        if (SLIST_EMPTY(&pce_cfg_head)) {
            TRACE_CORE("No PCEs configured, doing nothing");
            TRACE_FUNCTION_RETURN();
        }
		/* NSR Begin */
        pccd_core_connect_all_pces();
		/* NSR End */
        pce = pccd_core_get_main_pce();
        INSIST_ERR(pce != NULL);
        if (pce->pc_state > PCE_STATE_CONNECTED &&
                pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE) {
            if (!pccd_rpd_lsp_get_control_all()) {
                LOGGING_WAR("Failed to set external controller control "
                        "for all LSPs");
            }
            if (!pccd_rpd_get_all_lsps()) {
                LOGGING_WAR("Failed to request all LSPs");
            }
        }
        /* NSR Begin */
        /* incase of backup, query all lsp from rpd always */
        if (!is_master) {
            if (!pccd_rpd_get_all_lsps())
                LOGGING_WAR("Failed to request all LSPs");
        }
        /* NSR End */
    } else { /* rpd conn down */
        /* Connection with RPD has failed, clear all LSPs from locapccd_core_lsp_added_cbl cache */
        SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
            if (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATELESS) {
                continue;
            }
            if (pce->pc_state == PCE_STATE_SYNC) {
                TRACE_CORE("RPD is down during SYNC state");
                pcep_send_pcerr(pce->pc_conn, PCEP_ERR_TYPE_SYNC_ERR,
                                PCEP_ERR_VAL_PCC_SYNC_ERR);
                pccd_core_pce_disconnect(pce);
                continue;
            }
            if (pce->pc_state < PCE_STATE_UP) {
                pccd_core_pce_disconnect(pce);
                continue;
            }
            LOGGING_ERR("Connection with RDP has failed. Closing the PCE connections");
            TRACE_CORE("Connection with RDP has failed. Closing the PCE connections");

            pccd_core_pce_disconnect(pce);
            pccd_core_pce_connect(pce);
        }
        pccd_core_delete_all_lsps();
    }
    TRACE_FUNCTION_EXIT();
}

static void
pccd_core_lsp_added_cb(const struct pccd_rpd_lsp_info *rpd_lsp, bool last)
{
    boolean is_notify = FALSE;
    struct pce_cfg_core *pce = NULL;
    uint8_t vec_type;

    TRACE_FUNCTION_ENTRY();
    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_CORE("new LSP addded with lsp_name '%s' path_name '%s';no PCEs configured, ignoring",
                   rpd_lsp->lsp_name, rpd_lsp->path_name);
        /* Return control of the LSP, because we don't have connection to any
         * PCE at the moment.
         */
        pccd_core_return_control(rpd_lsp);
        TRACE_FUNCTION_RETURN();
    }
    TRACE_CORE("new LSP addded with lsp_name '%s' path_name '%s'", rpd_lsp->lsp_name, 
		rpd_lsp->path_name);
    /* Store the LSP */
    pce = pccd_core_get_main_pce();
    vec_type = LSP_VECTOR_P2P;
    if ((rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP) == LSP_PATH_TYPE_P2MP) {
        vec_type = (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) 
            ? LSP_VECTOR_P2MP_EXTERNALLY_PROV : LSP_VECTOR_P2MP_CLI_REGULAR;
    }

    /* NSR Begin */
    bool created = (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED);
    pccd_core_store_lsp(pce, rpd_lsp->id, SRP_ID_RESV1, created, vec_type);
    /* NSR End */

    struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
    /* Prefix over flowspc is only supported for P2P LSP currently */
    if (lsp_vec->lv_type == LSP_VECTOR_P2P) {
        /**
         * Since lsp vector is just created now so we need to create flowspec
         * for lsp prefixes if exists any so set the flag
         */
        lsp_vec->lv_need_to_create_fs = true;
        pccd_core_update_flowspec_prefix(rpd_lsp, lsp_vec, &is_notify);
    }

    if (pce->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_STATEFULACTIVE ||
            pce->pc_state < PCE_STATE_SYNC ) {
        /* If the connection status with the main PCE is not at least in SYNC
         * state we can't delegate the LSP, therefore return control to RPD if
         * we have it. This also applies if the main pce is not ACTIVE.
         */
        /* release control only if delegation clean up timer is not running.
        If delegation clean up timer is running already, will take care of 
        returning control to rpd */
        if (!evTestID(pce->pc_delegation_cleanup_tid)) {
            pccd_core_return_control(rpd_lsp);
        } else {
            TRACE_CORE("delegation cleanup timer is running");
        }
    }

    /*
     * Start lsp cleanup timer for provisioned LSP
     */
    if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
        struct lsp_vector *lsp = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        if (lsp==NULL) {
            LOGGING_ERR("Could not retrieve LSP in internal list");
            TRACE_FUNCTION_RETURN();
        }

        if (lsp->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
            struct pccd_rpd_lsp_info *rpd_lsp_exist = NULL;
            char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];

            pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                rpd_lsp->lsp_name, rpd_lsp->path_name);
            rpd_lsp_exist = pccd_rpd_get_specific_lsp(lsp_full_name, SETUP_TYPE_RSVP,
                            RSVP_P2MP_LEAF);
            if (rpd_lsp_exist) {
                rpd_lsp_exist->is_orphan = true;
            }

            /* Attach flowspec info to lsp vec */
            pccd_core_move_tmp_fs_to_lsp_vec(rpd_lsp->p2mp_lsp, lsp);
        }
        
        if (!evTestID(lsp->lv_lsp_cleanup_tid)) {
            /* NSR Begin */
            /*
             * Start lsp cleanup timer. Default value is 60 seconds
             */
            pccd_core_start_lsp_cleanup_tid(pce, lsp);
            /* NSR End */
        }
        pccd_core_provisioned_lsps_increase_counter();
    }

    /* Notify PCEs about the new LSP */
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
        if (pce->pc_state > PCE_STATE_CONNECTED &&
                (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
                 pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE)) {
            pccd_core_report_lsp(pce, rpd_lsp, last,
                                 pce->pc_state >= PCE_STATE_SYNC, SRP_ID_RESV1,
                                 NEW_LEAVES_TO_ADD, false);
        }
    }

    /* NSR Begin */
    pccd_repl_handle_update_lsp(rpd_lsp);
    /* NSR End */

    TRACE_FUNCTION_EXIT();
}

/* An LSP was deleted, and information about that action is being sent to PCCD
 * via this function. PCCD needs to clear state for that LSP -> find PCE that
 * this LSP belongs to, and remove the LSP from list of LSPs for that PCE.
 */
static void
pccd_core_lsp_deleted_cb(const struct pccd_rpd_lsp_info *rpd_lsp)
{
    struct lsp_vector *lsp_vec = NULL;

    TRACE_FUNCTION_ENTRY();
    TRACE_CORE("LSP deleted with lsp_name '%s' path_name '%s'", rpd_lsp->lsp_name,
        rpd_lsp->path_name);

    if (SLIST_EMPTY(&pce_cfg_head)) {
        INSIST_ERR(patricia_isempty(pccd_lsp_vector_root_id));
        TRACE_FUNCTION_RETURN();
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
    if (lsp_vec) {
        struct pce_cfg_core *pce_tmp = NULL;
        struct pce_cfg_core *temp = NULL;
        struct pce_cfg_core *pce = lsp_vec->lv_pce;
        daemon_trace_file_options_t *dtfo;
        dtfo = pccd_core_pce_get_traceoptions(pce);
        TRACE_PCEP(dtfo, "Found cached LSP id: %d in pce '%s'", rpd_lsp->id,
                   pce->pc_pce.pce_id);
        INSIST_ERR(lsp_vec->lv_pce != NULL);

        SLIST_FOREACH_SAFE(pce_tmp, &pce_cfg_head, pc_next, temp) {
            if (PCE_IS_STATEFUL(pce_tmp)) {
                if (pce_tmp->pc_state > PCE_STATE_CONNECTED) {
                    if (lsp_vec->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
                        pccd_core_report_deleted_lsp(pce_tmp, rpd_lsp, SRP_ID_RESV1);
                    } else {
                        /* Use the SRP id stored in lsp_vec */
                        pccd_core_report_lsp(pce_tmp, rpd_lsp, true,
                            pce_tmp->pc_state >= PCE_STATE_SYNC, lsp_vec->srp_id,
                            OLD_LEAVES_TO_REMOVE, false);
                        // Reset SRP ID after sending report
                        lsp_vec->srp_id = SRP_ID_RESV1;
                    }
                } else {
                    TRACE_PCEP(dtfo, "PCE '%s' is currently in state %s, can't send"
                               " PCRpt messages", pce_tmp->pc_pce.pce_id,
                               pccd_core_get_pce_state_str(pce_tmp->pc_state));
                }
            }
        }
    } else {
        TRACE_CORE("LSP id: %d not found in local cache", rpd_lsp->id);
        TRACE_FUNCTION_RETURN();
    }

    /* Delete the local cached copy of LSP information */
    if (lsp_vec->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV) {
        pccd_core_delete_lsp(lsp_vec);
    }
    TRACE_FUNCTION_EXIT();
}


/**
 * pccd_core_has_any_spring_pce
 *
 * Check if any pce is spring capable
 *
 * @return true        : if successful
 *         false       : otherwise
 */
bool
pccd_core_has_any_spring_pce (void)
{
    struct pce_cfg_core *pce = NULL;

    // check any pce is spring capable
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {

        if (pccd_core_pce_spring_capability(pce)) {
            return true;
        }
    }

    return false;
}
/**
 * pccd_core_has_any_srv6_pce
 *
 * Check if any pce is srv6 capable
 *
 * @return true        : if successful
 *         false       : otherwise
 */
bool
pccd_core_has_any_srv6_pce (void)
{
    struct pce_cfg_core *pce = NULL;

    // check any pce is srv6 capable
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {

        if (pccd_core_pce_srv6_capability(pce)) {
            return true;
        }
    }

    return false;
}

/**
 * pccd_core_remove_local_sr_lsp_cb
 *
 * Static configured SR LSP is reported only when we have a
 * pce that is spring capable, otherwise it will be removed
 * from local db
 *
 * @param[in] rpd_lsp         : pccd local lsp info
 * @return true        : if LSP need to be deleted
 *         false       : otherwise
 */
static bool
pccd_core_remove_local_sr_lsp_cb (const struct pccd_rpd_lsp_info *rpd_lsp)
{
    struct lsp_vector *lsp_vec = NULL;
    bool pce_found = false;

    TRACE_FUNCTION_ENTRY();


    // bail out if lsp setup type is not spring or type is not local configured
    if (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE ||
        rpd_lsp->type != LSP_TYPE_CLI_REGULAR_SIGNALLED) {
        TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    pce_found = pccd_core_has_any_spring_pce();

    /* 
     * If all pce's are not spring capable, then only remove 
     * the LSP from local db, else keep the LSP
     */
    if (!pce_found) {
        TRACE_CORE("None of the connected PCE is SPRING capable, PCRpt will not be sent");

        lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        if (lsp_vec) {
            TRACE_CORE("Removing LSP ID %d from PCE %p list",
                        lsp_vec->lv_lsp_id, lsp_vec->lv_pce);
            pccd_core_delete_lsp(lsp_vec);
        }
        TRACE_FUNCTION_RETURN(1);
    }

    TRACE_FUNCTION_RETURN(0);
}

/**
 * pccd_core_remove_local_srv6_lsp_cb
 *
 * Static configured SRv6 LSP is reported only when we have a
 * pce that is SRv6 capable, otherwise corresponding lsp_vector will be
 * removed in this function
 * rpd_lsp part of info will be removed in pccd_rpd_remove_local_srv6_lsps
 *
 * @param[in] rpd_lsp         : pccd local lsp info
 * @return true        : if LSP need to be deleted
 *         false       : otherwise
 */
static bool
pccd_core_remove_local_srv6_lsp_cb (const struct pccd_rpd_lsp_info *rpd_lsp)
{
    struct lsp_vector *lsp_vec = NULL;
    bool pce_found = false;

    TRACE_FUNCTION_ENTRY();


    // bail out if lsp setup type is not srv6 or type is not local configured
    if (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE ||
        rpd_lsp->type != LSP_TYPE_CLI_REGULAR_SIGNALLED) {
        TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
    }

    pce_found = pccd_core_has_any_srv6_pce();

    /*
     * If all pce's are not srv6 capable, then only remove
     * the LSP from local db, else keep the LSP
     */
    if (!pce_found) {
        TRACE_CORE("None of the connected PCE is SRv6 capable, PCRpt will not be sent");

        lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        if (lsp_vec) {
            TRACE_CORE("Removing LSP ID %d from PCE %p list",
                        lsp_vec->lv_lsp_id, lsp_vec->lv_pce);
            pccd_core_delete_lsp(lsp_vec);
        }
        TRACE_FUNCTION_RETURN(1);
    }

    TRACE_FUNCTION_RETURN(0);
}

/**
 * LSP got reconfigured, or RPD updated some of its attributes - send PCRpt.
 * This is a callback function registered in pccd_rpd.
 * @param rpd_lsp[in] lsp information from RPD
 * @param last_report[in] flag set to true if this report is the last one in
 *                        sequence. Used in PCEP SYNC phase.
 */
static void
pccd_core_lsp_report_cb(const struct pccd_rpd_lsp_info *rpd_lsp,
                        bool last_report, bool created, boolean is_notify)
{
    struct lsp_vector *lsp_vec = NULL;

    TRACE_FUNCTION_ENTRY();

    if(!rpd_lsp){
	/* Transition the PCE states to UP */
	pccd_core_move_all_pces_to_up();
	return;
    }

    TRACE_CORE("RPD updating params for LSP with lsp_name '%s' path_name '%s'",
		rpd_lsp->lsp_name, rpd_lsp->path_name);
    if (SLIST_EMPTY(&pce_cfg_head)) {
        pccd_core_return_control(rpd_lsp);
        INSIST_ERR(patricia_isempty(pccd_lsp_vector_root_id));
        TRACE_FUNCTION_RETURN();
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
    if (!lsp_vec) {
        TRACE_CORE("LSP with lsp_name '%s' path_name '%s' is not known, "
			"previous lsp_added callback missing", rpd_lsp->lsp_name, rpd_lsp->path_name);
        pccd_core_lsp_added_cb(rpd_lsp, last_report);
    } else if ((evTestID(lsp_vec->lv_lsp_cleanup_tid)) && 
                  (lsp_vec->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV)) {
        TRACE_CORE("P2mp BranchLSP with lsp_name '%s' path_name '%s' is not known, "
			"previous lsp_added callback missing", rpd_lsp->lsp_name, rpd_lsp->path_name);
        pccd_core_lsp_added_cb(rpd_lsp, last_report);
    } else {
        uint32_t srp_id = SRP_ID_RESV1;
        struct pce_cfg_core *pce = NULL;

        /*
         * Update flowspec prefix with latest lsp prefix tree
         * Prefix over flowspc is only supported for P2P LSP currently
         */
        if (lsp_vec->lv_type == LSP_VECTOR_P2P) {
            pccd_core_update_flowspec_prefix(rpd_lsp, lsp_vec, &is_notify);
        }

        if (lsp_vec->srp_id != SRP_ID_RESV1 &&
            !(rpd_lsp->msg_trigger_reason & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN)) {
            srp_id = lsp_vec->srp_id;
            // Reset SRP ID after sending the first response
            // except when msg is old inst delete during MBB
            lsp_vec->srp_id = SRP_ID_RESV1;
        }	
        /*If it is not response of request and is_notify is false, don't report to PCS*/
        if ( srp_id == SRP_ID_RESV1 && !is_notify)    {
            TRACE_CORE(" LSP report ignored as it is duplicate report which was reported ",
                       " earlier: lsp with lsp_name '%s' path_name '%s' deleg: %d",
                       rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->control_status);
            return ;
        }

        if ((rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED) &&
            !lsp_vec->lv_want_to_delegate && !lsp_vec->lv_ack_delegated &&
            lsp_vec->lv_retry_delegation) {
            pccd_core_return_control(rpd_lsp);
        }

        /* Send Flowspec to RPD */
        if ((lsp_vec->lv_type == LSP_VECTOR_P2MP_EXTERNALLY_PROV) && lsp_vec->fs_rpd_pend_upd) {
            pccd_core_send_lsp_fs_update(lsp_vec->lv_lsp_id, 0, false);
        }

        /* Send PCRpt to connected PCEs*/
        SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
            /* check no-advertise-pcc-owned-lsps */
            bool not_advert;
            if (pce->pc_pce.pce_opts.pco_no_advertise_pcc_owned_lsps == true) {
                not_advert = true;
            } else {
                not_advert = false;
            }
            if (pce->pc_state > PCE_STATE_CONNECTED &&
                    (pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
                     pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE)) {
                if (not_advert) {
                    if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED) {
                        pccd_core_report_lsp(pce, rpd_lsp, last_report,
                                             pce->pc_state >= PCE_STATE_SYNC, srp_id,
                                             OLD_LEAVE_MUST_UNCHAGED, false);
                    }
                } else {
                    pccd_core_report_lsp(pce, rpd_lsp, last_report,
                                         pce->pc_state >= PCE_STATE_SYNC || created, srp_id,
                                         OLD_LEAVE_MUST_UNCHAGED, false);
                }
            }
            if (pce->pc_main == true &&
                    (pce->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_STATEFULACTIVE ||
                    pce->pc_state < PCE_STATE_SYNC)) {
                if (!evTestID(pce->pc_delegation_cleanup_tid)) {
                    /* If the current main PCE is not STATEFUL ACTIVE, return
                     * delegation to RPD immediately. Else if the connection is not
                     * in at least STATE_SYNC, return the connection otherwise.
                     * Else, keep the delegation.
                     */
                    pccd_core_return_control(rpd_lsp);
                }
            }
        }
    }

    /* NSR Begin */
    pccd_repl_handle_update_lsp(rpd_lsp);
    /* NSR End */

    TRACE_FUNCTION_EXIT();
}

static void
pccd_core_lsp_deleg_cb(const struct pccd_rpd_lsp_info *rpd_lsp)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();
    TRACE_CORE("LSP delegation changed: lsp with lsp_name '%s' path_name '%s' deleg: %d",
        rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->control_status);
    if (SLIST_EMPTY(&pce_cfg_head)) {
        TRACE_CORE("SLIST EMPTY: lsp with lsp_name '%s' path_name '%s' deleg: %d",
            rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->control_status);
        pccd_core_return_control(rpd_lsp);
        INSIST_ERR(patricia_isempty(pccd_lsp_vector_root_id));
        TRACE_FUNCTION_RETURN();
    }

    pce = pccd_core_get_pce_cfg_lsp_id(rpd_lsp->id);
    INSIST_ERR(pce != NULL);
    INSIST_ERR(pce->pc_main == true);
    if (pce->pc_pce.pce_opts.pco_pce_type != PCE_TYPE_STATEFULACTIVE ||
            pce->pc_state < PCE_STATE_SYNC) {
        TRACE_CORE("LSP '%s' delegation status has changed, but associated "
                   "PCE is not connected.");
        pccd_core_return_control(rpd_lsp);
        TRACE_FUNCTION_RETURN();
    }
    if (pccd_core_report_lsp(pce, rpd_lsp, true,
                             pce->pc_state >= PCE_STATE_SYNC, SRP_ID_RESV1,
                             OLD_LEAVE_MUST_UNCHAGED, false)) {
        LOGGING_ERR("Could not send PCRpt to pce '%s' about lsp id %d with lsp_name '%s' "
			"path_name '%s' control status change to %d", pce->pc_pce.pce_id,
                    rpd_lsp->id, rpd_lsp->lsp_name, rpd_lsp->path_name, rpd_lsp->control_status);
        //FIXME: reconnect PCE/RPD?
    }
    TRACE_FUNCTION_EXIT();
}

static int
pccd_core_lsp_request_cb(const struct pccd_rpd_lsp_info *rpd_lsp UNUSED)
{
    //FIXME: Find PCE responsible for this PCE & send PCReq to the PCE
    //FIXME: If the LSP is not yet stored, report error
    return 0;
}

static int
pccd_core_reg_in_rpd(void)
{
    if (pccd_rpd_reg_state_change(pccd_core_rpd_state_change_cb)) {
        LOGGING_ERR("Failed to register RPD state change callback");
        abort();
    }
    if (pccd_rpd_reg_lsp_added(pccd_core_lsp_added_cb)) {
        LOGGING_ERR("Failed to register LSP change callback");
        abort();
    }
    if (pccd_rpd_reg_lsp_deleted(pccd_core_lsp_deleted_cb)) {
        LOGGING_ERR("Failed to register LSP deleted callback");
        abort();
    }
    if (pccd_rpd_reg_lsp_report(pccd_core_lsp_report_cb)) {
        LOGGING_ERR("Failed to register LSP report callback");
        abort();
    }
    if (pccd_rpd_reg_lsp_deleg_chg(pccd_core_lsp_deleg_cb)) {
        LOGGING_ERR("Failed to register LSP delegation change callback");
        abort();
    }
    if (pccd_rpd_reg_lsp_request(pccd_core_lsp_request_cb)) {
        LOGGING_ERR("Failed to register LSP request callback");
        abort();
    }
    if (pccd_rpd_reg_remove_local_sr_lsp(pccd_core_remove_local_sr_lsp_cb)) {
        LOGGING_ERR("Failed to register LSP SR remove callback");
        abort();
    }
    if (pccd_rpd_reg_remove_local_srv6_lsp(pccd_core_remove_local_srv6_lsp_cb)) {
        LOGGING_ERR("Failed to register LSP SRv6 remove callback");
        abort();
    }

    return 0;
}

int
pccd_core_init(evContext ctx)
{
    pccd_core_ev_ctx = ctx;
    pccd_pcep = pcep_init(ctx, pccd_pcep_log_cb, pccd_pcep_trace_cb,
                          pccd_pcep_onconnect_cb, pccd_pcep_onerror_cb,
                          pccd_pcep_onmessage_cb, NULL);

    if (!pccd_pcep) {
        LOGGING_ERR("pcep_init failed");
        return -1;
    }

    if (pccd_core_reg_in_rpd()) {
        LOGGING_ERR("Registering callback functions with pccd_rpd failed");
        return -1;
    }

    /*
     * Set counter for max provisioned lsps to
     * PCCD_MAX_PROVISIONED_LSPS_DEFAULT 
     */
    pccd_provisioned_lsps.counter = 0;
    pccd_provisioned_lsps.limit = PCCD_MAX_PROVISIONED_LSPS_DEFAULT;


    /*Initilize the patricia foor node of LSPs*/
    if (pccd_lsp_vector_root_id == NULL) {
        pccd_lsp_vector_root_id = patricia_init_root(sizeof(uint32_t));
        assert(pccd_lsp_vector_root_id);
    }
    TRACE_CORE("Initialised pccd_pcep: %p", pccd_pcep);

    return 0;
}

void
pccd_core_disconnect_all_pces()
{
    struct pce_cfg_core *pce = NULL;
    
    TRACE_FUNCTION_ENTRY();
   
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
	pccd_core_pce_disconnect(pce);
	TRACE_CORE("Disconnected PCE: %s", pce->pc_pce.pce_id);
    }

    TRACE_FUNCTION_EXIT();
}

/* NSR Begin */
/* try connecting all pce */
void
pccd_core_connect_all_pces()
{
    struct pce_cfg_core *pce = NULL;
    
    TRACE_FUNCTION_ENTRY();
   
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {        
        if (pce->pc_state == PCE_STATE_NEW) {
	        pccd_core_pce_connect(pce);
	        TRACE_CORE("Connecting PCE: %s", pce->pc_pce.pce_id);
        }
    }

    TRACE_FUNCTION_EXIT();
}
/* NSR End */

void
pccd_core_move_all_pces_to_up()
{
    struct pce_cfg_core *pce = NULL;
    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH(pce, &pce_cfg_head, pc_next) {
	if (pce->pc_state == PCE_STATE_SYNC) {
	    INSIST_ERR(pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFUL ||
                       pce->pc_pce.pce_opts.pco_pce_type == PCE_TYPE_STATEFULACTIVE);
            TRACE_CORE("Sending End of Marker Sync LSP to %s", pce->pc_pce.pce_id);
            pccd_core_report_empty_lsp(pce, SRP_ID_RESV1);
            
	    TRACE_CORE("Moving PCE:%s state to UP",pce->pc_pce.pce_id);
	    pccd_core_pce_transition_state(pce, PCE_STATE_UP);
	}
    }
    TRACE_FUNCTION_EXIT();
}

bool
pccd_core_del_lspvec_senderr (uint32_t lsp_id, bool delete,
                              bool send_err,
			      pccd_pce_err_type_val_t err){

    struct pce_cfg_core *pce = NULL;
    struct lsp_vector *lsp_vec = NULL;
    uint32_t srp_id = 0;

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp_id);
    if (lsp_vec) {
	pce = lsp_vec->lv_pce;
	TRACE_RPD("Found cached LSP id: %d in pce '%s'", lsp_id,
                   pce->pc_pce.pce_id);
	INSIST_ERR(lsp_vec->lv_pce != NULL);
    } else {
	TRACE_RPD("LSP id: %d not found in local cache", lsp_id);
	TRACE_FUNCTION_RETURN(false);
    }

    srp_id = lsp_vec->srp_id;
    if ((delete) && (lsp_vec->lv_type != LSP_VECTOR_P2MP_EXTERNALLY_PROV)) {
        /* Delete the local cached copy of LSP information */
        pccd_core_delete_lsp(lsp_vec);
    }
    /* Send the PCErr message to PCE */
    if(send_err && (pce->pc_state > PCE_STATE_CONNECTED)) {
	pccd_send_error_with_srp(pce->pc_conn, srp_id,
                                 err.pce_err_type, err.pce_err_val);
    }

    TRACE_FUNCTION_RETURN(true);
}

const char *
pccd_core_get_msg_trigger_string (u_int32_t msg_trigger_reason)
{
    switch (msg_trigger_reason){
        case RPD_MSG_REASON_RECONFIGURED:
             return "Reconfig";
        case RPD_MSG_REASON_LSP_RESTARTED:
             return "Lsp restarted";
        case RPD_MSG_REASON_RETRY_PCREQUEST:
             return "Retry pcreq";
        case RPD_MSG_REASON_LSP_MAINTENANCE:
             return "Lsp maintenance";
        case RPD_MSG_REASON_LSP_CTRL_CHANGE:
             return "Lsp ctrl change";
        case RPD_MSG_REASON_LSP_GET_INFO:
             return "Lsp get info";
        case RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN:
             return "Old instance down";
        case RPD_MSG_REASON_LSP_PATH_ACTIVE:
             return "Active";
        case RPD_MSG_REASON_LSP_PATH_DEACTIVE:
             return "Deactive";
        case RPD_MSG_REASON_LSP_PATH_UP:
             return "Up";
        case RPD_MSG_REASON_LSP_PATH_DOWN:
             return "Down";
        case RPD_MSG_REASON_LSP_PATH_REOPTIMIZATION:
             return "Reoptimized";
        case RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW:
             return "New Bw";
        case RPD_MSG_REASON_LSP_PATH_NEW_RRO_CHANGED:
             return "RRO changed";
        case RPD_MSG_REASON_LSP_PATH_STATE_CHANGE:
             return "Lsp state change";
        case RPD_MSG_REASON_LSP_PATH_UPDATE_REQUEST:
             return "Update";
        case RPD_MSG_REASON_LSP_PATH_CSPF_FAILED:
             return "CSPF failed";
        default:
             return NULL;
    }
}

static void
pccd_core_update_pcreport_reason (const struct pccd_rpd_lsp_info *rpd_lsp)
{
    const char *tmp = NULL;
    struct pccd_rpd_lsp_info *lsp = NULL;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    int rpt_index;

    if(!rpd_lsp) {
        return;
    }

    tmp = pccd_core_get_msg_trigger_string (rpd_lsp->msg_trigger_reason);

    if ((!tmp) || (RPT_REASON_SIZE <= strlen(tmp)))
        return;

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
        rpd_lsp->lsp_name, rpd_lsp->path_name);

    lsp = pccd_rpd_get_specific_lsp(
        lsp_full_name, rpd_lsp->name_tree_key.type,
        rpd_lsp->name_tree_key.sub_type);
    if (!lsp) {
        return;
    }
    
    for (rpt_index = 4; rpt_index > 0; rpt_index--) {
        memset(&lsp->rpt_reason[rpt_index], '\0', RPT_REASON_SIZE);
        strncpy(lsp->rpt_reason[rpt_index],lsp->rpt_reason[rpt_index-1], RPT_REASON_SIZE-1);
    }

    memset(&lsp->rpt_reason[0], '\0', RPT_REASON_SIZE);
    strncpy(lsp->rpt_reason[0], tmp, (RPT_REASON_SIZE - 1));

    return;
}

/* Return correct bandwidth string with units as per value */
void
pccd_core_get_bandwidth_str(uint64_t bw_bits, char* bw_str, uint32_t buffer_size)
{
    #define BW_BUFFER 26
 
    char temp[BW_BUFFER] = {0};
    if (bw_bits <= 1000) {
        snprintf(temp, (sizeof(temp) - 1), "%"PRIu64"bps", bw_bits);
    } else {
        if (bw_bits <= 1000000) {
            snprintf(temp, (sizeof(temp) - 1), "%gKbps", (double)bw_bits/1000);
        } else {
            if (bw_bits <= 1000000000) {
                snprintf(temp, (sizeof(temp) - 1), "%gMbps", (double)bw_bits/1000000);
            } else {
                snprintf(temp, (sizeof(temp) - 1), "%gGbps", (double)bw_bits/1000000000);
            }
        }
    }
    strncpy(bw_str, temp, (buffer_size - strlen(bw_str) - 1));
    #undef BW_BUFFER
}

/**
 * pccd_core_pcc_fs_id_alloc
 *
 * Get the next PCC generated FS id
 *
 * @return  generated pcc fs id
 */
uint32_t
pccd_core_pcc_fs_id_alloc(struct pce_cfg_core* pce)
{
    patnode_t* node = NULL;
    do {
        ++pcc_fs_id;
        /**
         * draft-ietf-pce-pcep-flowspec-08 sec 5:
         * Values 0 and 0xFFFFFFFF reserved and must not be used
         */
        if (pcc_fs_id >= PCCD_PCC_FS_ID_MAX) {
            TRACE_CORE("Rolling over PCC created Flowspec Ids");
            pcc_fs_id = 1;
        }
        node = patricia_get(pce->pccd_flowspec_info_root, sizeof(uint32_t), &pcc_fs_id);
    } while(node);

    return pcc_fs_id;
}


/**
 * pccd_core_tmp_prefix_data_cleanup
 *
 * Removing temporary data structures tmp_lv_fs_info_head & tmp_lsp_prefix_tree_root
 * having all prefix info if pccd fails to send message pcupdate to rpd
 *
 * @param[in] tmp_lv_fs_info_head       ptr to temporary lsp vector fs list head
 * @param[in] tmp_lsp_prefix_tree_root  ptr to temprorary rpd_lsp prefix tree root
 */
void
pccd_core_tmp_prefix_data_cleanup(struct pccd_flowspec_info_head  *tmp_lv_fs_info_head,
                    radix_root_t *tmp_lsp_prefix_tree_root)
{
    TRACE_FUNCTION_ENTRY();
    struct pccd_flowspec_info_s *fs_info, *fs_info_tmp;

    SLIST_FOREACH_SAFE(fs_info, tmp_lv_fs_info_head, fs_info_next, fs_info_tmp) {
        TRACE_CORE("Deleted Flowspec FS-ID: %u", fs_info->fs_id);
        if (fs_info->mcast_info) {
            xfree(fs_info->mcast_info);
        } else if(fs_info->dest_pfx_info) {
            pccd_core_fs_delete_all_prefixes(fs_info);
            xfree(fs_info->dest_pfx_info);
        }

        SLIST_REMOVE(tmp_lv_fs_info_head, fs_info, pccd_flowspec_info_s, fs_info_next);
        xfree(fs_info);
    }

    /* Delete all prefix info from tmp_lsp_prefix_tree_root */
    pccd_rpd_lsp_delete_all_prefix_info(tmp_lsp_prefix_tree_root);
    tmp_lsp_prefix_tree_root = NULL;

    TRACE_FUNCTION_EXIT();
}


/**
 * pccd_core_update_flowspec_prefix
 *
 * Update flowspec prefix info with updated lsp prefix tree after processing
 * rpd pcreq_status message
 *
 * @param[in]   rpd_lsp    ptr to rpd lsp info
 * @param[out]  lsp_vec    ptr to lsp vector
 * @param[out]  is_notify  ptr to is_notify, used to indicate if pc report
 *                         need to be sent or not
 */
void
pccd_core_update_flowspec_prefix(const struct pccd_rpd_lsp_info *rpd_lsp,
              struct lsp_vector* lsp_vec, boolean* is_notify)
{
    TRACE_FUNCTION_ENTRY();

    rnode_t* node = NULL;
    lsp_prefix_info_t* entry = NULL;
    struct pccd_flowspec_info_s *fs_info = NULL, *fs_info_tmp = NULL;
    struct pccd_fs_dest_prefix_s *fs_dst_pfx = NULL, *fs_dst_pfx_tmp = NULL;

    SLIST_FOREACH_SAFE(fs_info, &lsp_vec->lv_flowspec_info_head, fs_info_next, fs_info_tmp) {

        if (!fs_info->dest_pfx_info) {
            continue;
        }

        fs_dst_pfx = NULL;
        SLIST_FOREACH_SAFE(fs_dst_pfx, &fs_info->dest_pfx_info->dest_pfx_head,
                  dest_pfx_next, fs_dst_pfx_tmp) {

            entry = pccd_rpd_get_prefix(rpd_lsp->prefix_root,
                            fs_dst_pfx->mask, &fs_dst_pfx->prefix);
            /* If no correponding entry found then need to delete it from fs */
            if (!entry) {
                // Remove this prefix from fs node
                pccd_core_rmv_pfx_from_fs_node(fs_info, fs_dst_pfx);

                /* Update flag to send out report to controller */
                *is_notify = TRUE;
            }
        }

        if (SLIST_EMPTY(&fs_info->dest_pfx_info->dest_pfx_head)) {
            pccd_core_delete_flowspec_info(lsp_vec, fs_info->fs_id, true);
        }
    }

    bool new_fs_node_created = false;
    bool pfx_added_in_fs = false;
    struct pccd_flowspec_info_s fs_info_new;
    memset(&fs_info_new, 0, sizeof(struct pccd_flowspec_info_s));

    char pcc_ip_str[INET6_ADDRSTRLEN] = {0};
    pccd_core_pce_get_local_ip_str(lsp_vec->lv_pce, pcc_ip_str);

    for (node = PCCD_RADIX_NODE_FIND_NEXT(rpd_lsp->prefix_root, NULL); node;
         node = PCCD_RADIX_NODE_FIND_NEXT(rpd_lsp->prefix_root, node)) {

        entry = prefix_node2struct(node);

        /**
         * Need to create fs node in cases like
         * 1. new prefix is added from rpd
         * 2. lsp vector is just created
         */
        if (lsp_vec->lv_need_to_create_fs || BIT_ISSET(entry->flags, PCCD_RPD_LSP_PREFIX_ADDED_NEW)) {
            if (lsp_vec->lv_curr_pcc_fs_id_in_use) {
                fs_info = pccd_core_get_pce_fs_by_id(lsp_vec->lv_pce,
                            lsp_vec->lv_curr_pcc_fs_id_in_use);
            } else if (!new_fs_node_created) {
                fs_info = &fs_info_new;
                snprintf(fs_info->speaker_id, sizeof(fs_info->speaker_id), "%s",
                                    pcc_ip_str);
                fs_info->fs_id = pccd_core_pcc_fs_id_alloc(lsp_vec->lv_pce);
                fs_info->afi = 1; // IPv4 is supported only
                fs_info->flow_type = PCCD_FLOW_TYPE_DEST_PREFIX;
                fs_info->dest_pfx_info =
                    (pccd_fs_dest_pfx_info_t*)xcalloc(1, sizeof(pccd_fs_dest_pfx_info_t));
                new_fs_node_created = true;
            }

            if (fs_info) {
                fs_dst_pfx = pccd_core_add_prefix_in_fs_node(fs_info,
                                    entry->prefix.ipv4addr,
                                    entry->length,
                                    fs_info->afi);
                if (!fs_dst_pfx) {
                    if (fs_info->dest_pfx_info->fs_prefix_count >= MAX_PREFIX_SUPPORTED_PER_FLOWSPEC) {
                        if (new_fs_node_created) {
                            /**
                             * Add current new fs node to global flowpsec tree and
                             * create new fs node to further add locally configured
                             * prefixes
                             */
                            if (!pccd_core_add_flowspec(lsp_vec, fs_info)) {
                                TRACE_CORE("Failed to add pcc flowspec node with fs id %u",
                                    fs_info->fs_id);
                                pccd_core_fs_delete_all_prefixes(fs_info);
                                xfree(fs_info->dest_pfx_info);
                                fs_info->dest_pfx_info = NULL;
                                return;
                            }
                        } else {
                            /**
                             * As current fs node is exhausted and no further prefix
                             * can be added to it so reset lsp_vec curr_pcc_fs_id_in_use
                             */
                            lsp_vec->lv_curr_pcc_fs_id_in_use = 0;
                        }

                        memset(&fs_info_new, 0, sizeof(struct pccd_flowspec_info_s));
                        fs_info = &fs_info_new;
                        snprintf(fs_info->speaker_id, sizeof(fs_info->speaker_id),
                                            "%s", pcc_ip_str);
                        fs_info->fs_id = pccd_core_pcc_fs_id_alloc(lsp_vec->lv_pce);
                        fs_info->afi = 1; // IPv4 is supported only
                        fs_info->flow_type = PCCD_FLOW_TYPE_DEST_PREFIX;
                        fs_info->dest_pfx_info =
                            (pccd_fs_dest_pfx_info_t*)xcalloc(1, sizeof(pccd_fs_dest_pfx_info_t));
                        new_fs_node_created = true;

                        /* Goto the previous node again and retry to add it */
                        node = PCCD_RADIX_NODE_FIND_PREV(rpd_lsp->prefix_root, node);
                        continue;
                    } else {
                        TRACE_RPD("Failed to add prefix in fs node for fs-id: %u",
                            fs_info_new.fs_id);
                        continue; // To process rest of the prefixes
                    }
                } else {
                    pfx_added_in_fs = true;
                }
            } else {
                /**
                 * Unexpected pccd behaviour
                 */
                TRACE_RPD("Failed to add locally configured prefix in fs-node");
                return;
            }

            BIT_RESET(entry->flags, PCCD_RPD_LSP_PREFIX_ADDED_NEW);
        }
    }

    if (new_fs_node_created) {
        if (pfx_added_in_fs) {
            if (!pccd_core_add_flowspec(lsp_vec, fs_info)) {
                TRACE_CORE("Failed to add pcc flowspec node with fs id %u",
                    fs_info->fs_id);
                pccd_core_fs_delete_all_prefixes(fs_info);
                xfree(fs_info->dest_pfx_info);
                fs_info->dest_pfx_info = NULL;
                return;
            }

            /* Store this fs id in lsp vector to refer it directly */
            lsp_vec->lv_curr_pcc_fs_id_in_use = fs_info->fs_id;

            /* Update flag to send out report to controller */
            *is_notify = TRUE;
        } else {
            pccd_core_fs_delete_all_prefixes(fs_info);
            xfree(fs_info->dest_pfx_info);
            fs_info->dest_pfx_info = NULL;
        }
    }

    lsp_vec->lv_need_to_create_fs = false;

    TRACE_FUNCTION_EXIT();
}


/* NSR Begin */
/* update delegation flags, if its in standby */
void
pccd_core_update_lsp_delegation (struct pccd_rpd_lsp_info *rpd_lsp)
{
    TRACE_FUNCTION_ENTRY();

    if (pccd_nsr_master()) {
        TRACE_FUNCTION_RETURN();
    }

    if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
        TRACE_FUNCTION_RETURN();
    }

    struct lsp_vector *lv = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
    if (lv != NULL) {
        if ((rpd_lsp->type == LSP_TYPE_EXTERNALLY_CONTROLLED)
            && (rpd_lsp->control_status == LSP_EXTERNALLY_CONTROLLED)){
            lv->lv_want_to_delegate = true;
            lv->lv_ack_delegated = true;
        } else {
            lv->lv_want_to_delegate = false;
            lv->lv_ack_delegated = false;
        }
    }

    TRACE_FUNCTION_EXIT();
    return;
}
/* NSR End */

