/*
 * $Id: pccd_config.c 1325062 2023-03-29 15:13:08Z gchandraseka $
 *
 * pccd_config.c
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
/*
 * FIXME : sysexits.h is bsd specific. we should define our own error codes to
 * be able to run on multiple OS.
 */
#include <sysexits.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>


#include <ddl/dtypes.h>
#include <ddl/access.h>
#include <ddl/dax.h>
#include <jnx/aux_types.h>
#include <jnx/aux_types.h>
#include <jnx/bits.h>
#include <jnx/patricia.h>

#include <feature/pccd_sequence.h>
#include <feature/pccd_ddlnames.h>
#include <helpers/trace_util.h>

#include <jnx/libpcep_objects.h>

#include "pccd_config.h"
#include "pccd_config_check.h"
#include "pccd_stats.h"
#include "pccd_core.h"
#include "pccd_core_flowspec.h"
#include "pccd_mib.h"
#include "pccd_xmalloc.h"
#include "pccd_log.h"
#include "pccd_trace.h"
#include "pccd_linux_defines.h"
#include "pccd_mastership.h"
#include "pccd_lic.h"

uint8_t maximum_srmpls_segment_list_depth = DEFAULT_SRMPLS_MAX_SID_DEPTH;
bool propagate_lsp_max_segmentlist_depth = false;

void
pccd_pce_entity_table_create (struct pce_cfg *pce);

static bool reload_srmpls_pces = false;
static bool reload_srv6_pces = false;

static int pce_index = 0;

struct pce_group_cfg {
    char                       pgc_id[PCCD_PCE_GROUP_ID_MAX];
    struct pce_common_opts     pgc_opts;
    SLIST_ENTRY(pce_group_cfg) pgc_next;
};

SLIST_HEAD(pce_group_cfg_head, pce_group_cfg);

struct pccd_cfg {
    unsigned int              pdc_msg_rate_limit;
    unsigned int              pdc_upd_rate_limit;
    unsigned int              pdc_max_provisioned_lsps;
    int                       pdc_pce_groups_num;
    bool                      pdc_multipath_capability;
    bool                      pdc_propagate_maxsegment_list;
    bool                      pdc_disjoint_assoc_capability;
    bool                      pdc_tls_enable;
    struct pce_group_cfg_head pdc_pce_groups;
};

static struct pccd_cfg pccd_config;

#include "pccd_config_public.h"

/* Forward declarations */
/* END Forward declarations */

static void
config_error(ddl_handle_t *object UNUSED, const char *err, const char *apierr)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "Configuration error: %s. apierr: %s\n", err,
             apierr);
    LOGGING_ERR("%s", buf);
}

daemon_trace_file_options_t *
pccd_cfg_pce_group_traceoptions_get (struct pce_group_cfg *pce_group) {
    if (!pce_group) {
	return NULL;
    }

    return &(pce_group->pgc_opts.pco_traceoptions);
}

static void
pccd_cfg_remove_pce_group(struct pccd_cfg *config,
                          struct pce_group_cfg *pce_group)
{
    INSIST_ERR(config != NULL);
    INSIST_ERR(pce_group != NULL);

    SLIST_REMOVE(&config->pdc_pce_groups, pce_group, pce_group_cfg, pgc_next);
    config->pdc_pce_groups_num--;
    INSIST_ERR(config->pdc_pce_groups_num >= 0);
    free(pce_group);
}

static void
pccd_cfg_remove_all_pce_groups(struct pccd_cfg *config)
{
    struct pce_group_cfg *pce_group = NULL, *tmp;
    TRACE_FUNCTION_ENTRY();
    SLIST_FOREACH_SAFE(pce_group, &config->pdc_pce_groups, pgc_next, tmp) {
        TRACE_CORE("Removing PCE group ID %s from list", pce_group->pgc_id);
        SLIST_REMOVE(&config->pdc_pce_groups, pce_group, pce_group_cfg, pgc_next);
        config->pdc_pce_groups_num--;
        if (pce_group->pgc_opts.pco_traceoptions.dtf_trace_file) {
            daemon_trace_close(&pce_group->pgc_opts.pco_traceoptions);
        }
        free(pce_group);
    }
    TRACE_CORE("Deleted all PCE groups");
    INSIST_ERR(SLIST_EMPTY(&config->pdc_pce_groups)
               && config->pdc_pce_groups_num == 0);
    TRACE_FUNCTION_EXIT();
}

/*
 *  mallocs and adds pce_group_cfg to the pce-groups tree.
 */
static struct pce_group_cfg *
pccd_cfg_add_pce_group(struct pccd_cfg *config,
                       const char group_id[PCCD_PCE_GROUP_ID_MAX])
{
    struct pce_group_cfg *pgc = NULL;

    if (config == NULL || strlen(group_id) == 0) {
        return NULL;
    }

    pgc = xcalloc(1, sizeof(*pgc));
    strlcpy(pgc->pgc_id, group_id, sizeof(pgc->pgc_id));
    pgc->pgc_opts.pco_local_timers.plt_min_keepalive = MIN_KEEPALIVE_DEFAULT;
    pgc->pgc_opts.pco_local_timers.plt_max_keepalive = MAX_KEEPALIVE_DEFAULT;
    pgc->pgc_opts.pco_local_timers.plt_max_deadtimer = MAX_DEADTIMER_DEFAULT;
    pgc->pgc_opts.pco_remote_timers.prt_min_keepalive = MIN_KEEPALIVE_DEFAULT;
    pgc->pgc_opts.pco_remote_timers.prt_max_keepalive = MAX_KEEPALIVE_DEFAULT;
    /* Store pce group in the list */
    SLIST_INSERT_HEAD(&config->pdc_pce_groups, pgc, pgc_next);
    config->pdc_pce_groups_num++;
    return pgc;
}

static struct pce_group_cfg *
pccd_cfg_get_pce_group(struct pccd_cfg *config,
                       const char group_id[PCCD_PCE_GROUP_ID_MAX])
{
    struct pce_group_cfg *pgc = NULL;

    if (!config) {
        return NULL;
    }
    if (SLIST_EMPTY(&config->pdc_pce_groups)) {
        return NULL;
    }

    SLIST_FOREACH(pgc, &config->pdc_pce_groups, pgc_next) {
        if (!strncmp(pgc->pgc_id, group_id, PCCD_PCE_GROUP_ID_MAX)) {
            return pgc;
        }
    }
    return NULL;
}

static int
pccd_cfg_read_statefulness(struct pce_common_opts *pco, struct pce_cfg *pce,
                           pce_type_t def, ddl_handle_t *dop)
{
    char buf[16] = {'\0'};
    pce_type_t pce_type = def;
    const char *pce_type_path[] = {
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TYPE_OBJ,
            NULL,
    };
    ddl_handle_t *ddl_pce_type = NULL;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_object_by_path(dop, pce_type_path, &ddl_pce_type,
                                       FALSE)) {
        TRACE_CFG("reading statefullness");
        if (TRUE == dax_get_toggle_by_name(ddl_pce_type,
                                           DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TYPE_STATELESS,
                                           buf)) {
            pce_type = PCE_TYPE_STATELESS;
            TRACE_CFG("stateless");
        }

        if (TRUE == dax_get_toggle_by_name(ddl_pce_type,
                                           DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TYPE_STATEFUL,
                                           buf)) {
            if (pce_type == PCE_TYPE_STATELESS) {
                LOGGING_ERR("stateful and stateless set at the same time");
                dax_release_object(&ddl_pce_type);
                return DAX_WALK_ABORT;
            }
            pce_type = PCE_TYPE_STATEFUL;
            TRACE_CFG("stateful");
        }

        if (TRUE == dax_get_toggle_by_name(ddl_pce_type,
                                           DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TYPE_ACTIVE,
                                           buf)) {
            if (pce_type != PCE_TYPE_STATEFUL) {
                LOGGING_ERR("active toggle can be set only with stateful pce.");
                dax_release_object(&ddl_pce_type);
                return DAX_WALK_ABORT;
            }
            pce_type = PCE_TYPE_STATEFULACTIVE;
            TRACE_CFG("stateful active");
        }
        dax_release_object(&ddl_pce_type);
    } else {
        TRACE_CFG("There is no configuration for '%s', using default: %d",
                  DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TYPE_OBJ,
                  pce_type);
    }

    if (pco) {
        pco->pco_pce_type = pce_type;
    } else {
        pccd_core_pce_cfg_statefullness(pce, pce_type);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_lsp_provisioning(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool lsp_provisioning = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_LSP_PROVISIONING,
                               buf) == TRUE) {
        lsp_provisioning = true;
        TRACE_CFG("lsp provisioning");
    }

    if (pco) {
        pco->pco_lsp_provisioning = lsp_provisioning;
    } else {
        pccd_core_pce_cfg_lsp_provisioning(pce, lsp_provisioning);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_spring_capability(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool spring_cap = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_SPRING_CAPABILITY,
                               buf) == TRUE) {
        spring_cap = true;
        TRACE_CFG("spring capability");
    }

    if (pco) {
        pco->pco_spring_capability = spring_cap;
    } else {
        pccd_core_pce_cfg_spring_capability(pce, spring_cap);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_srv6_capability(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool srv6_cap = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_SRV6_CAPABILITY,
                               buf) == TRUE) {
        srv6_cap = true;
        TRACE_CFG("srv6 capability");
    }

    if (pco) {
        pco->pco_srv6_capability = srv6_cap;
    } else {
        pccd_core_pce_cfg_srv6_capability(pce, srv6_cap);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_disable_tlv_path_binding(struct pce_common_opts *pco, struct pce_cfg *pce,
                                       bool def, ddl_handle_t *dop)
{
    bool disable_tlv_path_bind = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }
    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_DISABLE_TLV_PATH_BINDING,
                               buf) == TRUE) {
        disable_tlv_path_bind = true;
        TRACE_CFG("TLV-PATH-BINDING disabled");
    }

    if (pco) {
        pco->pco_disable_tlv_path_binding = disable_tlv_path_bind;
    } else {
        pccd_core_pce_cfg_disable_tlv_path_binding(pce, disable_tlv_path_bind);
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_p2mp_lsp_report_capability(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool lsp_report = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_P2MP_LSP_REPORT_CAPABILITY,
                               buf) == TRUE) {
        lsp_report = true;
        TRACE_CFG("p2mp lsp reporting");
    }

    if (pco) {
        pco->pco_p2mp_lsp_report_capability = lsp_report;
    } else {
        pccd_core_pce_cfg_p2mp_lsp_report_capability(pce, lsp_report);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_p2mp_lsp_update_capability(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool lsp_update = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_P2MP_LSP_UPDATE_CAPABILITY,
                               buf) == TRUE) {
        lsp_update = true;
        TRACE_CFG("p2mp lsp updateing");
    }

    if (pco) {
        /*If p2mp lsp Update is set then set the reporting of P2MP LSP as well*/
        pco->pco_p2mp_lsp_report_capability = lsp_update;
        pco->pco_p2mp_lsp_update_capability = lsp_update;
    } else {
        pccd_core_pce_cfg_p2mp_lsp_update_capability(pce, lsp_update);
        pccd_core_pce_cfg_p2mp_lsp_report_capability(pce, lsp_update);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_p2mp_lsp_init_capability(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool lsp_init = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_P2MP_LSP_INIT_CAPABILITY,
                               buf) == TRUE) {
        lsp_init = true;
        TRACE_CFG("p2mp lsp initiation");
    }

    if (pco) {
        /*
         * If p2mp lsp initilization is configured then
         * set Update and reporting of P2MP LSP as well
         */
        pco->pco_p2mp_lsp_report_capability = lsp_init;
        pco->pco_p2mp_lsp_update_capability = lsp_init;
        pco->pco_p2mp_lsp_init_capability = lsp_init;
    } else {
            pccd_core_pce_cfg_p2mp_lsp_init_capability(pce, lsp_init);
            pccd_core_pce_cfg_p2mp_lsp_update_capability(pce, lsp_init);
            pccd_core_pce_cfg_p2mp_lsp_report_capability(pce, lsp_init);
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_lsp_cleanup_timer(struct pce_common_opts *pco, struct pce_cfg *pce,
                                u_int def, ddl_handle_t *dop)
{
    u_int lct = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }
    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_LSP_CLEANUP_TIMER,
                                     &lct)) {
        TRACE_CFG("Stored lsp_cleanup_timer %d", lct);
    }

    if (pco) {
        pco->pco_lsp_cleanup_timer = lct;
    } else {
        pccd_core_pce_cfg_lsp_cleanup_timer(pce, lct);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_lsp_retry_delegation(struct pce_common_opts *pco, struct pce_cfg *pce,
                               bool def, ddl_handle_t *dop)
{
    bool lsp_retry_delegation = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_LSP_RETRY_DELEGATION,
                               buf) == TRUE) {
        lsp_retry_delegation = true;
        TRACE_CFG("lsp retry delegation");
    }

    if (pco) {
        pco->pco_lsp_retry_delegation = lsp_retry_delegation;
    } else {
        pccd_core_pce_cfg_lsp_retry_delegation(pce, lsp_retry_delegation);
    }

    return DAX_WALK_OK;
}
/*
 * configure the delegation of LSP (from PCC to PCE) retry timer for an an LSP
 * - in case of re-delegation of LSP from PCE to PCC
 * - in case of delegation failure from PCC to PCE
 */
static int
pccd_cfg_read_lsp_retry_delegation_timer(struct pce_common_opts *pco, struct pce_cfg *pce,
                                u_int def, ddl_handle_t *dop)
{
    u_int lct = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }
    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_LSP_RETRY_DELEGATION_TIMER,
                                     &lct)) {
        TRACE_CFG("Stored lsp_cleanup_timer %d", lct);
    }

    if (pco) {
        pco->pco_delegation_retry_timeout = lct;
    } else {
        pccd_core_pce_cfg_delegation_retry_timeout(pce, lct);
    }

    return DAX_WALK_OK;
}

/*
 * configure the StartTLS wait timer
 */
static int
pccd_cfg_read_start_tls_wait_timer (struct pce_common_opts *pco,
                                    struct pce_cfg         *pce,
                                    u_int                   def,
                                    ddl_handle_t           *dop)
{
    uint8_t timer_val = (uint8_t) def;

    if ((pco && pce) || (!pco && !pce)) {
        /*
         * This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set
         */
        return DAX_WALK_ABORT;
    }
    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ubyte_by_name(
                                dop,
                                DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_START_TLS_WAIT_TIMER,
                                &timer_val)) {
        TRACE_CFG("Stored start tls wait timer %u", timer_val);
    }

    if (pco) {
        pco->pco_tls_wait_timer = timer_val;
    } else {
        pccd_core_pce_cfg_tls_wait_timer(pce, timer_val);
    }

    return DAX_WALK_OK;
}


/**
 *@brief
 * Parse empty ero action config attribute. Store the result either in common 
 * options pco, or pce config structure pce. This function is used in two 
 * places - 1. when the pce groups are being read, this is only when pce-group
 * is configured (pce != NULL is how the API is called) 2. when pce
 * configuration itself is being read.
 *
 * At any point in the time the empty ero config structures reflect what is
 * being configured by the user. When nothing is configured the code will play 
 * the default option(send-err). The default option will not be implicitly
 * set in this data structure.
 *
 * @param pco[out] PCE common options struct
 * @param pce[out] PCE configuration struct
 * @param def[in] Default value for empty ero action
 * @param dop[in] DAX handle pointing to container of empty-ero-action
 *                attribute.
 * @return DAX_WALK_OK if the parameters were OK and configuration were read
 *         successfuly, DAX_WALK_ERROR otherwise.
 */
static int
pccd_cfg_read_empty_ero_action (struct pce_common_opts*			pco,
				struct pce_cfg*				pce,
				pce_cfg_empty_ero_action_t*             def,
				ddl_handle_t*				dop)
{
    pce_cfg_empty_ero_action_t      empty_ero_action;
    unsigned    empty_ero_action_choice;

    if ((pco && pce) || (!pco && !pce)) {
        /* 
         * This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set
         */
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop,
             DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCUPDATE_EMPTY_ERO_ACTION,
             &empty_ero_action_choice)) {

        TRACE_CFG("empty ero action configured");
        bzero(&empty_ero_action, sizeof(empty_ero_action));

        switch (empty_ero_action_choice) {
            case DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCUPDATE_EMPTY_ERO_ACTION_ROUTING_DECISION:
                empty_ero_action.pceea_routing_decision = TRUE;
                TRACE_CFG("empty ero action routing-decision configured");
                break;
            case DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCUPDATE_EMPTY_ERO_ACTION_SEND_ERR:
                empty_ero_action.pceea_send_err = TRUE;
                TRACE_CFG("empty ero action send-err configured");
                break;
            case DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCUPDATE_EMPTY_ERO_ACTION_TEAR_DOWN_PATH:
                empty_ero_action.pceea_path_tear_down = TRUE;
                TRACE_CFG("empty ero action tear-down-path configured");
                break;
            default:
                break;
        }
    } else if (def) {
        memcpy(&empty_ero_action, def, sizeof(empty_ero_action));
        TRACE_CFG("empty ero action not configured, copy from default");
    } else {
        bzero(&empty_ero_action, sizeof(empty_ero_action));
        TRACE_CFG("no empty ero action configured");
    }

    if (pco) {
        memcpy(&pco->pco_empty_ero_action, &empty_ero_action,
               sizeof(pco->pco_empty_ero_action));
    } else {
        memcpy(&pce->pce_opts.pco_empty_ero_action, &empty_ero_action,
               sizeof(pce->pce_opts.pco_empty_ero_action));
    }

    return DAX_WALK_OK;
}

/**
 * Get the Authentication Keychain for the PCEP session from the Config
 */
static int
pccd_cfg_read_auth_keychain (struct pce_common_opts *pco, struct pce_cfg *pce,
                             const char *def, ddl_handle_t *dop)
{
    char auth_keychain[PCCD_AUTH_KEYCHAIN_MAX];

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (def) {
        strncpy(auth_keychain, def, sizeof(auth_keychain));
    } else {
        memset(auth_keychain, 0, sizeof(auth_keychain));
    }
    auth_keychain[sizeof(auth_keychain) - 1] = '\0';

    if (TRUE == dax_get_stringr_by_name(dop,
                    DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_AUTHENTICATION_KEY_CHAIN,
                    auth_keychain, sizeof(auth_keychain))) {
        TRACE_CFG("Stored auth-keychain '%s'", auth_keychain);
    }

    if (pco) {
        strncpy(pco->pco_auth_keychain, auth_keychain,
                sizeof(pco->pco_auth_keychain));
        pco->pco_auth_keychain[sizeof(pco->pco_auth_keychain) - 1] = '\0';
    } else {
        pccd_core_auth_keychain(pce, auth_keychain);
    }
    return DAX_WALK_OK;
}

/**
 * Get the Authentication Algorithm for the PCEP session from the Config
 */
static int
pccd_cfg_read_auth_algorithm (struct pce_common_opts *pco, struct pce_cfg *pce,
                              const char *def, ddl_handle_t *dop)
{
    char auth_algorithm[PCCD_AUTH_ALGORITHM_MAX];

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (def) {
        strncpy(auth_algorithm, def, sizeof(auth_algorithm));
    } else {
        memset(auth_algorithm, 0, sizeof(auth_algorithm));
    }
    auth_algorithm[sizeof(auth_algorithm) - 1] = '\0';

    if (TRUE == dax_get_stringr_by_name(dop,
                    DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_AUTHENTICATION_ALGORITHM,
                    auth_algorithm, sizeof(auth_algorithm))) {
        TRACE_CFG("Stored auth-algorithm '%s'", auth_algorithm);
    }

    if (pco) {
        strncpy(pco->pco_auth_algorithm, auth_algorithm,
                sizeof(pco->pco_auth_algorithm));
        pco->pco_auth_algorithm[sizeof(pco->pco_auth_algorithm) - 1] = '\0';
    } else {
        pccd_core_auth_algorithm(pce, auth_algorithm);
    }
    return DAX_WALK_OK;
}

/**
 * Get the Authentication Key for the PCEP session from the Config
 */
static int
pccd_cfg_read_auth_key (struct pce_common_opts *pco, struct pce_cfg *pce,
                        const char *def, ddl_handle_t *dop)
{
    char auth_key[PCCD_AUTH_KEY_MAX];

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (def) {
        strncpy(auth_key, def, sizeof(auth_key));
    } else {
        memset(auth_key, 0, sizeof(auth_key));
    }
    auth_key[sizeof(auth_key) - 1] = '\0';

    if (TRUE == dax_get_stringr_by_name(dop,
                    DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_AUTHENTICATION_KEY,
                    auth_key, sizeof(auth_key))) {
        TRACE_CFG("Stored auth-key '%s'", auth_key);
    }

    if (pco) {
        strncpy(pco->pco_auth_key, auth_key,
                sizeof(pco->pco_auth_key));
        pco->pco_auth_key[sizeof(pco->pco_auth_key) - 1] = '\0';
    } else {
        pccd_core_auth_key(pce, auth_key);
    }
    return DAX_WALK_OK;
}

static int
pccd_cfg_read_req_timer(struct pce_common_opts *pco, struct pce_cfg *pce,
                        u_short def, ddl_handle_t *dop)
{
    u_short rt = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }
    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ushort_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_REQUEST_TIMER,
                                       &rt)) {
        TRACE_CFG("Stored request_timer");
    }

    if (pco) {
        pco->pco_request_timer = rt;
        TRACE_CFG("Stored request_timer %d", pco->pco_request_timer);
    } else {
        pccd_core_pce_cfg_request_timer(pce, rt);
    }

    return DAX_WALK_OK;
}

/**
 * Parse max unknown requests config attribute. Store the result either in
 * common options (c) pco, or pce config structure (c) pce. This function
 * is used in two places - firstlly when the pce groups are being read
 * (pce != NULL), secondly when pce configuration itself is being read.
 *
 * @param pco[out] PCE common options struct
 * @param pce[out] PCE configuration struct
 * @param def[in] Default value for max unknown requests
 * @param dop[in] DAX handle pointing to container of max-unknown-requests
 *                attribute.
 * @return DAX_WALK_OK if the parameters were OK and configuration were read
 *         successfuly, DAX_WALK_ERROR otherwise.
 */
static int
pccd_cfg_read_max_unknown_rqsts(struct pce_common_opts *pco,
                                struct pce_cfg *pce, unsigned def,
                                ddl_handle_t *dop)
{
    unsigned max_unknown_requests = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }
    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_MAX_UNKNOWN_REQUESTS,
                                       &max_unknown_requests)) {
        TRACE_CFG("Stored max-unknown-requests: %d", max_unknown_requests);
    }

    if (pco) {
        pco->pco_max_unknown_requests = max_unknown_requests;
    } else {
        pccd_core_pce_cfg_max_unknown_requests(pce, max_unknown_requests);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_max_unknown_msgs(struct pce_common_opts *pco, struct pce_cfg *pce,
                               u_int def, ddl_handle_t *dop)
{
    u_int max_unknown_messages = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_MAX_UNKNOWN_MESSAGES,
                                       &max_unknown_messages)) {
        TRACE_CFG("Stored max-unknown-messages: %d", max_unknown_messages);
    }
    if (pco) {
        pco->pco_max_unknown_messages = max_unknown_messages;
    } else {
        pccd_core_pce_cfg_max_unknown_mesgs(pce, max_unknown_messages);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_no_advertise_own_lsps(struct pce_common_opts *pco,
                                 struct pce_cfg *pce, bool def,
                                 ddl_handle_t *dop)
{
    bool no_advertice_pcc_owned_lsps = def;
    char buf[32] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_toggle_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_NO_ADVERTISE_PCC_OWNED_LSPS,
                                       buf)) {
        TRACE_CFG("Stored no-advertise-own-lsps");
        no_advertice_pcc_owned_lsps = true;
    }

    if (pco) {
        pco->pco_no_advertise_pcc_owned_lsps = no_advertice_pcc_owned_lsps;
    } else {
        pccd_core_pce_cfg_no_advertise_own_lsps(pce,
                                                no_advertice_pcc_owned_lsps);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_trace_protocol(struct pce_common_opts *pco,
                             struct pce_cfg         *pce,
                             ddl_handle_t           *dop)
{
    daemon_trace_file_options_t  dtfo;
    ddl_handle_t *ddl_trace_protocol;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    memset(&dtfo, 0, sizeof(dtfo));
    if (TRUE == dax_get_object_by_name(dop, DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_TRACEOPTIONS_OBJ,
                                       &ddl_trace_protocol, FALSE)) {
        daemon_trace_initialize(&dtfo, "pcep");
        if (daemon_trace_read_global_options(&dtfo, FALSE) == FALSE) {
            LOGGING_ERR("Could not read pce/pce_group global trace configuration");
        }

        if (daemon_trace_read_config(dop, NULL, &dtfo) == FALSE) {
            LOGGING_ERR("Could not read trace configuration for pce/pce group");
        }

        /* Set the flag to use microseconds in tracing */
        dtfo.dtf_timestamp_ms = true;

        /* Always enable logging in microsecond timestamp */
        if (dtfo.dtf_trace_file) {
            trace_aux_flags_set(dtfo.dtf_trace_file, TRACE_AUX_FLAG_MSEC);
        }

        dax_release_object(&ddl_trace_protocol);
        TRACE_CFG("Initialized trace file: '%s'", dtfo.dtf_name);
    } else {
        LOGGING_INFO("No protocol trace configuration found");
    }

    if (pco) {
        memcpy(&pco->pco_traceoptions, &dtfo, sizeof(dtfo));
    } else {
        pccd_core_pce_cfg_trace_protocol(pce, &dtfo);
    }

    return DAX_WALK_OK;
}

/**
 * Read "min-keepalive" and "max-keepalive" from configuration from object
 * pointed to by (c) parent.
 * @param dop[in] pointer to dax object which contains "min-keepalive" and
 *                   "max-keepalive"
 * @param min_keepalive[out] pointer to store configuration for min-keepalive
 * @param max_keepalive[out] pointer to store configuration for max-keepalive
 */
static void
pccd_cfg_read_keepalive_timers(ddl_handle_t *dop, unsigned char *min_keepalive,
                               unsigned char *max_keepalive)
{
    INSIST_ERR(dop != NULL);
    INSIST_ERR(min_keepalive != NULL);
    INSIST_ERR(max_keepalive != NULL);

    if (dax_get_ubyte_by_name(dop,
                              DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_LOCAL_TIMERS_MIN_KEEPALIVE,
                              min_keepalive) == TRUE) {
    }

    if (dax_get_ubyte_by_name(dop,
                              DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_LOCAL_TIMERS_MAX_KEEPALIVE,
                              max_keepalive) == TRUE) {
    }
}

static int
pccd_cfg_read_local_timers(struct pce_common_opts *pco, struct pce_cfg *pce,
                           const struct pce_local_timers *def,
                           ddl_handle_t *dop)
{
    ddl_handle_t *ddl_timers;
    struct pce_local_timers timers;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (def) {
        memcpy(&timers, def, sizeof(timers));
    } else {
        timers.plt_min_keepalive = MIN_KEEPALIVE_DEFAULT;
        timers.plt_max_keepalive = MAX_KEEPALIVE_DEFAULT;
        timers.plt_max_deadtimer = MAX_DEADTIMER_DEFAULT;
    }

    if (TRUE == dax_get_object_by_name(dop, DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_LOCAL_TIMERS_OBJ,
                                       &ddl_timers, FALSE)) {
        pccd_cfg_read_keepalive_timers(ddl_timers, &timers.plt_min_keepalive,
                                       &timers.plt_max_keepalive);
        /* Read the max_deadtimer */
        if (dax_get_ubyte_by_name(ddl_timers,
                                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_LOCAL_TIMERS_MAX_DEADTIMER,
                                  (unsigned char*)&timers.plt_max_deadtimer) == TRUE) {
        }
        dax_release_object(&ddl_timers);
    }

    if (pco) {
        memcpy(&pco->pco_local_timers, &timers, sizeof(pco->pco_local_timers));
    } else {
        pccd_core_pce_cfg_local_timers(pce, &timers);
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_remote_timers(struct pce_common_opts *pco, struct pce_cfg *pce,
                            const struct pce_remote_timers *def,
                            ddl_handle_t *dop)
{
    ddl_handle_t *ddl_timers;
    struct pce_remote_timers timers;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (def) {
        memcpy(&timers, def, sizeof(timers));
    } else {
        timers.prt_min_keepalive = MIN_KEEPALIVE_DEFAULT;
        timers.prt_max_keepalive = MAX_KEEPALIVE_DEFAULT;
    }

    if (TRUE == dax_get_object_by_name(dop, DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_REMOTE_TIMERS_OBJ,
                                       &ddl_timers, FALSE)) {
        pccd_cfg_read_keepalive_timers(ddl_timers, &timers.prt_min_keepalive,
                                       &timers.prt_max_keepalive);
        dax_release_object(&ddl_timers);
    }

    if (pco) {
        memcpy(&pco->pco_remote_timers, &timers,
               sizeof(pco->pco_remote_timers));
    } else {
        pccd_core_pce_cfg_remote_timers(pce, &timers);
    }

    return DAX_WALK_OK;
}

/**
 * Read pce flowspec capability from configuration from under knob where
 * dop points to.
 * @param pco[in] pointer to struct to store the result to if != NULL
 * @param pce[in] pointer to pce configuration that is being read right now
 * @param def[in] default value
 * @param dop[in] dax pointer to parent of this timeout knob
 * @return DAX_WALK_ABORT if both pco and pce pointers are set, DAX_WALK_OK
 *                        otherwise.
 */
static int
pccd_cfg_read_flowspec_capability (struct pce_common_opts *pco, struct pce_cfg *pce,
                                   bool def, ddl_handle_t *dop)
{
    bool flowspec_capability = def;
    char buf[24] = {'\0'};

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (dax_get_toggle_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_PCE_TRAFFIC_STEERING,
                               buf) == TRUE) {
        flowspec_capability = true;
        TRACE_CFG("flowspec capability");
    }

    if (pco) {
        pco->pco_flowspec_capability = flowspec_capability;
    } else {
        pccd_core_pce_cfg_flowspec_capability(pce, flowspec_capability);
    }

    return DAX_WALK_OK;
}


/**
 * Read delegation-cleanup-timeout from configuration from under knob where
 * dop points to.
 * @param pco[in] pointer to struct to store the result to if != NULL
 * @param pce[in] pointer to pce configuration that is being read right now
 * @param def[in] default value
 * @param dop[in] dax pointer to parent of this timeout knob
 * @return DAX_WALK_ABORT if both pco and pce pointers are set, DAX_WALK_OK
 *                        otherwise.
 */
static int
pccd_cfg_read_deleg_cleanup_timeout(struct pce_common_opts *pco,
                                    struct pce_cfg *pce,
                                    unsigned int def,
                                    ddl_handle_t *dop)
{
    unsigned int cleanup_timeout = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_uint_by_name(dop,
                                     DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_DELEGATION_CLEANUP_TIMEOUT,
                                     &cleanup_timeout)) {
        TRACE_CFG("%s configured: %u",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_DELEGATION_CLEANUP_TIMEOUT,
                  cleanup_timeout);
    }

    if (pco) {
        pco->pco_delegation_cleanup_timeout = cleanup_timeout;
    } else {
        pccd_core_pce_cfg_delegation_cleanup_timeout(pce, cleanup_timeout);
    }

    return DAX_WALK_OK;
}

/**
 * Read delegation-setup-timeout from configuration from under knob where
 * dop points to.
 * @param pco[in] pointer to struct to store the result to if != NULL
 * @param pce[in] pointer to pce configuration that is being read right now
 * @param def[in] default value
 * @param dop[in] dax pointer to parent of this timeout knob
 * @return DAX_WALK_ABORT if both pco and pce pointers are set, DAX_WALK_OK
 *                        otherwise.
 */
static int
pccd_cfg_read_deleg_setup_timeout(struct pce_common_opts *pco,
                                  struct pce_cfg *pce,
                                  unsigned short def,
                                  ddl_handle_t *dop)
{
    unsigned short setup_timeout = def;

    if ((pco && pce) || (!pco && !pce)) {
        /* This function is used to read both PCE and pce-group config param.
         * In all cases, only one of pco or pce must be set */
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ushort_by_name(dop,
                                       DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_DELEGATION_SETUP_TIMEOUT,
                                       &setup_timeout)) {
        TRACE_CFG("%s configured: %u",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_DELEGATION_SETUP_TIMEOUT,
                  setup_timeout);
    }

    if (pco) {
        pco->pco_delegation_setup_timeout = setup_timeout;
    } else {
        pccd_core_pce_cfg_delegation_setup_timeout(pce, setup_timeout);
    }

    return DAX_WALK_OK;
}

/**
 * Reads and parses common options.
 * @param[out] pco Pointer to (c) pce_common_opts to store read values to. ((c)
 *					pce and (c) def MUST be NULL)
 * @param[out] pce Pointer to (c) pce_cfg to store read values to.
 * @param[out] def Pointer to (c) pce_common_opts with default values to use
 *					when parsing pce.
 * @param[in] dop Pointer to (c) ddl_handle_t which must point to path which
 * 					contains these common options in it.
 * @return DAX_WALK_OK if successful, DAX_WALK_ABORT otherwise.
 */
static int
pccd_cfg_read_common_opts(struct pce_common_opts *pco, struct pce_cfg *pce,
                          struct pce_common_opts *def, ddl_handle_t *dop)
{
    if ((pco && pce) || (!pco && !pce) || (pco && def)) {
        return DAX_WALK_ABORT;
    }

    if (!dop) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_statefulness(pco, pce,
                                                  (def) ? def->pco_pce_type : PCE_TYPE_STATEFULACTIVE,
                                                  dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_lsp_provisioning(pco, pce,
                                                      (def) ? def->pco_lsp_provisioning : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    /*
     * Don't chagne the order of processing of P2MP LSP initilization,
     * Update and reporting
     */
    if (DAX_WALK_OK != pccd_cfg_read_p2mp_lsp_init_capability(pco, pce,
                                                      (def) ? def->pco_p2mp_lsp_init_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_p2mp_lsp_update_capability(pco, pce,
                                                      (def) ? def->pco_p2mp_lsp_update_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_p2mp_lsp_report_capability(pco, pce,
                                                      (def) ? def->pco_p2mp_lsp_report_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_lsp_cleanup_timer(pco, pce,
                                                       (def) ? def->pco_lsp_cleanup_timer 
                                                       : PCCD_PCE_DEF_LSP_CLEANUP_TIMEOUT,
                                                       dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_auth_keychain(pco, pce,
                                       (def) ? def->pco_auth_keychain : NULL,
                                       dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_auth_algorithm(pco, pce,
                                       (def) ? def->pco_auth_algorithm : NULL,
                                       dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_auth_key(pco, pce,
                                       (def) ? def->pco_auth_key : NULL,
                                       dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_local_timers(pco, pce,
                                                  def ? &def->pco_local_timers : NULL,
                                                  dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_remote_timers(pco, pce,
                                                   def ? &def->pco_remote_timers : NULL,
                                                   dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_req_timer(pco, pce,
                                               def ? def->pco_request_timer : 0,
                                               dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_max_unknown_rqsts(pco, pce,
                                                       def ? def->pco_max_unknown_requests : 0,
                                                       dop)) {
        return DAX_WALK_ABORT;
    }
    if (DAX_WALK_OK != pccd_cfg_read_max_unknown_msgs(pco, pce,
                                                      def ? def->pco_max_unknown_messages : PCCD_PCE_MAX_UNKNOWN_MESSAGES,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_no_advertise_own_lsps(pco, pce,
                                                           def ? def->pco_no_advertise_pcc_owned_lsps : false,
                                                           dop)) {
        return DAX_WALK_ABORT;
    }


    if (DAX_WALK_OK != pccd_cfg_read_trace_protocol(pco, pce, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_deleg_cleanup_timeout(pco, pce,
                                                           def ? def->pco_delegation_cleanup_timeout : PCCD_PCE_DEF_DELEG_CLEANUP_TIMEOUT,
                                                           dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_deleg_setup_timeout(pco, pce,
                                                         def ? def->pco_delegation_setup_timeout : PCCD_PCE_DEF_DELEG_SETUP_TIMEOUT,
                                                         dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_lsp_retry_delegation(pco, pce,
                                                  (def) ? def->pco_lsp_retry_delegation : true,
                                                  dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_spring_capability(pco, pce,
                                                      (def) ? def->pco_spring_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_srv6_capability(pco, pce,
                                                      (def) ? def->pco_srv6_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_lsp_retry_delegation_timer(pco, pce,
                                                         def ? def->pco_delegation_retry_timeout : PCCD_PCE_DEF_DELEG_RETRY_TIMEOUT,
                                                         dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_empty_ero_action(pco, pce,
                                                      def ? &def->pco_empty_ero_action : NULL,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_disable_tlv_path_binding(
                                           pco, pce,
                                           def ? def->pco_disable_tlv_path_binding : false,
                                           dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_flowspec_capability(pco, pce,
                                                      (def) ? def->pco_flowspec_capability : false,
                                                      dop)) {
        return DAX_WALK_ABORT;
    }
    if (DAX_WALK_OK != pccd_cfg_read_start_tls_wait_timer(
                          pco, pce,
                          def ? def->pco_delegation_retry_timeout : PCCD_PCE_DEF_START_TLS_TIMEOUT,
                          dop)) {
        return DAX_WALK_ABORT;
    }

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_pce_tls_wait_timer (struct pce_cfg *pec, ddl_handle_t *dop)
{
    uint8_t timer_val = 60; // in seconds

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ubyte_by_name(
                                dop,
                                DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_START_TLS_WAIT_TIMER,
                                (unsigned char *) &timer_val)) {
        TRACE_CFG("Read tls wait timer: %u", timer_val);
    } else {
        TRACE_CFG("Default %s: %u",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_START_TLS_WAIT_TIMER, timer_val);
    }

    pccd_core_pce_cfg_tls_wait_timer(pec, timer_val);

    return DAX_WALK_OK;
}

/*
 * Reads and parses particular pce-group. dop points to "pccd pce-group" list
 * entry.
 */
static int
pccd_cfg_read_pce_group(struct pccd_cfg *config, ddl_handle_t *dop)
{
    char group_id[PCCD_PCE_GROUP_ID_MAX] = {'\0'};
    struct pce_group_cfg *pgc = NULL;
    struct pce_common_opts *pco = NULL;

    if (FALSE == dax_get_stringr_by_name(dop,
                                         DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_GROUP_ID, group_id,
                                         sizeof(group_id))) {
        LOGGING_ERR("Could not get pce-group identifier");
        return DAX_WALK_ABORT;
    }

    pgc = pccd_cfg_get_pce_group(config, group_id);
    if (pgc == NULL) {
        TRACE_CFG("New pce-group configured: %s'", group_id);
        pgc = pccd_cfg_add_pce_group(config, group_id);
        if (pgc == NULL) {
            LOGGING_ERR("Could not create new pce-group object in local "
                        "database for pce-group '%s'", group_id);
            return DAX_WALK_ABORT;
        }
    }

    INSIST_ERR(pgc != NULL);
    INSIST_ERR(strncmp(pgc->pgc_id, group_id, sizeof(pgc->pgc_id)) == 0);
    pco = &pgc->pgc_opts;
    if (DAX_WALK_OK != pccd_cfg_read_common_opts(pco, NULL, NULL, dop)) {
        LOGGING_ERR("Failed to read pce-group '%s' from configuration",
                    pgc->pgc_id);
        pccd_cfg_remove_pce_group(config, pgc);
        free(pgc);
        return DAX_WALK_ABORT;
    }
    pco->pco_changed = true;

    return DAX_WALK_OK;
}

/*
 * Walk and parse pce-groups in configuration
 */
static int
pccd_cfg_walk_pce_groups(dax_walk_data_t *dwd UNUSED, ddl_handle_t *dop,
                         int action, void *data)
{
    char pce_group_id[PCCD_PCE_GROUP_ID_MAX] = {'\0'};
    struct pccd_cfg *cfg = NULL;

    INSIST_ERR(data != NULL);

    INSIST_ERR(dop != NULL || action == DAX_ITEM_DELETE_ALL);

    cfg = data;

    switch (action) {
    case DAX_ITEM_DELETE_ALL:
        pccd_cfg_remove_all_pce_groups(cfg);
        TRACE_CFG("All pce-groups have been deleted");
        return DAX_WALK_OK;

    case DAX_ITEM_DELETE:
        {
            struct pce_group_cfg *pg = NULL;
            if (!dax_get_stringr_by_dwd_ident(dwd, NULL, 0, pce_group_id,
                                              sizeof(pce_group_id))) {
                LOGGING_ERR("Could not get deleted pce-group identifier");
                LOGGING_ERR("Inconsistency found between system configuration"
                        " and local config database - aborting");
                abort();
            }
            TRACE_CFG("pce-group %s deleted from configuration", pce_group_id);
            pg = pccd_cfg_get_pce_group(cfg, pce_group_id);
            if (pg == NULL) {
                LOGGING_ERR("Can't find pce-group '%s' configuration "
                            "that is proclaimed deleted", pce_group_id);
                return DAX_WALK_ABORT;
            }
            pccd_cfg_remove_pce_group(cfg, pg);
            TRACE_CFG("pce-group '%s' removed from pccd's database", pce_group_id);
            return DAX_WALK_OK;
        }

    case DAX_ITEM_CHANGED:
        if (!dax_get_stringr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_GROUP_GROUP_ID,
                                     pce_group_id, sizeof(pce_group_id))) {
            LOGGING_ERR("Could not retrieve pce-group-id from pce-group object");
            return DAX_WALK_ABORT;
        }
        TRACE_CFG("pce-group %s changed", pce_group_id);
        return pccd_cfg_read_pce_group(cfg, dop);
    default:
        LOGGING_ERR("Don't know how to handle DAX action: %d", action);
        return DAX_WALK_ABORT;
    }
    return DAX_WALK_OK;
}

static void
pccd_cfg_read_pce_groups(struct pccd_cfg *cfg)
{
    const char *pce_group_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_PCE_GROUP,
            NULL,
    };

    ddl_handle_t *dop;
    dax_get_object_by_path(NULL, pce_group_path, &dop, FALSE);
    /* dop will be NULL if the group is empty and dax_walk_list will trigger DAX_ITEM_DELETE_ALL */
    dax_walk_list(dop, DAX_WALK_DELTA, pccd_cfg_walk_pce_groups, cfg);
    if (dop) {
        dax_release_object(&dop);
    }
}

/*
 * Reads pce-group string id from pce configuration. Then searches that
 * pce-group id in configured pce-groups and sets (c) group to point to that
 * group configuration.
 */
static int
pccd_cfg_read_pce_group_link(struct pccd_cfg *cfg,
                             struct pce_group_cfg **groupp, ddl_handle_t *dop)
{
    char pce_group_id[PCCD_PCE_GROUP_ID_MAX] = {'\0'};

    if (!cfg || !groupp || !dop) {
        return DAX_WALK_ABORT;
    }

    if (FALSE == dax_get_stringr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_PCE_GROUP,
                                         pce_group_id, sizeof(pce_group_id))) {
        LOGGING_INFO("Could not get pce-group id from pce");
        return DAX_WALK_OK;
    }

    *groupp = pccd_cfg_get_pce_group(cfg, pce_group_id);
    if (!*groupp) {
        LOGGING_ERR("PCE configured with link to nonexistent pce-group-id "
                    "%s", pce_group_id);
        return DAX_WALK_ABORT;
    }

    return DAX_WALK_OK;
}

    
static int
pccd_cfg_read_pce_local_addr(struct pce_cfg *pec, ddl_handle_t *dop)
{
    int family = 0;
    struct in_addr local_addr;

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    memset(&local_addr, 0, sizeof(local_addr));

    if (TRUE == dax_get_ipaddr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_LOCAL_ADDRESS,
                                       &family, &local_addr, sizeof(local_addr))) {
        TRACE_CFG("Read local addr: %s", inet_ntoa(local_addr));
        if (family != AF_INET) {
            LOGGING_ERR("Read address family: %d and not required AF_INET:"
                        " %d", family, AF_INET);
            return DAX_WALK_ABORT;
        }

        pccd_core_pce_cfg_local_addr(pec, &local_addr);
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_pce_local_v6_addr(struct pce_cfg *pec, ddl_handle_t *dop)
{
    int family = 0;
    struct in6_addr local_v6_addr;
    memset(&local_v6_addr, 0, sizeof(local_v6_addr));

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ipaddr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_LOCAL_IPV6_ADDRESS,
                                       &family, &local_v6_addr, sizeof(local_v6_addr))) {

        char addr_str[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &local_v6_addr, addr_str, sizeof(addr_str));
        TRACE_CFG("Read local v6 addr: %s", addr_str);
        if (family != AF_INET6) {
            LOGGING_ERR("Read address family: %d and not required AF_INET6:"
                        " %d", family, AF_INET6);
            return DAX_WALK_ABORT;
        }

        /* set the flag for local v6 address configured */
        pec->is_local_v6_configured = true;

        pccd_core_pce_cfg_local_v6_addr(pec, &local_v6_addr);
    } else {
        /* Reset the flag for local v6 address configured */
        pec->is_local_v6_configured = false;
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_pce_dest_addr(struct pce_cfg *pec, ddl_handle_t *dop)
{
    int family = 0;
    struct in_addr dest_addr;

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));

    if (TRUE == dax_get_ipaddr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_DESTINATION_IPV4_ADDRESS,
                                       &family, &dest_addr, sizeof(dest_addr))) {
        TRACE_CFG("Read dest addr: %s", inet_ntoa(dest_addr));
        if (family != AF_INET) {
            LOGGING_ERR("Read address family: %d and not required AF_INET:"
                        " %d", family, AF_INET);
            return DAX_WALK_ABORT;
        }

        pccd_core_pce_cfg_dest_addr(pec, &dest_addr);
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_pce_dest_v6_addr(struct pce_cfg *pec, ddl_handle_t *dop)
{
    int family = 0;
    struct in6_addr dest_v6_addr;
    memset(&dest_v6_addr, 0, sizeof(dest_v6_addr));

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ipaddr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_DESTINATION_IPV6_ADDRESS,
                                       &family, &dest_v6_addr, sizeof(dest_v6_addr))) {

        char addr_str[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &dest_v6_addr, addr_str, sizeof(addr_str));
        TRACE_CFG("Read dest v6 addr: %s", addr_str);
        if (family != AF_INET6) {
            LOGGING_ERR("Read address family: %d and not required AF_INET6:"
                        " %d", family, AF_INET);
            return DAX_WALK_ABORT;
        }

        /* mark session as ipv6 cause destination address is of ipv6 type */
        pec->is_ipv6_session = true;

        pccd_core_pce_cfg_dest_v6_addr(pec, &dest_v6_addr);
    } else {
        /* reset ipv6 session flag not being able to read destination v6 address */
        pec->is_ipv6_session = false;
    }

    return DAX_WALK_OK;
}


static int
pccd_cfg_read_pce_dest_port(struct pce_cfg *pec, ddl_handle_t *dop)
{
    uint16_t port = 4189;

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ushort_by_name(dop,
                                       DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_DESTINATION_PORT,
                                       &port)) {
        TRACE_CFG("Read dest PORT: %u", port);
    }

    pccd_core_pce_cfg_tcp_port(pec, port);

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_pce_deleg_prio(struct pce_cfg *pec, ddl_handle_t *dop)
{
    u_short delegation_prio = 0;

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ushort_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_DELEGATION_PRIORITY,
                                       &delegation_prio)) {
        TRACE_CFG("Read delegation prio: %d", delegation_prio);
    }

    pccd_core_pce_cfg_delegation_priority(pec, delegation_prio);

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_pce_req_prio(struct pce_cfg *pec, ddl_handle_t *dop)
{
    u_short request_prio = 0;

    if (!pec || !dop) {
        return DAX_WALK_ABORT;
    }

    if (TRUE == dax_get_ushort_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_REQUEST_PRIORITY,
                                       &request_prio)) {
        TRACE_CFG("Read request prio: %d", request_prio);
    }

    pccd_core_pce_cfg_request_priority(pec, request_prio);

    return DAX_WALK_OK;
}

static int
pccd_cfg_read_pce(struct pccd_cfg *cfg, const char pce_id[PCCD_PCE_ID_MAX],
                  ddl_handle_t *dop)
{
    bool created_pce = false;
    unsigned short pce_old_dele_prio = 0;
    struct pce_group_cfg *group_cfg = NULL;
    struct pce_cfg *pec = NULL;

    if (!cfg || pce_id[0] == '\0' || !dop) {
        return DAX_WALK_ABORT;
    }

    /* If this PCE's configuration also contain pce-group reference, read the
     * group-id and get the pointer to that pce-group config in local db. Values
     * from that pce-group (already parsed) will be used as default values in
     * further pcc_core calls.
     * */

    if (DAX_WALK_OK != pccd_cfg_read_pce_group_link(cfg, &group_cfg, dop)) {
        return DAX_WALK_ABORT;
    }

    pec = pccd_core_get_pce_cfg(pce_id);
    if (!pec) {
        TRACE_CFG("Found nonexistent pce '%s', allocating", pce_id);
        pec = pccd_core_alloc_pce_cfg(pce_id);
        if (!pec) {
            LOGGING_ERR("Couldn't create new pce configuration storage");
            return DAX_WALK_ABORT;
        }
        pec->pce_index = ++pce_index;
        created_pce = true;
    } else {
        pce_old_dele_prio = pec->pce_delegation_prio;
    }

    pec->pce_pce_group = group_cfg;

    if (DAX_WALK_OK != pccd_cfg_read_common_opts(NULL, pec,
                                                 group_cfg ? &group_cfg->pgc_opts : NULL,
                                                 dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_local_v6_addr(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_dest_v6_addr(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_local_addr(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_dest_addr(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_dest_port(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_deleg_prio(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (DAX_WALK_OK != pccd_cfg_read_pce_req_prio(pec, dop)) {
        return DAX_WALK_ABORT;
    }
    if (DAX_WALK_OK != pccd_cfg_read_pce_tls_wait_timer(pec, dop)) {
        return DAX_WALK_ABORT;
    }

    if (created_pce) {
        pccd_core_created_pce(pec);
        pccd_snmp_mib_tables_create(pec);
    } else {
        /* The pce already existed, so core needs to be notified about changed
         * configuration. */
        if (pec->pce_delegation_prio != pce_old_dele_prio) {
            pccd_core_update_pce_list(pec);
        }
        /* If session critical configV has been modified then only need to reset the session */
        if (pec->pce_session_critical_config_modify) {
            pccd_core_reload_pce(pec);
        }
    }

    /* clear the flag for next time processing */
    pec->pce_session_critical_config_modify = false;

    return DAX_WALK_OK;
}

/*
 * Walk and parse pces in configuration (callback for dax walk list)
 */
static int
pccd_cfg_walk_pces(dax_walk_data_t *dwd UNUSED,
                   ddl_handle_t *dop, int action, void *data)
{
    char pce_id[PCCD_PCE_ID_MAX] = {'\0'};
    struct pccd_cfg *cfg = data;

    INSIST_ERR(dop != NULL || action == DAX_ITEM_DELETE_ALL);

    switch(action) {
    case DAX_ITEM_DELETE_ALL:
        pccd_core_delete_all_pces();
        TRACE_CFG("All pces have been deleted");
        return DAX_WALK_OK;

    case DAX_ITEM_DELETE:
        {
            struct pce_cfg *pce = NULL;
            if (!dax_get_stringr_by_dwd_ident(dwd, NULL, 0, pce_id,
                                              sizeof(pce_id))) {
                LOGGING_ERR("Could not get deleted pce identifier");
                LOGGING_ERR("Inconsistency found between system configuration"
                            " and local config database - aborting");
                abort();
            }
            TRACE_CFG("pce %s deleted", pce_id);
            pce = pccd_core_get_pce_cfg(pce_id);
            if (pce == NULL) {
                LOGGING_ERR("Can't find pce config that is proclaimed "
                        "deleted by junos: '%s'", pce_id);
                return DAX_WALK_ABORT;
            }
            if (pccd_core_deleted_pce(pce)) {
                LOGGING_ERR("Failed to delete PCE '%s' from local cache - "
                            "inconsistency found", pce_id);
                abort();
            }
            TRACE_CFG("pce '%s' removed from pccd's database", pce_id);
            return DAX_WALK_OK;
        }

    case DAX_ITEM_UNCHANGED:
        {
            struct pce_group_cfg *group_cfg = NULL;

            if (!dax_get_stringr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_PCE_ID,
                                         pce_id, sizeof(pce_id))) {
                LOGGING_ERR("Could not get pce identifier");
                return DAX_WALK_ABORT;
            }
            /* If this PCE's configuration also contain pce-group reference, check
             * if the group's config changed. If yes reload pce.
             * */
    
            if (DAX_WALK_OK != pccd_cfg_read_pce_group_link(cfg, &group_cfg, dop)) {
                return DAX_WALK_ABORT;
            }
    
            if (group_cfg && group_cfg->pgc_opts.pco_changed) {
                TRACE_CFG("group for pce '%s' changed", pce_id);
                return pccd_cfg_read_pce(cfg, pce_id, dop);
            } else {
                return DAX_WALK_OK;
            }
        }
    case DAX_ITEM_CHANGED:
        if (!dax_get_stringr_by_name(dop, DDLNAME_JUNIPER_PROTOCOLS_PCEP_PCE_PCE_ID,
                                     pce_id, sizeof(pce_id))) {
            LOGGING_ERR("Could not get pce identifier");
            return DAX_WALK_ABORT;
        }
        TRACE_CFG("pce '%s' changed", pce_id);
        return pccd_cfg_read_pce(cfg, pce_id, dop);
    default:
        LOGGING_ERR("Don't know how to handle DAX action: %d", action);
        return DAX_WALK_ABORT;
    }
    return DAX_WALK_OK;
}

static void
pccd_cfg_read_pces(struct pccd_cfg *cfg)
{
    const char *pce_group_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_PCE_OBJ,
            NULL,
    };

    ddl_handle_t *dop;
    dax_get_object_by_path(NULL, pce_group_path, &dop, FALSE);
    /* dop will be NULL if the group is empty and dax_walk_list will trigger DAX_ITEM_DELETE_ALL */
    dax_walk_list(dop, DAX_WALK_DELTA | DAX_WALK_CONFIGURED, pccd_cfg_walk_pces, cfg);
    if (dop) dax_release_object(&dop);
}

static void
pccd_cfg_groups_clear_changed_flag(struct pccd_cfg *cfg)
{
    struct pce_group_cfg *pce_group = NULL, *tmp;
    SLIST_FOREACH_SAFE(pce_group, &cfg->pdc_pce_groups, pgc_next, tmp) {
        pce_group->pgc_opts.pco_changed = false;
    }
}

static void
pccd_cfg_read_pccd_iana_obj_class_cnf (void)
{
    const char *pccd_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
	    DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_OBJ,
            NULL,
    };
 
    char buf[32] = {'\0'};
    ddl_handle_t *dop;
    ddl_boolean_t ret;
 
    if (dax_get_object_by_path(NULL, pccd_path, &dop, FALSE) == FALSE) {
        TRACE_CFG("Could not find object-class root in configuration");
        assoc_obj_complaince = ASSOC_OBJ_RFC_COMPLAINT;
        obj_s2ls_IANA_compliant = TRUE;
        return;
    }

    ret = dax_get_toggle_by_name(dop,
                DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_ASSOCIATION_OLD_VALUE,
                                 buf);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: ",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_ASSOCIATION_OLD_VALUE);
        assoc_obj_complaince = ASSOC_OBJ_OLD_OBJ_CLASS_OLD_FORMAT;
    }
    
    ret = dax_get_toggle_by_name(dop,
                DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_ASSOCIATION_INITIAL_DRAFT_COMPLIANT,
                                 buf);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: ",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_ASSOCIATION_INITIAL_DRAFT_COMPLIANT);
        assoc_obj_complaince = ASSOC_OBJ_OLD_FORMAT;
    }

    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_S2LS_OLD_VALUE,
                                 buf);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: ",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_OBJECT_CLASS_S2LS_OLD_VALUE);
    	obj_s2ls_IANA_compliant = FALSE;
    } else {
	obj_s2ls_IANA_compliant = TRUE;
    }

    dax_release_object(&dop);
}
 
static void
pccd_cfg_read_pccd_iana_tlv_type_cnf (void)
{
    const char *pccd_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_TLV_TYPE_OBJ,
            NULL,
    };
 
    char buf[32] = {'\0'};
    ddl_handle_t *dop;
    ddl_boolean_t ret;
 
    if (dax_get_object_by_path(NULL, pccd_path, &dop, FALSE) == FALSE) {
        TRACE_CFG("Could not find tlv-type root in configuration");
	tlv_p2mp_ipv4_lsp_id_IANA_compliant = TRUE;
        return;
    }
 
    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_TLV_TYPE_P2MP_IPV4_LSP_IDENTIFIER_OLD_VALUE,
                                 buf);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: ",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_TLV_TYPE_P2MP_IPV4_LSP_IDENTIFIER_OLD_VALUE);
	tlv_p2mp_ipv4_lsp_id_IANA_compliant = FALSE;
    } else {
        tlv_p2mp_ipv4_lsp_id_IANA_compliant = TRUE;
    }

    dax_release_object(&dop);
}

static void
pccd_cfg_read_pccd_multipath_iana_cnf (void)
{
    const char *pccd_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_SEGMENT_ROUTING_MULTIPATH_OBJ,
            NULL,
    };
    unsigned int pathattribute_color_tlv = 0;
    ddl_handle_t *dop;
    ddl_boolean_t ret;

    if (dax_get_object_by_path(NULL, pccd_path, &dop, FALSE) == FALSE) {
        TRACE_CFG("Could not find segment-routing-multipath root in configuration");
        pathattribute_color_tlv_type = TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT;
        return;
    }

    ret = dax_get_uint_by_name(
                dop,
                DDLNAME_JUNIPER_PROTOCOLS_PCEP_SEGMENT_ROUTING_MULTIPATH_PATHATTRIBUTE_COLOR_TLV,
                &pathattribute_color_tlv);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %d",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_SEGMENT_ROUTING_MULTIPATH_PATHATTRIBUTE_COLOR_TLV,
                  pathattribute_color_tlv);
        pathattribute_color_tlv_type = (uint16_t) pathattribute_color_tlv;
    } else {
        TRACE_CFG("Default %s: %d",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_SEGMENT_ROUTING_MULTIPATH_PATHATTRIBUTE_COLOR_TLV,
                  pathattribute_color_tlv);
        pathattribute_color_tlv_type = TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT;
    }
    dax_release_object(&dop);
}


static void
pccd_cfg_read_pccd_srv6_iana_cnf (void)
{
    const char *pccd_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_SRV6_OBJ,
            NULL,
    };

    ddl_handle_t *dop;
    ddl_boolean_t ret;

    unsigned int ero_type = PCEP_ERO_SUB_SRV6_DEFAULT;
    unsigned int rro_type = PCEP_RRO_SUB_SRV6_DEFAULT;
    unsigned int pst_type = SRV6_PST_TYPE_DEFAULT;
    unsigned int pce_cap_sub_tlv_type = SRV6_PCE_CAPABILITY_SUB_TLV_TYPE_DEFAULT;

    if (dax_get_object_by_path(NULL, pccd_path, &dop, FALSE) == FALSE) {
        TRACE_CFG("Could not find srv6 root in configuration");
        return;
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_ERO_SUBOBJECT_TYPE,
                               &ero_type);
    if (ret == TRUE) {
        srv6_ero_subobject_type = (uint8_t)ero_type;
        TRACE_CFG("Parsed %s: %u",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_ERO_SUBOBJECT_TYPE,
                   srv6_ero_subobject_type);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_ERO_SUBOBJECT_TYPE,
                   srv6_ero_subobject_type);
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_RRO_SUBOBJECT_TYPE,
                               &rro_type);
    if (ret == TRUE) {
        srv6_rro_subobject_type = (uint8_t)rro_type;
        TRACE_CFG("Parsed %s: %u",
                    DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_RRO_SUBOBJECT_TYPE,
                   srv6_rro_subobject_type);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_RRO_SUBOBJECT_TYPE,
                   srv6_rro_subobject_type);
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PST_TYPE,
                               &pst_type);
    if (ret == TRUE) {
        srv6_pst_type = (uint8_t)pst_type;
        TRACE_CFG("Parsed %s: %u",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PST_TYPE,
                   srv6_pst_type);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PST_TYPE,
                   srv6_pst_type);
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PCE_CAP_SUB_TLV_TYPE,
                               &pce_cap_sub_tlv_type);
    if (ret == TRUE) {
        srv6_pce_capability_sub_tlv_type = (uint16_t)pce_cap_sub_tlv_type;
        TRACE_CFG("Parsed %s: %u",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PCE_CAP_SUB_TLV_TYPE,
                   srv6_pce_capability_sub_tlv_type);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_SRV6_SRV6_PCE_CAP_SUB_TLV_TYPE,
                   srv6_pce_capability_sub_tlv_type);
    }
}


static void
pccd_cfg_read_pccd_iana_config (void)
{
    pccd_cfg_read_pccd_iana_obj_class_cnf();
    pccd_cfg_read_pccd_iana_tlv_type_cnf();
    pccd_cfg_read_pccd_srv6_iana_cnf();
    pccd_cfg_read_pccd_multipath_iana_cnf();
}

static void
pccd_cfg_read_pccd(struct pccd_cfg *cfg)
{
    const char *pccd_path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            NULL,
    };
    char buf[32] = {'\0'};
    ddl_handle_t *dop;
    unsigned short value = 0;
    unsigned int max_provisioned_lsps = PCCD_MAX_PROVISIONED_LSPS_DEFAULT;
    ddl_boolean_t ret = FALSE;
    bool RFC8231_compliant = TRUE;
    unsigned int srv6_msd = MAX_H_ENCAPS_MSD_VALUE_DEFAULT;
    unsigned int srmpls_msd = DEFAULT_SRMPLS_MAX_SID_DEPTH;

    pccd_alloc_msg_rate_buffer(0);
    pccd_alloc_upd_rate_buffer(0);
    if (dax_get_object_by_path(NULL, pccd_path, &dop, FALSE) == FALSE) {
        TRACE_CFG("Could not find pccd root in configuration");
        return;
    }

    ret = dax_get_ushort_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_MESSAGE_RATE_LIMIT,
                                 &value);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %d",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_MESSAGE_RATE_LIMIT, value);
        cfg->pdc_msg_rate_limit = value;
        pccd_alloc_msg_rate_buffer(value);
    }

    ret = dax_get_ushort_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_UPDATE_RATE_LIMIT,
                                 &value);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %d",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_UPDATE_RATE_LIMIT, value);
        cfg->pdc_upd_rate_limit = value;
        pccd_alloc_upd_rate_buffer(value);
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAX_PROVISIONED_LSPS,
                               &max_provisioned_lsps);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %d",
        		DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAX_PROVISIONED_LSPS, max_provisioned_lsps);
    } else {
        TRACE_CFG("Default %s: %d",
                  DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAX_PROVISIONED_LSPS, max_provisioned_lsps);
    }
    cfg->pdc_max_provisioned_lsps = max_provisioned_lsps;
    pccd_set_max_provisioned_lsps(max_provisioned_lsps);

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRMPLS_SEGMENT_LIST_DEPTH,
                               &srmpls_msd);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %u",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRMPLS_SEGMENT_LIST_DEPTH,
                   srmpls_msd);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRMPLS_SEGMENT_LIST_DEPTH,
                   srmpls_msd);
    }

    if ((true == pccd_core_has_any_spring_pce()) && (maximum_srmpls_segment_list_depth != srmpls_msd)) {
        TRACE_CFG("Reload all SRMPLS PCEs as SRMPLS MSD changed, Received SRMPLS MSD = %d", srmpls_msd);
        reload_srmpls_pces = true;
    }

    maximum_srmpls_segment_list_depth = (uint8_t)srmpls_msd;

    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_PROPAGATE_LSP_MAX_SEGMENT_LIST_DEPTH,
                                 buf);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s", DDLNAME_JUNIPER_PROTOCOLS_PCEP_PROPAGATE_LSP_MAX_SEGMENT_LIST_DEPTH);

        if (true == propagate_lsp_max_segmentlist_depth) {
            TRACE_CFG("propagate lsp MSD is already set to true");
        } else {
            propagate_lsp_max_segmentlist_depth = true;

            TRACE_CFG("Reload all SRMPLS and SRv6 PCEs as propagate lsp MSD is set to true");
            reload_srmpls_pces = true;
            reload_srv6_pces = true;
        }
    } else {
        if (false == propagate_lsp_max_segmentlist_depth) {
            TRACE_CFG("propagate lsp MSD is already set to false");
        } else {
            propagate_lsp_max_segmentlist_depth = false;

            TRACE_CFG("Reload all SRMPLS and SRv6 PCEs as propagate lsp MSD is set to false");
            reload_srmpls_pces = true;
            reload_srv6_pces = true;
        }
    }

    ret = dax_get_uint_by_name(dop,
                               DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRV6_SEGMENT_LIST_DEPTH,
                               &srv6_msd);
    if (ret == TRUE) {
        TRACE_CFG("Parsed %s: %u",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRV6_SEGMENT_LIST_DEPTH,
                   srv6_msd);
    } else {
        TRACE_CFG("Default value of %s: %d",
                   DDLNAME_JUNIPER_PROTOCOLS_PCEP_MAXIMUM_SRV6_SEGMENT_LIST_DEPTH,
                   srv6_msd);
    }

    if ((true == pccd_core_has_any_srv6_pce()) && (maximum_srv6_segment_list_depth != srv6_msd)) {
        TRACE_CFG("Reload all SRv6 PCEs as SRv6 MSD changed, Received SRv6 MSD = %d", srv6_msd);
        reload_srv6_pces = true;
    }

    maximum_srv6_segment_list_depth = (uint8_t)srv6_msd;

    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_DIVERSITY_ASSOCIATION_CAPABILITY,
                                 buf);
    if (ret == TRUE) {
        cfg->pdc_disjoint_assoc_capability = true;
        TRACE_CFG("Parsed %s: %d", DDLNAME_JUNIPER_PROTOCOLS_PCEP_DIVERSITY_ASSOCIATION_CAPABILITY,
                  cfg->pdc_disjoint_assoc_capability);
    } else {
        cfg->pdc_disjoint_assoc_capability =  false;
    }
    pccd_set_disjoint_assoc_capability(cfg->pdc_disjoint_assoc_capability);

    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_DISABLE_MULTIPATH_CAPABILITY,
                                 buf);
    if (ret == TRUE) {
        cfg->pdc_multipath_capability = false;
        TRACE_CFG("Parsed %s: %d", DDLNAME_JUNIPER_PROTOCOLS_PCEP_DISABLE_MULTIPATH_CAPABILITY,
                  cfg->pdc_multipath_capability);
    } else {
        cfg->pdc_multipath_capability =  true;
    }
    pccd_set_multipath_capability(cfg->pdc_multipath_capability);
    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_TLS_STRICT,
                                 buf);
    if (ret == TRUE) {
        cfg->pdc_tls_enable = true;
        TRACE_CFG("Parsed %s: %d", DDLNAME_JUNIPER_PROTOCOLS_PCEP_TLS_STRICT,
                  cfg->pdc_tls_enable);
    } else {
        cfg->pdc_tls_enable = false;
    }
    pccd_set_tls_enable(cfg->pdc_tls_enable);

    ret = dax_get_toggle_by_name(dop,
                                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_PROPAGATE_MAX_SEGMENTLIST,
                                 buf);
    if (ret == TRUE) {
        cfg->pdc_propagate_maxsegment_list = true;
        TRACE_CFG("Parsed %s: %d", DDLNAME_JUNIPER_PROTOCOLS_PCEP_PROPAGATE_MAX_SEGMENTLIST,
                  cfg->pdc_propagate_maxsegment_list);
    } else {
        cfg->pdc_propagate_maxsegment_list = false;
    }
    pccd_set_maxsegment_list_propagation(cfg->pdc_propagate_maxsegment_list);

    ret = dax_get_toggle_by_name(dop,
    		                 DDLNAME_JUNIPER_PROTOCOLS_PCEP_STATEFUL_DRAFT_07_COMPLIANT,
                                 buf);

    if (ret == TRUE) {
        RFC8231_compliant = FALSE;
        TRACE_CFG("Parsed %s: %d",
        	  DDLNAME_JUNIPER_PROTOCOLS_PCEP_STATEFUL_DRAFT_07_COMPLIANT,
                  RFC8231_compliant);
    } else {
        RFC8231_compliant = TRUE;
    }

    pccd_core_set_rfc8231_compliance(RFC8231_compliant);
    
    pccd_cfg_read_pccd_iana_config();

    dax_release_object(&dop);
}

static bool
pccd_config_open_db(bool check_config)
{
    const char *error = NULL;

    #ifdef HOSTPROG
    error = dax_open_db(NULL, DNAME_NONE, 0, 0, check_config == true ? 1:0);
    #else
    error = dax_open_db(NULL, DNAME_PCCD, 0,
                        DDL_ACCESS_SEQUENCE_IGNORE, check_config == true ? 1:0);
    #endif
    if (error) {
        config_error(NULL, "ddl_access_open_db failed", error);
        return false;
    }
    return true;
}

static ddl_handle_t *
pccd_config_open_pccd(void)
{
    const char *path[] = {
            "protocols",
            DDLNAME_DDC_JUNIPER_PROTOCOLS_PCEP_OBJ,
            NULL};
    ddl_handle_t *dop = NULL;
    const char *name = NULL;

    if (FALSE == dax_get_object_by_path(NULL, path, &dop, FALSE)) {
        TRACE_CFG("pccd was not found in configuration");
        return NULL;
    }

    if (dax_get_name(dop, &name) == TRUE) {
        TRACE_CFG("pccd found in config path. dop name: %s, changed: %d",
                  name, dax_is_changed(dop));
    } else {
        TRACE_CFG("pccd found in config path, but dax_get_name(%p, %p)"
                  " failed", dop, &name);
    }

    return dop;
}

/* Only called when check_commit == 0 */
static ddl_handle_t *
pccd_config_open_db_pccd(void)
{
    ddl_handle_t *dop = NULL;
    if (!pccd_config_open_db(false)) {
        exit(EX_CONFIG);
    }

    dop = pccd_config_open_pccd();
    if (!dop) {
        pccd_lic_release();
        exit(EX_CONFIG);
	return dop;
    }

    return dop;
}

static int
pccd_config_check(bool check_config)
{
    ddl_handle_t *pccd_root = NULL;
    if (!check_config) {
        return EX_OK;
    }

    if (!pccd_config_open_db(true)) {
        return EX_CONFIG;
    }

    pccd_root = pccd_config_open_pccd();
    if (!pccd_root) {
	/* config is not present */
        return EX_OK;
    }

    if (pccd_config_check_do(pccd_root)) {
        return EX_CONFIG;
    }

    return EX_OK;
}

void
pccd_read_config(bool check_config)
{
    const char *error;
    ddl_handle_t *dop = NULL;

    TRACE_CFG("pccd_read_config check_config:%d", check_config);
    if (check_config) {
        exit(pccd_config_check(check_config));
    }

    dop = pccd_config_open_db_pccd();
    if (!dop) {
        exit(EX_CONFIG);
	return;
    }

    reload_srmpls_pces = false;
    reload_srv6_pces = false;

    pccd_trace_read_config();
    pccd_cfg_read_pccd(&pccd_config);
    pccd_cfg_read_pce_groups(&pccd_config);
    pccd_cfg_read_pces(&pccd_config);
    pccd_cfg_groups_clear_changed_flag(&pccd_config);

    error = dax_close_db();
    if (error) {
        config_error(NULL, "ddl_access_open_db failed", error);
    }

    if (reload_srmpls_pces && reload_srv6_pces) {
        pccd_core_reload_all_sr_pces();
    } else if (reload_srmpls_pces) {
        pccd_core_reload_all_srmpls_pces();
    } else if (reload_srv6_pces) {
        pccd_core_reload_all_srv6_pces();
    }
}

/* NSR Begin */
boolean
pccd_cfg_is_nsr_enabled(void)
{
    static const char *nsr_path[] = { "routing-options", "nonstop-routing", NULL };
    //ddl_handle_t *dop;
    const char *error;

    if (!pccd_config_open_db(false)) {
        exit(EX_CONFIG);
    }

    if (!ddl_access_object_find_by_name(NULL, nsr_path, 0, NULL, 0))
        return false;

    error = dax_close_db();
    if (error)
        config_error(NULL, "ddl_access_close_db failed", error);

    return true;
}
/* NSR End */

