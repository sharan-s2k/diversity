/*
 * $Id: pccd_rpd.c 1332762 2023-04-27 14:47:54Z gchandraseka $
 *
 * pccd_rpd.c Contains communication with rpd.
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <sysexits.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <syslog.h>

#define PROTO_UNIX
#include <jnx/jsockaddr.h>
#include <jnx/librpd/shared.h>
#include <jnx/librpd/lspinfo.h>
#include <jnx/librpd/librpd.h>
#include <jnx/librpd/jnx.h>
#include <jnx/name_tree.h>
#include <isc/eventlib.h>
#include <jnx/jtimers.h>
#include <jnx/thread.h>
#include <jnx/bits.h>
#include <jnx/patricia.h>
#include <jnx/mirror_data_node.h>
#include <jnx/mirror_data.h>

#include "pccd_ret_code.h"
#include "pccd_rpd.h"
#include "pccd_stats.h"
#include "pccd_xmalloc.h"
#include "pccd_core.h"
#include "pccd_core_util.h"
#include "pccd_core_flowspec.h"
#include "pccd_log.h"
#include "pccd_trace.h"
#include "pccd_util.h"
#include "pccd_rpd_ipc.h"
#include "pccd_queue_stubs.h"
#include "pccd_ro.h"
#include "pccd_radix.h"
#include "pccd_mirror.h"

typedef enum pcupd_dag_operation_e_ {
    PCUPD_DAG_OP_NONE,
    PCUPD_DAG_OP_ADD,
    PCUPD_DAG_OP_UPD,
    PCUPD_DAG_OP_DEL,
    PCUPD_DAG_OP_MAX,
} pcupd_dag_operation_e;

static rbroot* lspid_tree = NULL;
static rbroot *p2mp_tree = NULL;

/**
 * pccd_rpd_lsp_id_cmp
 *
 * Compares two lsp ids
 *
 * @param e1        : first lsp
 * @param e2        : second lsp
 * @return int      : -1 if lsp id of e1 is smaller than that of e2
 *                  : 0 if both have same lsp ids
 *                  : 1 if lsp id of e1 is greater than that of e2
 */
static int
pccd_rpd_lsp_id_cmp(const void* e1, const void* e2)
{
    const pccd_rpd_lsp *ent1;
    const pccd_rpd_lsp *ent2;

    /* We get passed in a pointer to the key*/
    ent1 = RBNODE_KEY_TO_PCCD_RPD_LSP_STRUCT(e1, lsp_node);
    ent2 = RBNODE_KEY_TO_PCCD_RPD_LSP_STRUCT(e2, lsp_node);

    if (ent1->lsp_info.id < ent2->lsp_info.id) {
        return -1;
    }
    if (ent1->lsp_info.id > ent2->lsp_info.id) {
        return 1;
    }
    return (0);
}

/**
 * pccd_rpd_p2mp_id_cmp
 *
 * Compares two p2mp lsp plsp_ids
 *
 * @param e1        : first p2mp lsp
 * @param e2        : second p2mp lsp
 * @return int      : -1 if plsp_id of e1 is smaller than that of e2
 *                  : 0 if both have same plsp_ids
 *                  : 1 if plsp_id of e1 is greater than that of e2
 */
static int
pccd_rpd_p2mp_id_cmp (const void* e1, const void* e2)
{
    const pccd_rpd_p2mp_lsp *ent1;
    const pccd_rpd_p2mp_lsp *ent2;

    /* We get passed in a pointer to the key*/
    ent1 = RBNODE_KEY_TO_PCCD_RPD_P2MP_STRUCT(e1, p2mp_node);
    ent2 = RBNODE_KEY_TO_PCCD_RPD_P2MP_STRUCT(e2, p2mp_node);

    if (ent1->info.plsp_id < ent2->info.plsp_id) {
	return -1;
    }
    if (ent1->info.plsp_id > ent2->info.plsp_id) {
        return 1;
    }
    return 0;
}

/**
 * pccd_rpd_rbtree_init 
 *
 * Initializes lsp_id RB tree
 *
 */
static void
pccd_rpd_rbtree_init(void)
{
    lspid_tree = junos_redblack_root_init(lspid_tree,
				   	  FALSE, 0, FALSE);
}

/**
 * pccd_rpd_rbtree_p2mp_init 
 *
 * Initializes p2mp RB tree
 *
 */
static void
pccd_rpd_rbtree_p2mp_init (void)
{
    p2mp_tree = junos_redblack_root_init(p2mp_tree,
				FALSE, 0, FALSE);
}

/**
 * pccd_rpd_rbtree_delete
 *
 * Free the rbnode used to store LSP id
 *
 * @param[in] node         : rbnode for this Lspid
 * @return int             : 0 if success
 */
static int
pccd_rpd_rbtree_delete(rbnode *node)
{
    if (!junos_redblack_delete(lspid_tree, node)){
	TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);	
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 * get rbnode for this LSP in lsp tree
 *
 * @param[in] lsp_id : LSP id.
 *
 * @return: A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if the key cannot be found
 */
static rbnode *
pccd_rpd_rbtree_get_node (uint32_t lsp_id)
{
    const void *srch_key;
    pccd_rpd_lsp lsp_struct;

    lsp_struct.lsp_info.id = lsp_id;
    srch_key = junos_redblack_key(lspid_tree, &(lsp_struct.lsp_node));
    return junos_redblack_get(lspid_tree, srch_key,
    		pccd_rpd_lsp_id_cmp);
}

/**
 * get rbnode for this LSP in p2mp lsp tree
 *
 * @param[in] plsp_id : PLSP id.
 *
 * @return: A pointer to an @c rbnode structure;
 *     @c NULL if the tree is empty, or if the key cannot be found
 */
static rbnode *
pccd_rpd_p2mp_rbtree_get_node (uint32_t plsp_id)
{
    const void *srch_key;
    pccd_rpd_p2mp_lsp p2mp_struct;

    p2mp_struct.info.plsp_id = plsp_id;
    srch_key = junos_redblack_key(p2mp_tree, &(p2mp_struct.p2mp_node));
    return junos_redblack_get(p2mp_tree, srch_key,
		pccd_rpd_p2mp_id_cmp);
}

//TEST


//#ifdef NOT_INCLUDING

/* The next macro should warn future maintainers when
 * sizeof(struct pccd_rpd_lsp.name) gets larger than NAME_KEY_LENGTH
 * from name_tree.
 *
 * This test is here, so that pccd_rpd.h is not unnecessary poluted with
 * name_tree.h (which is needed for NAME_KEY_LENGTH)
 */
BUILD_ASSERT_DECL(sizeof(((struct pccd_rpd_lsp_info *)NULL)->id) < NAME_KEY_LENGTH);

#define PCCD_RPD_CONNECT_TIMEOUT_SECS 2 /* Timeout in seconds for connecting to RPD */
#define PCCD_RPD_CLIENT_ID	"pccd"
#define PCCD_RPD_RECONNECT	10 /*< seconds between rpd_session_connect attempts */

extern struct pce_cfg_core *pccd_core_get_main_pce (void);

typedef enum {
    PCCD_RPD_STATE_CLOSED,
    PCCD_RPD_STATE_CONNECTING,
    PCCD_RPD_STATE_CONNECTED,
    PCCD_RPD_STATE_ACC, /* Wait for 'accepted' message from RPD */
    PCCD_RPD_STATE_UP,
} pccd_rpd_state_t;

static pccd_rpd_state_change_fn     pccd_rpd_state_change;
static pccd_rpd_lsp_added_fn        pccd_rpd_lsp_added;
static pccd_rpd_lsp_deleted_fn      pccd_rpd_lsp_deleted;
static pccd_rpd_lsp_report_fn       pccd_rpd_lsp_report;
static pccd_rpd_lsp_deleg_fn        pccd_rpd_lsp_deleg;
static pccd_rpd_lsp_request_fn      pccd_rpd_lsp_request;
static pccd_rpd_remove_local_sr_lsp_fn  pccd_rpd_remove_local_sr_lsp;
static pccd_rpd_remove_local_srv6_lsp_fn  pccd_rpd_remove_local_srv6_lsp;

static pccd_rpd_state_t             pccd_rpd_state;
static rpd_session_handle           pccd_rpd_ses_hndl;
static evFileID                     pccd_rpd_read_id;
static evFileID                     pccd_rpd_write_id;
static evContext                    pccd_rpd_ev_ctx;
static name_tree_t                  pccd_p2mp_lsps;

#define MAX_LSP_ID                  0xfffff
static uint32_t                     lsp_id;
static uint32_t                     total_lsps;
static bool                         pccd_rpd_in_get_all_lsps_info;
static u_int8_t                     pccd_rpd_lsp_batch_end_count;
static bool                         pccd_rpd_get_all_flowspec_info;

static name_tree_t                  pccd_rpd_rsvp_p2p_name_tree;
static name_tree_t                  pccd_rpd_rsvp_p2mp_name_tree;
static name_tree_t                  pccd_rpd_rsvp_bypass_name_tree;
static name_tree_t                  pccd_rpd_sr_p2p_name_tree;
static name_tree_t                  pccd_rpd_srv6_p2p_name_tree;

static name_tree_t                  *pccd_rpd_rsvp_name_tree[RSVP_SUBTYPE_MAX] = {
                                            &pccd_rpd_rsvp_p2p_name_tree,
                                            &pccd_rpd_rsvp_p2mp_name_tree,
                                            &pccd_rpd_rsvp_bypass_name_tree};

static name_tree_t                  *pccd_rpd_sr_name_tree[SR_SUBTYPE_MAX] = {
                                            &pccd_rpd_sr_p2p_name_tree};

static name_tree_t                  *pccd_rpd_srv6_name_tree[SRv6_SUBTYPE_MAX] = {
                                            &pccd_rpd_srv6_p2p_name_tree};

static pccd_rpd_setup_type_info		pccd_rpd_name_tree_setup_type[SETUP_TYPE_MAX] = {
    {pccd_rpd_rsvp_name_tree, RSVP_SUBTYPE_MAX},
    {pccd_rpd_sr_name_tree, SR_SUBTYPE_MAX},
    {pccd_rpd_srv6_name_tree, SRv6_SUBTYPE_MAX}};

static name_tree_t                  sr_color_cpath_table;

/* Forward declarations */
static int
pccd_rpd_connect(evContext ctx);
static int
pccd_rpd_reconnect(void);
static int
pccd_rpd_schedule_reconnect(void);
static void
pccd_rpd_delete_all_lsps(void);
static uint32_t
pccd_rpd_lsp_id_alloc(void);
void
pccd_rpd_lsp_err_rmv_lsp(struct pccd_rpd_lsp_info *rpd_lsp);
extern boolean 
pccd_nsr_master(void);

/* End of forward declarations */

/* State machine functions */


/**
 * pccd_rpd_get_subtype_tree_count
 *
 * Returns number of sub_type trees in a given type
 *
 * @param[in] type    :
 *
 * @return  Returns number of sub_type trees in a given type
 */

static uint8_t
pccd_rpd_get_subtype_tree_count(uint8_t type)
{
    uint8_t sub_type;
    if(type >= SETUP_TYPE_MAX) {
        LOGGING_ERR("Invalid type :type is %d", type);
        return RSVP_SUBTYPE_MAX;
    }
    sub_type = pccd_rpd_name_tree_setup_type[type].subtype_tree_count;
    return sub_type;
}

/**
 * pccd_rpd_get_name_tree
 *
 * Returns corresponding name_tree depending on type and sub_type
 *
 * @param[in] type    :
 *
 * @return  name_tree_t* :Returns name_tree pointer correspoding to type ans sub_type
 *          NULL         :If respective name_tree is not present
 */
static name_tree_t*
pccd_rpd_get_name_tree(uint8_t type, uint8_t sub_type)
{
    name_tree_t *tree_name;
    if(type >= SETUP_TYPE_MAX) {
        LOGGING_ERR("Invalid type :type is %d , sub_type is %d", type, sub_type);
        return NULL;
    }
    if(sub_type >= pccd_rpd_get_subtype_tree_count(type)) {
        LOGGING_ERR("Invalid sub_type :type is %d , sub_type is %d", type, sub_type);
        return NULL;
    }
    tree_name = (pccd_rpd_name_tree_setup_type[type].tree_name)[sub_type];
    return tree_name;
}

static void
pccd_rpd_transition_to_closed(void)
{
    TRACE_RPD("Entering CLOSED state");
    pccd_rpd_state = PCCD_RPD_STATE_CLOSED;
    if (pccd_rpd_state_change) {
        pccd_rpd_state_change(false);
    }
    pccd_rpd_delete_all_lsps();
}

static void
pccd_rpd_transition_to_connecting(void)
{
    TRACE_RPD("Entering CONNECTING state");
    LOGGING_INFO("RPD: Entering CONNECTING state");
    pccd_rpd_state = PCCD_RPD_STATE_CONNECTING;
}

static void
pccd_rpd_transition_to_connected(void)
{
    TRACE_RPD("Entering CONNECTED state");
    LOGGING_INFO("RPD: Entering CONNECTED state");
    pccd_rpd_state = PCCD_RPD_STATE_CONNECTED;
}

static bool
pccd_rpd_transition_to_acc(void)
{
    TRACE_RPD("Entering ACC state");
    LOGGING_INFO("RPD: Entering ACC state");
    INSIST_ERR(pccd_rpd_state == PCCD_RPD_STATE_CONNECTED);

    //FIXME: add timer for "wait for accepted message"
    pccd_rpd_state = PCCD_RPD_STATE_ACC;
    return true;
}

static void
pccd_rpd_transition_to_up(void)
{
    INSIST_ERR(pccd_rpd_state == PCCD_RPD_STATE_ACC);
    TRACE_RPD("Entering UP state");
    LOGGING_INFO("RPD: Entering UP state");
    pccd_rpd_state = PCCD_RPD_STATE_UP;

    if (pccd_rpd_state_change) {
        pccd_rpd_state_change(true);
    }

    /* clear get_all_lsps_info flag and get_all_flowspec_info flag */
    pccd_rpd_in_get_all_lsps_info = false;
    pccd_rpd_get_all_flowspec_info = false;
}

/* End of state machine functions */


/**
 * pccd_rpd_get_lsp_count
 *
 * Returns the total lsps count
 *
 * @param[in] void
 * @return total_lsps
 */
static uint32_t
pccd_rpd_get_lsp_count (void)
{
    return total_lsps;
}

/**
 * pccd_rpd_increment_lsp_count
 *
 * Increment the total lsps count
 *
 * @param[in] void
 * @return void
 */
static void
pccd_rpd_increment_lsp_count (void)
{
    total_lsps++;
}

/**
 * pccd_rpd_decrement_lsp_count
 *
 * Decrement the total lsps count
 *
 * @param[in] void
 * @return void
 */
static void
pccd_rpd_decrement_lsp_count (void)
{
    if (total_lsps > 0) {
        total_lsps--;
    } else {
        LOGGING_ERR("Error in decrementing lsp counts, %u", total_lsps);
    }
}

static void
pccd_rpd_free_lsp_div_assoc_info (struct pccd_rpd_lsp_info *lsp)
{
    if (lsp->div_assoc_info) {
        free(lsp->div_assoc_info);
        lsp->div_assoc_info = NULL;
    }
}

static void
pccd_rpd_free_lsp_buffers(struct pccd_rpd_lsp_info *lsp)
{
    if (lsp->ero_info) {
        free(lsp->ero_info);
        lsp->ero_info = NULL;
    }
    if (lsp->rro_info) {
        free(lsp->rro_info);
        lsp->rro_info = NULL;
    }
    if (lsp->error_spec_obj) {
        free(lsp->error_spec_obj);
        lsp->error_spec_obj = NULL;
    }
    bzero(lsp->assoc_info, (sizeof(lsp->num_assoc_info) * sizeof(lsp_association_info)));

    if (lsp->srte_ero_info) {
        free(lsp->srte_ero_info);
        lsp->srte_ero_info = NULL;
    }
    if (lsp->srte_rro_info) {
        free(lsp->srte_rro_info);
        lsp->srte_rro_info = NULL;
    }
}

/**
 * Free PCE Proposed ERO buffer while LSP cleaning
 */
static void
pccd_rpd_free_pce_proposed_ero(struct pccd_rpd_lsp_info *lsp)
{
    if (lsp->pce_proposed_ero_info) {
        free(lsp->pce_proposed_ero_info);
        lsp->pce_proposed_ero_info = NULL;
    }
    lsp->pce_proposed_ero_info_total = 0;
    lsp->pce_proposed_ero_info_len   = 0;
}

/**
 * Free Intended metric list
 */
void
pccd_rpd_free_intended_metric(struct pccd_rpd_lsp_info *lsp)
{
    TRACE_FUNCTION_ENTRY();
    struct lsp_metric_s *intended_metric = NULL;
    if (lsp) {
        while (!SLIST_EMPTY(&lsp->intended_attrs.intended_metric_head)) {
            intended_metric = SLIST_FIRST(&lsp->intended_attrs.intended_metric_head);
            SLIST_REMOVE(&lsp->intended_attrs.intended_metric_head, intended_metric,
                    lsp_metric_s, metric_next);
            free(intended_metric);
        }
        SLIST_INIT(&lsp->intended_attrs.intended_metric_head);
    }
    TRACE_FUNCTION_RETURN();
}

/**
 * Free Actual metric list
 */
void
pccd_rpd_free_actual_metric(struct pccd_rpd_lsp_info *lsp)
{
    TRACE_FUNCTION_ENTRY();
    struct lsp_metric_s *actual_metric = NULL;
    if (lsp) {
        while (!SLIST_EMPTY(&lsp->actual_metric_head)) {
            actual_metric = SLIST_FIRST(&lsp->actual_metric_head);
            SLIST_REMOVE(&lsp->actual_metric_head, actual_metric,
                    lsp_metric_s, metric_next);
            free(actual_metric);
        }
        SLIST_INIT(&lsp->actual_metric_head);
    }
    TRACE_FUNCTION_RETURN();
}

/**
 * Update PCE Proposed ERO as per LSP setup type
 */
void
pccd_rpd_update_pce_proposed_info(const rpd_extctrl_lsp_config_status_info_t *info)
{
    struct pccd_rpd_lsp_info *rpd_lsp_info = NULL;
    char name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE+1)];
    bzero(name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));

    if(strlen(info->path_name)) {
        snprintf(name, sizeof(name), "%s/%s", info->name, info->path_name);

    } else {
        snprintf(name, sizeof(name), "%s", info->name);

    }

    rpd_lsp_info = pccd_rpd_get_lsp_by_name(name);
    if (rpd_lsp_info) {

        /* Free PCE Proposed ERO if there is any */
        if (rpd_lsp_info->pce_proposed_ero_info != NULL) {
            pccd_rpd_free_pce_proposed_ero(rpd_lsp_info);
        }

        /* Update PCE proposed ERO for PCE Provisioned/Controlled */
        if ((info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
            (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
            unsigned len = info->srte_ero_len;
            if (len) {
                rpd_lsp_info->pce_proposed_ero_info = xmalloc(len);
                if (rpd_lsp_info->pce_proposed_ero_info != NULL) {
                    memcpy(rpd_lsp_info->pce_proposed_ero_info, info->srte_ero_info,
                        len);
                }
            }
            rpd_lsp_info->pce_proposed_ero_info_total = info->srte_total_ero_count;
            rpd_lsp_info->pce_proposed_ero_info_len = info->srte_ero_len;
        } else { /* RSVP LSPs */
            if (info->ero_len) {
                rpd_lsp_info->pce_proposed_ero_info = xmalloc(info->ero_len);
                if (rpd_lsp_info->pce_proposed_ero_info != NULL) {
                    memcpy(rpd_lsp_info->pce_proposed_ero_info, info->ero_info,
                        info->ero_len);
                }
            }
            rpd_lsp_info->pce_proposed_ero_info_total = 1;
            rpd_lsp_info->pce_proposed_ero_info_len = info->ero_len;
        }

        /* Store External LOCAL CSPF information received from PCE */
        rpd_lsp_info->prli_local_cspf = info->relcsi_local_cspf;
    }

}

/**
 * send SRPAG for colored SR LSPs from existing rpd_lsp
 * if not received in PCUpd as SRTE always expects SRPAG
 * info for colored LSPs
 */
static void
pccd_rpd_update_srpag(const struct pccd_rpd_lsp_info *rpd_lsp,
        rpd_extctrl_lsp_config_status_info_t *info)
{
    unsigned itr = 0;
    unsigned srpag_itr = 0;
    bool colored_sr_lsp = false;
    bool sending_srpag = false;
    if(!rpd_lsp)
        return;

    if ((info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
        (info->lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) ) {
        while ((itr < rpd_lsp->num_assoc_info) && (itr < LSP_ASSOCIATION_TYPE_MAX)) {
            if (LSP_ASSOCIATION_TYPE_SRPAG == rpd_lsp->assoc_info[itr].assoc_type) {
                colored_sr_lsp = true;
                srpag_itr = itr;
            }

            if (LSP_ASSOCIATION_TYPE_SRPAG == info->assoc_info[itr].assoc_type) {
                sending_srpag = true;
            }
            itr++;
        }

        if((true == colored_sr_lsp) && (false == sending_srpag)) {
            /* Send SRPAG from rpd_lsp as SRTE always expects SRPAG for colored LSP*/
            TRACE_RPD("Sending SRPAG in db to RPD");
            info->assoc_info[info->num_assoc_info].assoc_type = LSP_ASSOCIATION_TYPE_SRPAG;
            info->assoc_info[info->num_assoc_info].assoc_grp_id = rpd_lsp->assoc_info[srpag_itr].assoc_grp_id;
            info->assoc_info[info->num_assoc_info].is_assoc_src_ipv6 =
                    rpd_lsp->assoc_info[srpag_itr].is_assoc_src_ipv6;

            if (!info->assoc_info[info->num_assoc_info].is_assoc_src_ipv6) {
                info->assoc_info[info->num_assoc_info].assoc_source_u.v4 =
                        rpd_lsp->assoc_info[srpag_itr].assoc_source_u.v4;
            } else {
                memcpy(info->assoc_info[info->num_assoc_info].assoc_source_u.v6,
                        rpd_lsp->assoc_info[srpag_itr].assoc_source_u.v6, 16);
            }

            info->assoc_info[info->num_assoc_info].sr_srpag_t.color = 
                rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.color;
            info->assoc_info[info->num_assoc_info].sr_srpag_t.sr_proto_origin = 
                rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.sr_proto_origin;
            info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_asn = 
                rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.originator_asn;
            info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_endpoint_ipv6 =
                    rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.is_srpag_endpoint_ipv6;
            info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_originator_ipv6 =
                    rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.is_srpag_originator_ipv6;

            if (!info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_originator_ipv6) {
                info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v4 =
                        rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.originator_addr_u.v4;
            } else {
                memcpy(info->assoc_info[info->num_assoc_info].sr_srpag_t.originator_addr_u.v6,
                        rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.originator_addr_u.v6, 16);
            }

            if (!info->assoc_info[info->num_assoc_info].sr_srpag_t.is_srpag_endpoint_ipv6) {
                info->assoc_info[info->num_assoc_info].sr_srpag_t.srpag_endpoint_addr_u.v4 =
                        rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.srpag_endpoint_addr_u.v4;
            } else {
                memcpy(info->assoc_info[info->num_assoc_info].sr_srpag_t.srpag_endpoint_addr_u.v6,
                        rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.srpag_endpoint_addr_u.v6, 16);
            }
            info->assoc_info[info->num_assoc_info].sr_srpag_t.discriminator = 
                rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.discriminator;
            info->assoc_info[info->num_assoc_info].sr_srpag_t.preference_valid = 
                rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.preference_valid;

            if (rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.preference_valid) {
                info->assoc_info[info->num_assoc_info].sr_srpag_t.preference = 
                    rpd_lsp->assoc_info[srpag_itr].sr_srpag_t.preference;
            }

            info->num_assoc_info++;
        }
    }
}


/**
 * Get the next lsp id.
 */
static uint32_t
pccd_rpd_lsp_id_alloc(void)
{
    ++lsp_id;
    if (lsp_id > MAX_LSP_ID) {
        lsp_id = 1;
    }

    return lsp_id;
}

/**
 * Delete all LSPs stored in pccd_rpd's cache.
 */
static void
pccd_rpd_delete_all_lsps(void)
{
    uint8_t type = 0;
    uint8_t sub_type = 0;
    name_tree_t *tree_name;
    pccd_rpd_lsp *lsp = NULL;
    rbnode *_curr, *_next;
    char *value = NULL;

    TRACE_RPD("Deleting all LSPs");

    if (lspid_tree) {
        _curr = junos_redblack_find_next(lspid_tree, NULL);
        for (; _curr; _curr = _next) {

            _next = junos_redblack_find_next(lspid_tree, _curr);
            pccd_rpd_rbtree_delete(_curr);
            pccd_rpd_decrement_lsp_count();
        }
    }

    do {
        tree_name = pccd_rpd_get_name_tree(type,sub_type);
        if(NULL == tree_name) {
            LOGGING_ERR("Error finding internal storage while deleting all LSPs");
            return;
        }

        while (!name_tree_isempty(tree_name)) {
            const char *key = name_tree_first_key(tree_name);
            INSIST_ERR(key != NULL);
            lsp = name_tree_delete(tree_name, key);
            if(tree_name == (&pccd_rpd_rsvp_p2mp_name_tree)) {
                pccd_p2mp_remove_branch_lsp(&lsp->lsp_info, true);
            }

            /* NSR Begin */
            /**
            * Inform replication module about lsp deletion, so that
            * replication module will unresolve the replication lsp 
            */
            if (lsp->lsp_info.type != LSP_TYPE_CLI_REGULAR_SIGNALLED) {
                pccd_repl_handle_delete_lsp(&lsp->lsp_info);
            }
            /* NSR End */

            pccd_rpd_free_lsp_buffers(&lsp->lsp_info);
            pccd_rpd_free_lsp_div_assoc_info(&lsp->lsp_info);
            pccd_rpd_free_pce_proposed_ero(&lsp->lsp_info);
            pccd_rpd_free_intended_metric(&lsp->lsp_info);
            pccd_rpd_free_actual_metric(&lsp->lsp_info);

            /* Delete all prefix info from lsp */
            pccd_rpd_lsp_delete_all_prefix_info(lsp->lsp_info.prefix_root);
            lsp->lsp_info.prefix_root = NULL;

            INSIST_ERR(lsp != NULL);
            free(lsp);
        }

        sub_type++;
        if(sub_type >= pccd_rpd_get_subtype_tree_count(type))  {
            type++;
            sub_type = 0;
        }
    }while(type < SETUP_TYPE_MAX);

    /* delete all entries from pccd_rpd_sr_color_name_tree */
    while (!name_tree_isempty(&sr_color_cpath_table)) {
        const char *key = name_tree_first_key(&sr_color_cpath_table);
        INSIST_ERR(key != NULL);
        value = name_tree_delete(&sr_color_cpath_table, key);
        INSIST_ERR(value != NULL);
        free(value);
    }

    INSIST_ERR(pccd_rpd_get_lsp_count() == 0);

    if (!name_tree_isempty(&pccd_p2mp_lsps)) {
        TRACE_RPD("P2MP tree should be clean here, but not. Error condition");
    }
}

/**
 * Requests info about all LSPs from RPD, and turns the responses from RPD
 * to reports towards the pccd_rpd's client once they all come back. Only
 * one get_all_lsps request may be in process in any point in time.
 * @return false if the connection with RPD is not in UP state, or if the
 *         sending of the message to RPD failed; otherwise true.
 */
bool
pccd_rpd_get_all_lsps()
{
    TRACE_FUNCTION_ENTRY();
    if (pccd_rpd_state < PCCD_RPD_STATE_UP) {
        TRACE_RPD("RPD connection not in UP state, can't request LSP list");
        TRACE_FUNCTION_RETURN(false);
    }

    if (pccd_rpd_in_get_all_lsps_info == true) {
        TRACE_RPD("One get-all-lsps-info request is already in process, "
                  "ignoring this one");
        TRACE_FUNCTION_RETURN(true);
    }

    if (pccd_rpd_lsp_get_info_all_send(pccd_rpd_ses_hndl, false)) {
        LOGGING_ERR("Failed to request all LSPs from RPD");
        if (pccd_rpd_reconnect()) {
            if (pccd_rpd_schedule_reconnect()) {
                /* If we failed to even schedule a reconnection, can't do much
                 * more here. */
                abort();
            }
        }
        TRACE_FUNCTION_RETURN(false);
    }

    pccd_rpd_in_get_all_lsps_info = true;
    pccd_rpd_lsp_batch_end_count = 0;

    TRACE_FUNCTION_RETURN(true);
}

/**
 * Requests info about particular LSP from RPD. 
 * @return false if the connection with RPD is not in UP state, or if the
 *         sending of the message to RPD failed; otherwise true.
 */
bool
pccd_rpd_get_one_lsp(const char *lsp_name,
                         const char *path_name,
                         const uint8_t setup_type, 
                         const uint8_t sub_type,
                         const uint32_t context)
{
    TRACE_FUNCTION_ENTRY();

    if (pccd_rpd_state < PCCD_RPD_STATE_UP) {
        TRACE_RPD("RPD connection not in UP state, can't request LSP");
        TRACE_FUNCTION_RETURN(false);
    }

    TRACE_RPD("Sending get_lsp request to RPD for lsp '%s'", lsp_name);
    if (pccd_rpd_lsp_get_info_send(pccd_rpd_ses_hndl, lsp_name, path_name,
                                   setup_type, sub_type, context)) {
        TRACE_RPD("pccd_rpd_lsp_get_lsp_send failed: %d '%s'", errno,
                  strerror(errno));                           
        LOGGING_ERR("pccd_rpd_lsp_get_lsp_send failed: %d '%s'", errno,
                    strerror(errno));
        TRACE_FUNCTION_RETURN(false);
    }

    TRACE_FUNCTION_RETURN(true);
}

static bool
pccd_rpd_session_close(evContext ctx, rpd_session_handle handle)
{
    int ret = 0;

    if (evTestID(pccd_rpd_read_id)) {
        evDeselectFD(ctx, pccd_rpd_read_id);
        evInitID(&pccd_rpd_read_id);
    }

    if (evTestID(pccd_rpd_write_id)) {
        evDeselectFD(ctx, pccd_rpd_write_id);
        evInitID(&pccd_rpd_write_id);
    }

    ret = rpd_session_close(handle);
    if (ret) {
	LOGGING_ERR("Could not close connection with RPD gracefully.");
    }

    return !!ret;
}

static void
pccd_rpd_ses_connect_cb(rpd_session_handle handle, u_int32_t ctx UNUSED,
                        enum session_connect_return code)
{
    switch(code) {
    case RPD_SC_SUCCESS:
	LOGGING_INFO("Connection with rpd established!");
        pccd_rpd_transition_to_connected();
        if (rpd_client_identify(pccd_rpd_ses_hndl, PCCD_RPD_CLIENT_ID) == -1) {
            LOGGING_ERR("rpd_pccd_identify failed: %d %s", errno,
                        strerror(errno));
            if (pccd_rpd_reconnect()) {
                if (pccd_rpd_schedule_reconnect()) {
                    exit(EX_SOFTWARE);
                }
            }
            return;
        }

        pccd_rpd_transition_to_acc();
        break;
    default:
        LOGGING_ERR("Connection to RPD failed");
        pccd_rpd_session_close(pccd_rpd_ev_ctx, pccd_rpd_ses_hndl);
        pccd_rpd_transition_to_closed();
        INSIST_ERR(pccd_rpd_schedule_reconnect() == 0);
        break;
    }
}

static void
pccd_rpd_ses_state_cb(rpd_session_handle handle, u_int32_t ctx UNUSED,
                      enum session_state state)
{
    /* PCCD got disconnected from RPD, try to reconnect */
    if (state != RPD_SS_DOWN) {
        LOGGING_ERR("Unknown session state: %d", state);
    }
    pccd_rpd_cleanup_frag_state();
    if (pccd_rpd_reconnect()) {
        if (pccd_rpd_schedule_reconnect()) {
            exit(EX_SOFTWARE);
        }
    }
}

static void
pccd_rpd_sock_writable_cb(evContext ctx UNUSED, void *uap, int fd UNUSED,
                          int evmask)
{
    rpd_session_handle handle;

    INSIST_ERR(evmask == EV_WRITE);
    INSIST_ERR(uap != NULL);

    handle = uap;
    rpd_session_write_callback(handle);
}

static void
pccd_rpd_register_write_cb(rpd_session_handle handle)
{
    int fd = rpd_session_handle_descriptor(handle);
    if (fd == -1) {
        LOGGING_ERR("librpd wants to register descriptor for select(), "
                    "but fails to provide file descriptor");
        exit(EX_SOFTWARE);
    }

    if (evTestID(pccd_rpd_write_id)) {
        /* For some reason, librpd is re-registering RPD's FD for writable cb */
        if (evDeselectFD(pccd_rpd_ev_ctx, pccd_rpd_write_id) == -1) {
            LOGGING_ERR("Could not deregister RPD's FD from eventloop");
            exit(EX_SOFTWARE);
        }
        evInitID(&pccd_rpd_write_id);
    }

    TRACE_RPD("EV_WRITE evSelectFD on RPD's FD %d", fd);
    if (evSelectFD(pccd_rpd_ev_ctx, fd, EV_WRITE,
                   pccd_rpd_sock_writable_cb, handle,
                   &pccd_rpd_write_id) == -1) {
        LOGGING_ERR("Could not register rpd's fd %d for EV_WRITE", fd);
        exit(EX_SOFTWARE);
    }
}

static void
pccd_rpd_unregister_write_cb(rpd_session_handle handle UNUSED)
{
    if (evTestID(pccd_rpd_write_id) &&
            evDeselectFD(pccd_rpd_ev_ctx, pccd_rpd_write_id) == -1) {
        LOGGING_ERR("Could not deselect librpd's sock fd from event "
                    "context");
        exit(EX_SOFTWARE);
    }
    evInitID(&pccd_rpd_write_id);
    TRACE_RPD("Unregistered RPD's FD from eventloop");
}

struct rpd_client_functions funcs = {
        .session_connect = pccd_rpd_ses_connect_cb,
        .session_state = pccd_rpd_ses_state_cb,
        .protocol_register = NULL,
        .protocol_unregister = NULL,
        .rt_add = NULL,
        .rt_delete = NULL,
        .rt_lookup = NULL,
        .rt_change_gw = NULL,
        .rt_instance_state = NULL, /*NULL*/
        .rt_table_locate = NULL,
        .register_write = pccd_rpd_register_write_cb,
        .unregister_write = pccd_rpd_unregister_write_cb,
        .alias_op_complete = NULL,
        .interface_event = NULL,
        .ra_event = NULL,
        .local_as_info = NULL,
        .rt_flash_reg = NULL
};

static const char*
pccd_rpd_debug_get_trigger_reason (uint32_t reason)
{
    static char buf[1024];
    buf[0] = '\0';

    if (reason & RPD_MSG_REASON_RECONFIGURED) {
        strlcat(buf, " RPD_MSG_REASON_RECONFIGURED", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_RECONFIGURED;
    }
    if (reason & RPD_MSG_REASON_LSP_RESTARTED) {
        strlcat(buf, " RPD_MSG_REASON_LSP_RESTARTED", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_RESTARTED;
    }
    if (reason & RPD_MSG_REASON_LSP_MAINTENANCE) {
        strlcat(buf, " RPD_MSG_REASON_LSP_MAINTENANCE", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_MAINTENANCE;
    }
    if (reason & RPD_MSG_REASON_LSP_CTRL_CHANGE) {
        strlcat(buf, " RPD_MSG_REASON_LSP_CTRL_CHANGE", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_CTRL_CHANGE;
    }
    if (reason & RPD_MSG_REASON_LSP_GET_INFO) {
        strlcat(buf, " RPD_MSG_REASON_LSP_GET_INFO", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_GET_INFO;
    }
    if (reason & RPD_MSG_REASON_RETRY_PCREQUEST) {
        strlcat(buf, " RPD_MSG_REASON_RETRY_PCREQUEST", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_RETRY_PCREQUEST;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_ACTIVE) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_ACTIVE", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_ACTIVE;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_DEACTIVE) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_DEACTIVE", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_DEACTIVE;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_UP) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_UP", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_UP;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_DOWN) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_DOWN", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_DOWN;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_REOPTIMIZATION) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_REOPTIMIZATION", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_REOPTIMIZATION;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_NEW_RRO_CHANGED) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_NEW_RRO_CHANGED", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_NEW_RRO_CHANGED;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_STATE_CHANGE) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_STATE_CHANGE", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_STATE_CHANGE;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_UPDATE_REQUEST) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_UPDATE_REQUEST", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_UPDATE_REQUEST;
    }
    if (reason & RPD_MSG_REASON_LSP_PATH_CSPF_FAILED) {
        strlcat(buf, " RPD_MSG_REASON_LSP_PATH_CSPF_FAILED", sizeof(buf));
        reason = reason & ~(uint32_t)RPD_MSG_REASON_LSP_PATH_CSPF_FAILED;
    }
    return buf;
}

static const char *
pccd_rpd_lsp_path_flags_get_string (u_int16_t config_flags)
{
    static char flags_str[256];

    if (!config_flags) {
        return "0";
    }
    
    flags_str[0] = '\0';

    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_PRIMARY)) {
        strlcat(flags_str, " Primary", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_SECONDARY)) {
        strlcat(flags_str, " Sec", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_SECONDARY_STANDBY)) {
        strlcat(flags_str, " Sec-SB", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_BYPASS)) {
        strlcat(flags_str, " Bypass", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_AUTOBW)) {
        strlcat(flags_str, " AUTOBW", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_TE_PLUS_PLUS)) {
        strlcat(flags_str, " TEPP", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_LOCAL_PROTECTION_DESIRED)) {
        strlcat(flags_str, " LocalProt-Desired", sizeof(flags_str));
    }
    /*
     * FIXME:
     * pls uncomment the code below once we have automated testcase to cover
     * this
     */
#if 0
    if (BIT_ISSET(config_flags, LSP_PATH_STATE_ASSOCIATION_REMOVED)) {
        strlcat(flags_str, " Assoc-Removed", sizeof(flags_str));
    }
#endif    
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_P2MP)) {
        strlcat(flags_str, " P2mp", sizeof(flags_str));
    }
    if (BIT_ISSET(config_flags, LSP_PATH_MBB_IN_PROGRESS)) {
        strlcat(flags_str, " MBB-In-Progress", sizeof(flags_str));
    }

    return flags_str;
}

static void
pccd_rpd_print_sr_ero_info(rpd_sr_ero_list_t *rpd_sr_ero)
{   
    struct in_addr addr;
    TRACE_RPD("Number of SR-ERO subobjects: %d", rpd_sr_ero->rsel_n_eros);
    for (unsigned i = 0; i < rpd_sr_ero->rsel_n_eros; i++) {
        rpd_sr_ero_t *sr_ero  = &rpd_sr_ero->rsel_ero[i];
        TRACE_RPD("SR-ERO loose_type: %d", sr_ero->rse_loose);
        TRACE_RPD("SR-ERO SID label type: %d", sr_ero->rse_sid.rses_type);
        switch(sr_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                TRACE_RPD("SID is absent");
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
                TRACE_RPD("SR-ERO sid value: %d", sr_ero->rse_sid.u.rses_label_20);
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
                TRACE_RPD("SR-ERO sid value: %d", sr_ero->rse_sid.u.rses_label_32);
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
                TRACE_RPD("SR-ERO sid value: %d", sr_ero->rse_sid.u.rses_index);
                break;
            default:
                TRACE_RPD("Unknow SID type is received");
        }
        TRACE_RPD("SR-ERO NAI type: %d", sr_ero->rse_nai.rsen_type);
        switch(sr_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                TRACE_RPD("NAI is absent");
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_node_ipv4_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_RPD("SR-ERO IPv4-Node addr for subobject %i: %s", i, inet_ntoa(addr));
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                TRACE_RPD("SR-ERO NAI is Node IPv6 address");
                break;
#endif
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_local_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_RPD("SR-ERO IPv4-ADJ local addr for subobject %i: %s", i, inet_ntoa(addr));
                memcpy(&addr.s_addr, &sr_ero->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr, 
                                                        sizeof(addr.s_addr));
                TRACE_RPD("SR-ERO IPv4-ADJ remote addr for subobject %i: %s", i, inet_ntoa(addr));
                
                break;
#ifdef PCEP_SR_IPV6
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                TRACE_RPD("SR-ERO NAI is ADJ IPv6 address");
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
                TRACE_RPD("SR-ERO NAI is Unnumbered address");
                break;
#endif
            default:
                TRACE_RPD("Unknown segment object NAI type: %d", 
                            sr_ero->rse_nai.rsen_type);
        }
    }
}

static void
pccd_rpd_print_srv6_ero_info(rpd_sr_ero_list_t *rpd_sr_ero)
{
    TRACE_RPD("Number of SRv6-ERO subobjects: %d", rpd_sr_ero->rsel_n_eros);
    for (unsigned i = 0; i < rpd_sr_ero->rsel_n_eros; i++) {
        rpd_sr_ero_t *srv6_ero  = &rpd_sr_ero->rsel_ero[i];
        TRACE_RPD("SR-ERO loose_type: %d, sid_verification: %d, "
                "sid structure valid: %d, endpoint behavior: %d",
                srv6_ero->rse_srv6_loose, srv6_ero->rse_srv6_sid_verification,
                srv6_ero->rse_srv6_sid_structure_valid, srv6_ero->rse_srv6_endpoint_behavior);
        TRACE_RPD("SR-ERO SID label type: %d", srv6_ero->rse_sid.rses_type);
        switch(srv6_ero->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                TRACE_RPD("SID is absent");
                break;
            case RPD_SR_ERO_SID_TYPE_SRV6: {
                char sidstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_sid.u.rses_addr, sidstr_ipv6, sizeof(sidstr_ipv6));
                TRACE_RPD("SR-ERO sid value: %s", sidstr_ipv6);
            }
                break;
            default:
                TRACE_RPD("Unknow SID type is received");
        }
        TRACE_RPD("SR-ERO NAI type: %d", srv6_ero->rse_nai.rsen_type);
        switch(srv6_ero->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                TRACE_RPD("NAI is absent in SRv6 ERO");
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID: {
                char nodeidstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_node_ipv6_addr, nodeidstr_ipv6, sizeof(nodeidstr_ipv6));

                TRACE_RPD("SRv6-ERO IPv6-Node addr for subobject %i: %s", i, nodeidstr_ipv6);
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                TRACE_RPD("SRv6-ERO IPv6-ADJ local addr for subobject %i: %s", i, localipstr_ipv6);
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                TRACE_RPD("SRv6-ERO IPv6-ADJ remote addr for subobject %i: %s", i, remoteipstr_ipv6);
            }
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ: {
                char localipstr_ipv6[INET6_ADDRSTRLEN] = "";
                char remoteipstr_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr,
                        localipstr_ipv6, sizeof(localipstr_ipv6));
                TRACE_RPD("SRv6-ERO IPv6-ADJ local addr, interface id for subobject %i: %s, %u",
                        i, localipstr_ipv6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id);
                inet_ntop(AF_INET6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr,
                        remoteipstr_ipv6, sizeof(remoteipstr_ipv6));
                TRACE_RPD("SRv6-ERO IPv6-ADJ remote addr, interface id for subobject %i: %s, %u",
                        i, remoteipstr_ipv6, srv6_ero->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id);
            }
                break;
            default:
                TRACE_RPD("Unknown segment object NAI type: %d",
                            srv6_ero->rse_nai.rsen_type);
        }

        if (srv6_ero->rse_srv6_sid_structure_valid) {
            TRACE_CORE("SRv6-ERO sid structure: lb length: %d, ln length: %d"
                       "fun length: %d, arg length: %d",
                       srv6_ero->rse_srv6_sid_structure.lb_length,
                       srv6_ero->rse_srv6_sid_structure.ln_length,
                       srv6_ero->rse_srv6_sid_structure.fun_length,
                       srv6_ero->rse_srv6_sid_structure.arg_length);
        }
    }
}

#define PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN 1024
static void
pccd_rpd_debug_lsp_info (const char* custom_prefix_msg,
			 const	     rpd_extctrl_lsp_config_status_info_t *info)
{
    char	   assoc_str[PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN] = {0};
    char src[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
    u_int32_t count = 0, div_count = 0;
    const rpd_disjoint_assoc_block_t *dag_info=NULL;

    memset(src, 0, INET6_ADDRSTRLEN);
    memset(dest, 0, INET6_ADDRSTRLEN);

    if (!info->is_lsp_src_dst_addr_type_ipv6) {
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = (in_addr_t) info->srcaddr_u.v4;
        dst_addr.s_addr = (in_addr_t) info->dstaddr_u.v4;
        memcpy(src, inet_ntoa(src_addr), 20);
        memcpy(dest, inet_ntoa(dst_addr), 20);
    } else {
        struct in6_addr srcv6_addr, dstv6_addr;
        memcpy(&srcv6_addr, info->srcaddr_u.v6, 16);
        memcpy(&dstv6_addr, info->dstaddr_u.v6, 16);
        inet_ntop(AF_INET6, &srcv6_addr, src, sizeof(src));
        inet_ntop(AF_INET6, &dstv6_addr, dest, sizeof(dest));
    }

    TRACE_RPD("%s name(%s) path(%s) template(%s) is src dest ipv6(%d) src(%s) dst(%s) "
	    "msg_trigger(%s) type(%"PRIu16") state(%"PRIu16") "
	    "control(%"PRIu8") flags(0x%x) admin grp exclude(%"PRIu32") "
	    "admin grp include any(%"PRIu32") admin grp include all(%"PRIu32")"
	    " setup prio(%u) hold prio(%u) bw(%"PRIu64"bps) conf_bw(%"PRIu64"bps) metric(%"PRIu32")"
            " binding type (%"PRIu16") binding value (%"PRIu32")",
	    custom_prefix_msg,
	    info->name, info->path_name, info->template_name,
	    info->is_lsp_src_dst_addr_type_ipv6, src, dest,
	    pccd_rpd_debug_get_trigger_reason(info->msg_trigger_reason),
	    info->type, info->state, info->control_status, info->lsp_flags,
	    info->relcsi_admin_grp_exclude_any,
	    info->relcsi_admin_grp_include_any,
	    info->relcsi_admin_grp_include_all,
	    info->setup_prio, info->hold_prio, info->bandwidth,
	    info->configured_bandwidth, info->metric,
            info->lsp_binding_sid.binding_type,
            info->lsp_binding_sid.binding_value);
    TRACE_RPD("    lsp_id(%"PRIu16") tunnel_id(%"PRIu16") setup_type(%u) sub_type(%u)"
        "ero(%p) ero_len(%zu) rro(%p) rro_len(%zu) sr-ero(%p), sr-ero_len(%zu) "
        "sr-rro(%p) sr-rro_len(%zu) err_spec(%p) err_spec_len(%zu) #assoc(%d)",
        info->lsp_id, info->tunnel_id, info->lsp_type_info.setup_type,
        info->lsp_type_info.sub_type ,info->ero_info, info->ero_len,
        info->rro_info, info->rro_len, info->srte_ero_info,
        info->srte_ero_len,
        info->srte_rro_info,
        info->srte_rro_len,
        info->error_spec_obj,
        info->error_spec_obj_len, info->num_assoc_info);

    if (info->srte_ero_info) {
        int counter = 0;
        rpd_sr_ero_list_t *srte_ero_list = info->srte_ero_info;
        if (srte_ero_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
            for (counter=0; counter < info->srte_total_ero_count; counter++) {
                TRACE_RPD(" SRTE ERO (%u/%u): ", counter+1, info->srte_total_ero_count);
                pccd_rpd_print_sr_ero_info(srte_ero_list);
                srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
            }
        } else {
            for (counter=0; counter < info->srte_total_ero_count; counter++) {
                TRACE_RPD(" SRv6 ERO (%u/%u): ", counter+1, info->srte_total_ero_count);
                pccd_rpd_print_srv6_ero_info(srte_ero_list);
                srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
            }
        }
    }
    if (info->srte_rro_info) {
        int counter = 0;
        rpd_sr_ero_list_t *srte_rro_list = info->srte_rro_info;
        if (srte_rro_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
            for (counter=0; counter < info->srte_total_rro_count; counter++) {
                TRACE_RPD(" SRTE RRO (%u/%u): ", counter+1, info->srte_total_rro_count);
                pccd_rpd_print_sr_ero_info(info->srte_rro_info);
                srte_rro_list = (rpd_sr_ero_list_t *)&(srte_rro_list->rsel_ero[srte_rro_list->rsel_n_eros]);
            }
        } else {
            for (counter=0; counter < info->srte_total_rro_count; counter++) {
                TRACE_RPD(" SRv6 RRO: (%u/%u): ", counter+1, info->srte_total_rro_count);
                pccd_rpd_print_srv6_ero_info(info->srte_rro_info);
                srte_rro_list = (rpd_sr_ero_list_t *)&(srte_rro_list->rsel_ero[srte_rro_list->rsel_n_eros]);
            }
        }
    }

    while (count < info->num_assoc_info) {
	snprintf(assoc_str, PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN,
		"grp_id[%u] type[%u] Total[%u] count[%u] grp_id[%u]",
		  info->assoc_info[count].assoc_grp_id,
		  info->assoc_info[count].assoc_type, info->num_assoc_info,
		  count, info->assoc_info[count].assoc_grp_id);

	if (info->assoc_info[count].assoc_flags & LSP_PATH_TYPE_PRIMARY) {
	    snprintf(assoc_str + strnlen(assoc_str, PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN),
		    PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN-1,
		    "-pri path-");
	}
	if (info->assoc_info[count].assoc_flags & LSP_PATH_TYPE_SECONDARY) {
	    snprintf(assoc_str + strnlen(assoc_str, PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN),
		    PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN-1,
		    "-sec path-");
	}
	count++;
    }

    while (div_count < info->div_assoc_info_count) {
        dag_info = &info->div_assoc_info[div_count].disjoint_assoc_list;
        if (dag_info->assoc_conf_info_valid) {
            snprintf(assoc_str + strnlen(assoc_str, PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN),
                    PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN-1,
                    " (div-assoc-conf-group-%u-conf-flags -%u %u %u %u %u- )",
                    info->div_assoc_info[div_count].assoc_grp_id,
                    dag_info->assoc_conf_info.link_diverse,
                    dag_info->assoc_conf_info.node_diverse,
                    dag_info->assoc_conf_info.srlg_diverse,
                    dag_info->assoc_conf_info.strictness,
                    dag_info->assoc_conf_info.shortest_first);
        }
        if (dag_info->assoc_status_info_valid) {
            snprintf(assoc_str + strnlen(assoc_str, PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN),
                    PCCD_RPD_DEBUG_LSP_INFO_ASSOC_OBJ_MAX_LEN-1,
                    " (div-assoc-status-group-%u-status-flags -%u %u %u %u %u- )",
                    info->div_assoc_info[div_count].assoc_grp_id,
                    dag_info->assoc_status_info.link_diverse,
                    dag_info->assoc_status_info.node_diverse,
                    dag_info->assoc_status_info.srlg_diverse,
                    dag_info->assoc_status_info.strictness,
                    dag_info->assoc_status_info.shortest_first);
        }
        div_count++;
    }

    TRACE_RPD("    path_flags(%s) new AuBw(%"PRIu64"bps) #paths(%d) assoc(%s)"
	    "local_cspf(%"PRIu8")",
	    pccd_rpd_lsp_path_flags_get_string(info->path_flags),
	    info->auto_bandwidth, info->num_paths, assoc_str,
	    info->relcsi_local_cspf);
	
	if (info->rbyp_params.rbp_nhaddr.rbn_ipv4_addr != 0) {
		TRACE_RPD("\n Bypass params: Nexthop(0x%x) Protection Type(%d)"
			" Subscription Rate(%d)",
			info->rbyp_params.rbp_nhaddr.rbn_ipv4_addr,
			info->rbyp_params.rbp_prot_type,
			info->rbyp_params.rbp_subscr);
	}

    if (info->optimization_metric_list) {
        TRACE_RPD("\n Optimization metric::");
        for (uint32_t i = 0; i < info->optimization_metric_list->list_len; i++) {
            TRACE_RPD("metric type (%u) ",
                    info->optimization_metric_list->metric_type[i]);
        }
    }

    if (info->bound_metric_list) {
        TRACE_RPD("\n Bounded metric::");
        for (uint32_t i = 0; i < info->bound_metric_list->list_len; i++) {
            TRACE_RPD("metric type (%u), metric value(%qu)",
                    info->bound_metric_list->metric[i].metric_type,
                    info->bound_metric_list->metric[i].metric_val);
        }
    }

    if (info->actual_metric_list) {
        TRACE_RPD("\n Actual metric::");
        for (uint32_t i = 0; i < info->actual_metric_list->list_len; i++) {
            TRACE_RPD("metric type (%u), metric value(%qu)",
                    info->actual_metric_list->metric[i].metric_type,
                    info->actual_metric_list->metric[i].metric_val);
        }
    }
	
    return;
}

/**
 * pccd_rpd_get_lsp_by_name
 *
 * Searches given name in all name trees and returns pointer to pccd_rpd_lsp_info
 *
 * @param[in] name :
 *
 * @return  Returns pointer to pccd_rpd_lsp_info, if name is found in any name_tree
 *          Returns NULL, if name is not found in any name tree
 */

struct pccd_rpd_lsp_info *
pccd_rpd_get_lsp_by_name(const char name[RPD_LSP_NAME_SIZE +1])
{
    uint8_t type = 0;
    uint8_t sub_type = 0;
    pccd_rpd_lsp *rpd_lsp = NULL;
    do {
        name_tree_t *tree_name = pccd_rpd_get_name_tree(type,sub_type);
        if(NULL == tree_name) {
            return NULL;
        }
        rpd_lsp = name_tree_lookup(tree_name, name);
        if(rpd_lsp) {
            break;
        }
        sub_type++;
        if(sub_type >= pccd_rpd_get_subtype_tree_count(type))  {
            type++;
            sub_type = 0;
        }
    }while( (type < SETUP_TYPE_MAX) && (!rpd_lsp)); 

    if (!rpd_lsp) {
        TRACE_RPD("Can't find lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
            name, type, sub_type);
        return NULL;
    }
    TRACE_RPD("Found lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
        name, type, sub_type);
    return &rpd_lsp->lsp_info;
}


/**
 * pccd_rpd_get_lsp_by_name_and_preference
 *
 * Search for rpd_lsp in the preferrred name_tree first and if rpd_lsp is not found, search in
 *   remining name_trees
 *
 * @param[in] name                  :
 *            preferred_type        : 
 *            preferred_sub_type    : 
 *
 * @return  NULL                    : When lsp is not found in any name_tree
 *          pccd_rpd_lsp_info *     : When lsp is found in name_tree
 */
struct pccd_rpd_lsp_info *
pccd_rpd_get_lsp_by_name_and_preference(const char name[RPD_LSP_NAME_SIZE +1], 
                                                       uint8_t preferred_type,
                                                       uint8_t preferred_sub_type)
{
    uint8_t type = 0;
    uint8_t sub_type = 0;
    pccd_rpd_lsp *rpd_lsp = NULL;
    name_tree_t *tree_name;
    /*Search first in preferred tree*/
    tree_name = pccd_rpd_get_name_tree(preferred_type, preferred_sub_type);
    if(NULL == tree_name) {
        return NULL;
    }
    rpd_lsp = name_tree_lookup(tree_name, name);

    while((type < SETUP_TYPE_MAX) && (!rpd_lsp)) {
        
        if((type != preferred_type) || (sub_type != preferred_sub_type)) {
            tree_name = pccd_rpd_get_name_tree(type,sub_type);
            if(NULL == tree_name) {
                return NULL;
            }
            rpd_lsp = name_tree_lookup(tree_name, name);
            if(rpd_lsp) {
                break;
            }
        }
        sub_type++;

        if(sub_type >= pccd_rpd_get_subtype_tree_count(type)) {
            type++;
            sub_type = 0;
        }
    }

    if (!rpd_lsp) {
        TRACE_RPD("Can't find lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
            name, type, sub_type);
        return NULL;
    }
    TRACE_RPD("Found lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
        name, type, sub_type);
    return &rpd_lsp->lsp_info;
}

/**
 * pccd_rpd_get_specific_lsp
 *
 * Searches given name in specified trees and returns pointer to pccd_rpd_lsp_info
 *
 * @param[in] name :
 * @param[in] type :
 * @param[in] sub_type :
 *
 * @return  Returns pccd_rpd_lsp_info pointer, if name is found in any name_tree
 *          Returns NULL, if name is not found in any name tree
 */
struct pccd_rpd_lsp_info *
pccd_rpd_get_specific_lsp(const char name[RPD_LSP_NAME_SIZE +1], 
                                                   const uint8_t type,
                                                   const uint8_t sub_type)
{
    pccd_rpd_lsp *rpd_lsp = NULL;
    name_tree_t *tree_name = NULL;

    if(sub_type >= pccd_rpd_get_subtype_tree_count(type)) {
        TRACE_RPD("Invalid sub_type received:%d", sub_type);
        return NULL;
    }

    tree_name = pccd_rpd_get_name_tree(type,sub_type);
    if(NULL == tree_name) {
        return NULL;
    }
    rpd_lsp = name_tree_lookup(tree_name, name);

    if (!rpd_lsp) {
        TRACE_RPD("Can't find lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
            name, type, sub_type);
        return NULL;
    }
    TRACE_RPD("Found lsp '%s' in local LSP cache, type is %d and sub_type is %d", 
        name, type, sub_type);
    return &rpd_lsp->lsp_info;
}


/**
 * pccd_rpd_delete_lsp_from_name_tree
 *
 * delete LSP entry in correponding name tree
 *
 * @param[in] name :
 *
 * @return  Returns pccd_rpd_lsp pointer, if name is found in any name_tree
 *          Returns NULL, if name is not found in any name tree
 */
pccd_rpd_lsp *
pccd_rpd_delete_lsp_from_name_tree(const char name[RPD_LSP_NAME_SIZE +1])
{
    uint8_t type = 0;
    uint8_t sub_type = 0;
    pccd_rpd_lsp *rpd_lsp = NULL;
    name_tree_t *tree_name;
    do {
        tree_name = pccd_rpd_get_name_tree(type,sub_type);
        if(NULL == tree_name) {
            return NULL;
        }
        rpd_lsp = name_tree_lookup(tree_name, name);
        if(rpd_lsp) {
            break;
        }
        sub_type++;
        if(sub_type >= pccd_rpd_get_subtype_tree_count(type)){
            type++;
            sub_type = 0;	
        }
    }while( (type < SETUP_TYPE_MAX) && (!rpd_lsp)); 

    if (rpd_lsp) {
        /* NSR Begin */
        if (rpd_lsp->lsp_info.type != LSP_TYPE_CLI_REGULAR_SIGNALLED) {
            pccd_repl_handle_delete_lsp(&rpd_lsp->lsp_info);
        }
        /* NSR End */

        INSIST_ERR(name_tree_delete(tree_name, name) != NULL);
        TRACE_RPD("Deleted lsp %s from tree %p", name, tree_name);
    }
    else {
        TRACE_RPD("Can't find lsp '%s' in local LSP cache", name);
        return NULL;
    }
    return rpd_lsp;
}



static int
pccd_rpd_remove_lsp(const char name[RPD_LSP_NAME_SIZE +1])
{
    pccd_rpd_lsp *rpd_lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    TRACE_RPD("Deleting lsp '%s' from local db", name);

    rpd_lsp = pccd_rpd_delete_lsp_from_name_tree(name);
    if (!rpd_lsp) {
        TRACE_RPD("Can't find lsp '%s' in local LSP cache", name);
        TRACE_FUNCTION_RETURN(0);
    }

    pccd_rpd_sr_color_cpath_delete(rpd_lsp);
    pccd_rpd_lsp_deleted(&rpd_lsp->lsp_info);

    if (BIT_ISSET(rpd_lsp->lsp_info.path_flags, LSP_PATH_TYPE_P2MP)) {
        /**
         * we have to take out p2mp lsp pointer from rpd_lsp before calling
         * pccd_p2mp_remove_branch_lsp, as the reference would be removed
         * inside that function.
         */
        struct pccd_p2mp_lsp_info* p2mp_lsp_tmp = rpd_lsp->lsp_info.p2mp_lsp;

        pccd_p2mp_remove_branch_lsp(&rpd_lsp->lsp_info, true);

        /* If last branch is pending to be deleted then set the flag in p2mp lsp */
        if (p2mp_lsp_tmp && (p2mp_lsp_tmp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
            (p2mp_lsp_tmp->branch_lsp_count == 1)) {
            p2mp_lsp_tmp->last_branch_del_pending = true;
        }

        if (LSP_TYPE_EXTERNALLY_PROVISIONED != rpd_lsp->lsp_info.type) {
	    junos_redblack_delete(lspid_tree, &rpd_lsp->lsp_node);
            pccd_rpd_decrement_lsp_count();
        }
    } else {
	junos_redblack_delete(lspid_tree, &rpd_lsp->lsp_node);
        pccd_rpd_decrement_lsp_count();
    }

    pccd_rpd_free_lsp_buffers(&rpd_lsp->lsp_info);
    pccd_rpd_free_lsp_div_assoc_info(&rpd_lsp->lsp_info);
    pccd_rpd_free_pce_proposed_ero(&rpd_lsp->lsp_info);
    pccd_rpd_free_intended_metric(&rpd_lsp->lsp_info);
    pccd_rpd_free_actual_metric(&rpd_lsp->lsp_info);

    /* Delete all prefix info from lsp */
    pccd_rpd_lsp_delete_all_prefix_info(rpd_lsp->lsp_info.prefix_root);
    rpd_lsp->lsp_info.prefix_root = NULL;

    free(rpd_lsp);

    TRACE_FUNCTION_RETURN(0);
}

static uint8_t
pccd_rpd_get_pccd_metric_type_from_rpd_metric_type(uint8_t rpd_metric_type)
{
    uint8_t pccd_metric_type = PCEP_METRIC_TYPE_MAX;
    switch(rpd_metric_type) {
        case RPD_LSP_METRIC_TYPE_IGP:
            pccd_metric_type = IGP_METRIC;
            break;
        case RPD_LSP_METRIC_TYPE_TE:
            pccd_metric_type = TE_METRIC;
            break;
        case RPD_LSP_METRIC_TYPE_PATH_DELAY_MIN:
            pccd_metric_type = PATH_DELAY_METRIC;
            break;
        case RPD_LSP_METRIC_TYPE_HOP_COUNT:
            pccd_metric_type = HOPCOUNT_METRIC;
            break;
        case RPD_LSP_METRIC_TYPE_SEGMENT_LIST_DEPTH:
            pccd_metric_type = SEGMENT_ID_DEPTH;
            break;
        default:
            TRACE_RPD("Unknown metric type received from RPD. Metric type: %d ", rpd_metric_type);
            LOGGING_ERR("Unknown metric type received from RPD. Metric type: %d ", rpd_metric_type);
    }
    return pccd_metric_type;
}

static bool
pccd_rpd_ignore_rpd_metric(const u_int8_t current_control_status, const u_int8_t new_control_status,
        const u_int16_t type)
{
    if (current_control_status == new_control_status) {
        if (LSP_EXTERNALLY_CONTROLLED == new_control_status) {
            return true;
        }
    }

    if ((LSP_TYPE_EXTERNALLY_PROVISIONED == type) && (LSP_EXTERNALLY_CONTROLLED == new_control_status)) {
        return true;
    }
    return false;
}

static bool
pccd_rpd_ignore_rpd_dag_info (const u_int8_t  current_control_status,
                              const u_int8_t  new_control_status,
                              const u_int16_t type)
{
    if (current_control_status == new_control_status) {
        if (LSP_EXTERNALLY_CONTROLLED == new_control_status) {
            return true;
        }
    }

    if ((LSP_TYPE_EXTERNALLY_PROVISIONED == type) &&
        (LSP_EXTERNALLY_CONTROLLED == new_control_status)) {
        return true;
    }

    return false;
}

static bool
pccd_rpd_ignore_rpd_bound_metric(const uint8_t rpd_bound_metric_type, const u_int8_t new_control_status)
{
    if (((RPD_LSP_METRIC_TYPE_IGP == rpd_bound_metric_type) ||
            (RPD_LSP_METRIC_TYPE_TE == rpd_bound_metric_type) ||
            (RPD_LSP_METRIC_TYPE_PATH_DELAY_MIN == rpd_bound_metric_type)) &&
            (LSP_LOCALLY_CONTROLLED == new_control_status)) {
        TRACE_RPD("Ignoring rpd metric type: %d ", rpd_bound_metric_type);
        return true;
    }
    return false;
}


static void
pccd_rpd_reconfig_lsp(struct pccd_rpd_lsp_info *lsp,
                      const u_int32_t context,
                      const rpd_extctrl_lsp_config_status_info_t *info,
                      bool add_lsp,
                      boolean* is_notify)
{
    bool is_p2mp_lsp = FALSE;
    const lsp_type_info_t *lsp_type_info = NULL;
    bool ignore_rpd_metric = FALSE;
    bool ignore_rpd_dag_info = FALSE;
    int i = 0;

    INSIST_ERR(lsp != NULL);
    INSIST_ERR(info != NULL);
 
    lsp_type_info = &info->lsp_type_info;
    lsp->is_lsp_src_dst_addr_type_ipv6 = info->is_lsp_src_dst_addr_type_ipv6;

    if (!info->is_lsp_src_dst_addr_type_ipv6) {
        lsp->srcaddr.v4 = info->srcaddr_u.v4;
        lsp->dstaddr.v4 = info->dstaddr_u.v4;

        /* It is safe to use the srcaddr to fill in the Extended Tunnel ID
         * on the ingress router for now. This has to be changed when
         * local protection is supported. */

        lsp->extended_tunnel_id.v4 = info->srcaddr_u.v4;
    } else {
        memcpy(lsp->srcaddr.v6, info->srcaddr_u.v6, 16);
        memcpy(lsp->dstaddr.v6, info->dstaddr_u.v6, 16);

        /* It is safe to use the srcaddr to fill in the Extended Tunnel ID
         * on the ingress router for now. This has to be changed when
         * local protection is supported. */

        memcpy(lsp->extended_tunnel_id.v6, info->srcaddr_u.v6, 16);
    }
    lsp->type = info->type;
    lsp->state = info->state;
    /* If Control status is changed, update fields accordingly */
    if (lsp->control_status != info->control_status) {
        if (info->control_status == LSP_LOCALLY_CONTROLLED) {
            /* If Lsp is made local from externally controlled, reset 
             * lsp-intended-attrs as it is used to hold Controller's  
             * informed bandwidth values
             */
            lsp->intended_attrs.bw = 0;
            lsp->intended_attrs.bw_valid = FALSE;

            /* Once Delegation is removed and LSP becomes local
             * Free PCE Proposed ERO if there's any
             */
            pccd_rpd_free_pce_proposed_ero(lsp);
        }
    }

    ignore_rpd_metric = pccd_rpd_ignore_rpd_metric(lsp->control_status, info->control_status, info->type);
    ignore_rpd_dag_info = pccd_rpd_ignore_rpd_dag_info(lsp->control_status, info->control_status, info->type);
    lsp->control_status = info->control_status;
    lsp->lsp_flags = info->lsp_flags;
    lsp->path_flags = info->path_flags;
    lsp->prli_admin_grp_exclude_any = info->relcsi_admin_grp_exclude_any;
    lsp->prli_admin_grp_include_any = info->relcsi_admin_grp_include_any;
    lsp->prli_admin_grp_include_all = info->relcsi_admin_grp_include_all;
    lsp->setup_prio = info->setup_prio;
    lsp->hold_prio = info->hold_prio;
    lsp->msg_trigger_reason = info->msg_trigger_reason;
    lsp->configured_bandwidth = info->configured_bandwidth;
    lsp->bandwidth = info->bandwidth;
    lsp->metric = info->metric;

    pccd_rpd_free_lsp_buffers(lsp);
    lsp->setup_type = lsp_type_info->setup_type;
    lsp->sub_type = lsp_type_info->sub_type;
    is_p2mp_lsp = (info->path_flags & LSP_PATH_TYPE_P2MP);
    lsp->name_tree_key = pccd_rpd_create_name_tree_key(lsp_type_info->setup_type, 
                                              lsp_type_info->sub_type, is_p2mp_lsp);

    lsp->ero_info = info->ero_info;
    lsp->ero_len = info->ero_len;

    lsp->rro_info = info->rro_info;
    lsp->rro_len = info->rro_len;

    lsp->srte_ero_len = info->srte_ero_len;
    lsp->srte_rro_len = info->srte_rro_len;
    lsp->srte_total_ero_count = info->srte_total_ero_count;
    lsp->srte_ero_info = info->srte_ero_info;
    lsp->srte_total_rro_count = info->srte_total_rro_count;
    lsp->srte_rro_info = info->srte_rro_info;
    lsp->max_segment_list = info->max_segment_list;

    lsp->error_spec_obj = info->error_spec_obj;
    lsp->error_spec_obj_len = info->error_spec_obj_len;

    if (pccd_nsr_master()) {
        /* If LSP Id has been changed and in the case of MBB only *
         * Old LSP Id will be updated otherwise update current only */
        if (lsp->lsp_id != info->lsp_id && BIT_ISSET(info->path_flags, LSP_PATH_MBB_IN_PROGRESS)) {
            lsp->old_lsp_id = lsp->lsp_id;
        }
    }

    /* Updating current LSP Id */
    lsp->lsp_id = info->lsp_id;

    lsp->tunnel_id = info->tunnel_id;
    lsp->context = context;
    lsp->num_assoc_info = info->num_assoc_info;
    lsp->num_paths = info->num_paths;
    snprintf(lsp->template_name, sizeof(lsp->template_name), "%s", 
	     info->template_name);
    TRACE_RPD("LSP %p, template name %s",
	      lsp, lsp->template_name);

    if (BIT_ISSET(lsp->path_flags,LSP_PATH_TYPE_P2MP)) {
        /*P2MP LSP*/
        struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_p2mp_add_branch_lsp(info, lsp);
        if (NULL != p2mp_lsp){
            TRACE_RPD("P2MP LSP p2mp_name %s and p2mp_id %u"
                      " lsp_id %d, tunnel_id %d extended_tunnel_id %u",
                      p2mp_lsp->p2mp_name, p2mp_lsp->p2mp_id,
                      lsp->lsp_id, lsp->tunnel_id, lsp->extended_tunnel_id);
        }
    }

    while(i < info->num_assoc_info) {
        lsp->assoc_info[i].assoc_type = info->assoc_info[i].assoc_type;
        lsp->assoc_info[i].assoc_grp_id = info->assoc_info[i].assoc_grp_id;
        lsp->assoc_info[i].assoc_flags = info->assoc_info[i].assoc_flags;
        lsp->assoc_info[i].sr_srpag_t = info->assoc_info[i].sr_srpag_t;
        lsp->assoc_info[i].is_assoc_src_ipv6 = info->assoc_info[i].is_assoc_src_ipv6;
        if (!info->assoc_info[i].is_assoc_src_ipv6) {
            lsp->assoc_info[i].assoc_source_u.v4 = info->assoc_info[i].assoc_source_u.v4;
        } else {
            memcpy(lsp->assoc_info[i].assoc_source_u.v6,
                   info->assoc_info[i].assoc_source_u.v6, 16);
        }

        /** If association source is not present ,set local IP address
          * as association source
          */
        if ((!info->assoc_info[i].is_assoc_src_ipv6) &&
                (0 == lsp->assoc_info[i].assoc_source_u.v4)) {
            struct pce_cfg_core *main_pce = pccd_core_get_main_pce();
            if (main_pce) {
                struct in_addr l_addr = pccd_core_pce_get_local_ip_addr(main_pce);
                memcpy(&lsp->assoc_info[i].assoc_source_u.v4, &l_addr, sizeof(uint32_t));
            }
        }
        i++;
    }

    /*
     * Diversity Association Processing
     */
    if (!ignore_rpd_dag_info) {
        TRACE_RPD("DAG: processing received dag info. type %u control status %u",
                  info->type, info->control_status);
        if (info->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
            if (lsp->div_assoc_info_count == 0) {
                if (info->div_assoc_info_count == 0) {
                    TRACE_RPD("DAG: No diversity assoc info in both pccd and input msg");
                } else {
                    TRACE_RPD("DAG: No exiting diversity assoc info, Updating new info");
                    pccd_rpd_free_lsp_div_assoc_info(lsp);
                    lsp->div_assoc_info_count = info->div_assoc_info_count;
                    lsp->div_assoc_info = info->div_assoc_info;
                }
            } else {
                if (info->div_assoc_info_count == 0) {
                    TRACE_RPD("DAG: Existing diversity association info, new update is empty, doing nothing");
                } else {
                    TRACE_RPD("DAG: Existing diversity association info, overwriting new info. "
                              "Unexpected behaviour for an externally provisioned LSP");
                    pccd_rpd_free_lsp_div_assoc_info(lsp);
                    lsp->div_assoc_info_count = info->div_assoc_info_count;
                    lsp->div_assoc_info = info->div_assoc_info;
                }
            }
        } else if (info->type == LSP_TYPE_EXTERNALLY_CONTROLLED) {
            if (lsp->div_assoc_info_count == 0) {
                if (info->div_assoc_info_count == 0) {
                    TRACE_RPD("DAG: No diversity assoc info in both pccd and input");
                } else {
                    TRACE_RPD("DAG: No exiting diversity assoc info, "
                              "seeing diversity assoc info for first time. Saving values");
                    pccd_rpd_free_lsp_div_assoc_info(lsp);
                    lsp->div_assoc_info_count = info->div_assoc_info_count;
                    lsp->div_assoc_info = info->div_assoc_info;
                }
            } else {
                if (info->div_assoc_info_count == 0) {
                    TRACE_RPD("DAG: Existing diversity association info, "
                              "update is empty. Removing old info");
                    pccd_rpd_free_lsp_div_assoc_info(lsp);
                    lsp->div_assoc_info_count = 0;
                    lsp->div_assoc_info = NULL;
                } else {
                    TRACE_RPD("DAG: Existing diversity association info, seeing changes in current update. "
                              "Ignoring updates as LSP is already delegated. New changes are not accepted");
                }
            }
        } else if (info->type == LSP_TYPE_CLI_REGULAR_SIGNALLED) {
            uint32_t count = 0;
            while (count < lsp->div_assoc_info_count) {
                lsp->div_assoc_info[count].assoc_flags = 1;
                count++;
            }
            TRACE_RPD("DAG: LSP Delegation is removed. cleaning up dag info");
        }
    } else {
        TRACE_RPD("DAG: Ignoring the diversity association in received message");
        if (info->div_assoc_info) {
            rpd_extctrl_lsp_config_status_info_t *info_cpy = (rpd_extctrl_lsp_config_status_info_t *) info;
            free(info_cpy->div_assoc_info);
            info_cpy->div_assoc_info = NULL;
            info_cpy->div_assoc_info_count = 0;
        }
    }
    
    lsp->path_priority = info->path_priority;
    lsp->auto_bandwidth = info->auto_bandwidth;

    /** Store existing binding type and binding value as old as only diff needs to be sent to PCE */
    lsp->old_binding_type = lsp->binding_type;
    lsp->old_binding_value = lsp->binding_value;
    lsp->binding_type = info->lsp_binding_sid.binding_type;
    lsp->binding_value = info->lsp_binding_sid.binding_value;

    if (!ignore_rpd_metric) {
        TRACE_RPD("Update LSP with metrics, configured bandwidth sent by RPD, LSP name '%s', path name '%s'",
                info->name, info->path_name);
        struct lsp_metric_s *metric_new = NULL;
        pccd_rpd_free_intended_metric(lsp);
        pccd_rpd_free_actual_metric(lsp);

        lsp->intended_attrs.bw = info->configured_bandwidth;
        lsp->intended_attrs.bw_valid = TRUE;

        if (info->bound_metric_list && (info->bound_metric_list->list_len > 0)) {
            for (i = (info->bound_metric_list->list_len - 1); i >= 0; i--) {
                if (!pccd_rpd_ignore_rpd_bound_metric(info->bound_metric_list->metric[i].metric_type,
                        info->control_status)) {
                    uint8_t rpd_metric_type = info->bound_metric_list->metric[i].metric_type;
                    metric_new = xcalloc(1, sizeof(*metric_new));
                    metric_new->metric_info.metric_type =
                            pccd_rpd_get_pccd_metric_type_from_rpd_metric_type(rpd_metric_type);
                    metric_new->metric_info.metric = (uint32_t)info->bound_metric_list->metric[i].metric_val;
                    metric_new->metric_info.bound_flag = 1;

                    SLIST_INSERT_HEAD(&lsp->intended_attrs.intended_metric_head, metric_new, metric_next);
                }
            }
        }

        if (info->optimization_metric_list && (info->optimization_metric_list->list_len > 0)) {
            for (i = (info->optimization_metric_list->list_len - 1); i >= 0; i--) {
                uint8_t rpd_metric_type = info->optimization_metric_list->metric_type[i];
                metric_new = xcalloc(1, sizeof(*metric_new));
                metric_new->metric_info.metric_type =
                        pccd_rpd_get_pccd_metric_type_from_rpd_metric_type(rpd_metric_type);
                SLIST_INSERT_HEAD(&lsp->intended_attrs.intended_metric_head, metric_new, metric_next);
            }
        }

        if (info->actual_metric_list && (info->actual_metric_list->list_len > 0)) {
            for (i = (info->actual_metric_list->list_len - 1); i >= 0; i--) {
                uint8_t rpd_metric_type = info->actual_metric_list->metric[i].metric_type;
                metric_new = xcalloc(1, sizeof(*metric_new));
                metric_new->metric_info.metric_type =
                        pccd_rpd_get_pccd_metric_type_from_rpd_metric_type(rpd_metric_type);
                metric_new->metric_info.metric = (uint32_t)info->actual_metric_list->metric[i].metric_val;
                metric_new->metric_info.computed_flag = 1;

                SLIST_INSERT_HEAD(&lsp->actual_metric_head, metric_new, metric_next);
            }
        }
    } else {
        TRACE_RPD("Metrics sent by RPD are not considered, LSP name '%s', path name '%s'",
                info->name, info->path_name);
    }

    /* PCE Initiated Bypass : begin */ 
    if (add_lsp) {
        lsp->bypass_info.bp_nhaddr = info->rbyp_params.rbp_nhaddr.rbn_ipv4_addr;
    }
    lsp->bypass_info.bp_prot_type = info->rbyp_params.rbp_prot_type;
    lsp->bypass_info.bp_subscr = info->rbyp_params.rbp_subscr;
    lsp->bypass_info.bp_prot_in_use = (info->rbyp_state.rbs_in_use 
                                        ? true : false);
	if (lsp->bypass_info.bp_nhaddr != 0) {
		TRACE_RPD("Received bypass params for lsp_name %s, path_name %s :"
				  "nexthop 0x%x, prot_type %u, subsc rate %f,"
				  "prot_in_use: %u from RPD",
				  lsp->lsp_name, lsp->path_name,lsp->bypass_info.bp_nhaddr,
				  lsp->bypass_info.bp_prot_type, lsp->bypass_info.bp_subscr, 
				  lsp->bypass_info.bp_prot_in_use);
	}
    /* PCE Initiated Bypass : end */ 

    /**
     * Reconfiguration of prefix in pccd database
     *
     * In case of OLD_INS_DOWN, no need to do reconfig of prefix in pccd again as
     * prefix processing for this lsp would be done when rpd will send new
     * instance of the lsp with new lsp id and flag MBB_IN_PROGRESS
     */
    if (!(info->msg_trigger_reason & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN)) {
        /**
         * This is only supported over P2P lsps currently.
         *
         * pccd_rpd_reconfig_lsp is also called also from pccd_core_store_lsp
         * for PCE Init LSPs. But prefix population for PCInitiated lsps are
         * done while parsing flowspec objects so no need to do it again.
         *
         * So ignoring these 2 cases.
         */
        if (!(is_p2mp_lsp ||
             ((lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
              (lsp->state == LSP_STATE_CREATION_PENDING)))) {
            pccd_rpd_proc_prefix_in_pcreq_status(lsp, info->install_prefix_info,
                            is_notify);
        }
    }

    /* NSR Begin */
    /* update delegation flags for delegated lsp, if its in standby */
    pccd_core_update_lsp_delegation(lsp);
    /* NSR End */
}

static int
pccd_rpd_store_new_lsp(const rpd_extctrl_lsp_config_status_info_t *info, const u_int32_t context)
{
    boolean is_notify = FALSE;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    pccd_rpd_lsp *rpd_lsp = NULL;
    struct pccd_rpd_lsp_info *lsp = NULL;
    name_tree_t *tree_name = NULL;
    unsigned int tries = 1;

    INSIST_ERR(info != NULL);

    TRACE_FUNCTION_ENTRY();

    rpd_lsp = calloc(1, sizeof(*rpd_lsp));
    lsp = &rpd_lsp->lsp_info;

    bzero(lsp->lsp_name, sizeof(lsp->lsp_name));
    bzero(lsp->path_name, sizeof(lsp->path_name));
    bzero(lsp->template_name ,sizeof(lsp->template_name));
    bzero(&lsp->last_pc_req_rpt ,sizeof(lsp->last_pc_req_rpt));
    bzero(&lsp->last_pcupd_sent ,sizeof(lsp->last_pcupd_sent));
    bzero(&lsp->last_pcerr_sent ,sizeof(lsp->last_pcerr_sent));
    bzero(&lsp->last_pc_upd_crt ,sizeof(lsp->last_pc_upd_crt));

    SLIST_INIT(&lsp->intended_attrs.intended_metric_head);
    SLIST_INIT(&lsp->actual_metric_head);

    snprintf(lsp->lsp_name, sizeof(lsp->lsp_name), "%s", info->name);

    if(strlen(info->path_name)) {
        snprintf(lsp->path_name, sizeof(lsp->path_name), "%s", info->path_name);
    }

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
        lsp->lsp_name, lsp->path_name);

    if(info->path_priority)
        lsp->path_priority = info->path_priority;

    rpd_lsp->lsp_info.assoc_requested = info->assoc_requested;

    lsp->lsp_id = 0;
    lsp->old_lsp_id = 0;

    /**
     * Initialize LSP Prefix tree
     *
     * Install-Prefix is supported only over P2P LSP and for pce initiated
     * lsps prefix tree root will be initialized before parsing pcep objects so
     * no need to initialize it again here
     *
     * So ignoring these 2 cases
     */
    if (!(BIT_ISSET(info->path_flags, LSP_PATH_TYPE_P2MP) ||
         ((info->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
          (info->state == LSP_STATE_CREATION_PENDING)))) {

        /* check if already initialized */
        if (!lsp->prefix_root) {
            lsp->prefix_root = PCCD_RADIX_ROOT_INIT(NULL);
            if (!lsp->prefix_root) {
                LOGGING_ERR("prefix_tree_init failed");
                TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
            }
        }
    }

    pccd_rpd_reconfig_lsp(lsp, context, info, TRUE, &is_notify);

    /*
     * Insert the LSP into name tree, so that we can retrieve LSP by the
     * RPD's LSP name.
     */
    tree_name = pccd_rpd_get_name_tree(lsp->name_tree_key.type,
            lsp->name_tree_key.sub_type);
    if(NULL == tree_name) {
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    if (!name_tree_add(tree_name, lsp_full_name, rpd_lsp)) {
        LOGGING_ERR("name_tree_add failed");
        abort();
    }

    /* Add the LSP also into LSP RB/P2MP RB tree, so that we can search by
     * the LSP id too. */
    if ((BIT_ISSET(info->path_flags, LSP_PATH_TYPE_P2MP)) && 
        (LSP_TYPE_EXTERNALLY_PROVISIONED == rpd_lsp->lsp_info.type)){
        pccd_rpd_p2mp_lsp *p2mp_lsp_node = name_tree_lookup(&pccd_p2mp_lsps, info->p2mp_name);
        if (NULL != p2mp_lsp_node) {
            if (0 != p2mp_lsp_node->info.plsp_id) {
                lsp->id = p2mp_lsp_node->info.plsp_id;
            } else {        
                p2mp_lsp_node->info.plsp_id = pccd_rpd_lsp_id_alloc();
		while (!junos_redblack_add(p2mp_tree, &p2mp_lsp_node->p2mp_node,
		       pccd_rpd_p2mp_id_cmp)) {
                    /* Since there is at least one more LSP ID free for sure,
                     * re-try this loop until found. */
                    p2mp_lsp_node->info.plsp_id = pccd_rpd_lsp_id_alloc();
                    tries++;
                }
                lsp->id = p2mp_lsp_node->info.plsp_id;
                
                pccd_rpd_increment_lsp_count();
            }
        }
    } else {
        rpd_lsp->lsp_info.id = pccd_rpd_lsp_id_alloc();

        while (!junos_redblack_add(lspid_tree, &rpd_lsp->lsp_node,
                pccd_rpd_lsp_id_cmp)) {
            /* Since there is at least one more LSP ID free for sure,
             * re-try this loop until found. */
            lsp->id = pccd_rpd_lsp_id_alloc();
            tries++;
        }

        pccd_rpd_increment_lsp_count();
    }
    
    if (tries > 1) {
        TRACE_RPD("Found free LSP id %d on try number %u",
                  lsp->id, tries);
    }

    TRACE_RPD("Stored new LSP as :%s for LSP %s  with path '%s' id %d",
	      lsp_full_name, lsp->lsp_name, lsp->path_name, lsp->id);

    TRACE_FUNCTION_RETURN(0);
}

static bool
pccd_rpd_compare_sr_ero(rpd_sr_ero_list_t *sr_ero_info_old,
                        rpd_sr_ero_list_t *sr_ero_info_new)
{
    if (sr_ero_info_old->rsel_n_eros !=
            sr_ero_info_new->rsel_n_eros) return true;

    for (unsigned i = 0; i < sr_ero_info_old->rsel_n_eros; i++) {
        rpd_sr_ero_t *sr_ero_old = &sr_ero_info_old->rsel_ero[i];
        rpd_sr_ero_t *sr_ero_new = &sr_ero_info_new->rsel_ero[i];

        if (sr_ero_old->rse_loose != sr_ero_new->rse_loose) return true;
        if (sr_ero_old->rse_sid.rses_type !=
                sr_ero_new->rse_sid.rses_type) return true;
        switch (sr_ero_old->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_20:
                if (sr_ero_old->rse_sid.u.rses_label_20 !=
                        sr_ero_new->rse_sid.u.rses_label_20) return true;
                break;
            case RPD_SR_ERO_SID_TYPE_LABEL_32:
                if (sr_ero_old->rse_sid.u.rses_label_32 !=
                        sr_ero_new->rse_sid.u.rses_label_32) return true;
                break;
            case RPD_SR_ERO_SID_TYPE_INDEX:
                if (sr_ero_old->rse_sid.u.rses_index !=
                        sr_ero_new->rse_sid.u.rses_index) return true;
                break;
        }

        if (sr_ero_old->rse_nai.rsen_type !=
                sr_ero_new->rse_nai.rsen_type) return true;
        switch (sr_ero_old->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                if (sr_ero_old->rse_nai.u.rsen_node_ipv4_addr !=
                        sr_ero_new->rse_nai.u.rsen_node_ipv4_addr) return true;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID:
                if (sr_ero_old->rse_nai.u.rsen_adj_ipv4.rsen_local_addr !=
                    sr_ero_new->rse_nai.u.rsen_adj_ipv4.rsen_local_addr) return true;

                if (sr_ero_old->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr !=
                    sr_ero_new->rse_nai.u.rsen_adj_ipv4.rsen_remote_addr) return true;
                break;
        }
    }
    return false;
}

static bool
pccd_rpd_compare_srv6_ero(rpd_sr_ero_list_t *sr_ero_info_old,
                        rpd_sr_ero_list_t *sr_ero_info_new)
{
    if ((NULL == sr_ero_info_old) || (NULL == sr_ero_info_new))
        return true;

    if (sr_ero_info_old->rsel_n_eros !=
            sr_ero_info_new->rsel_n_eros) return true;

    for (unsigned i = 0; i < sr_ero_info_old->rsel_n_eros; i++) {
        rpd_sr_ero_t *srv6_ero_old = &sr_ero_info_old->rsel_ero[i];
        rpd_sr_ero_t *srv6_ero_new = &sr_ero_info_new->rsel_ero[i];

        if (srv6_ero_old->rse_srv6_loose != srv6_ero_new->rse_srv6_loose) return true;
        if (srv6_ero_old->rse_srv6_sid_verification != srv6_ero_new->rse_srv6_sid_verification) return true;
        if (srv6_ero_old->rse_srv6_sid_structure_valid != srv6_ero_new->rse_srv6_sid_structure_valid) return true;
        if (srv6_ero_old->rse_srv6_endpoint_behavior != srv6_ero_new->rse_srv6_endpoint_behavior) return true;
        if (srv6_ero_old->rse_sid.rses_type !=
                srv6_ero_new->rse_sid.rses_type) return true;
        switch (srv6_ero_old->rse_sid.rses_type) {
            case RPD_SR_ERO_SID_TYPE_NONE:
                break;
            case RPD_SR_ERO_SID_TYPE_SRV6:
                if (memcmp(srv6_ero_old->rse_sid.u.rses_addr,
                        srv6_ero_new->rse_sid.u.rses_addr, 16)) return true;
                break;
            default:
                TRACE_RPD("Unknown SID Type for exisint ERO .Type is %d", srv6_ero_old->rse_sid.rses_type);
                break;
        }

        if (srv6_ero_old->rse_nai.rsen_type !=
                srv6_ero_new->rse_nai.rsen_type) return true;
        switch (srv6_ero_old->rse_nai.rsen_type) {
            case RPD_SR_ERO_NAI_TYPE_ABSENT:
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                if (memcmp(srv6_ero_old->rse_nai.u.rsen_node_ipv6_addr,
                        srv6_ero_new->rse_nai.u.rsen_node_ipv6_addr, 16)) return true;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
                if (memcmp(srv6_ero_old->rse_nai.u.rsen_adj_ipv6.rsen_local_addr,
                    srv6_ero_new->rse_nai.u.rsen_adj_ipv6.rsen_local_addr, 16)) return true;

                if (memcmp(srv6_ero_old->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr,
                    srv6_ero_new->rse_nai.u.rsen_adj_ipv6.rsen_remote_addr, 16)) return true;
                break;
            case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                if (memcmp(srv6_ero_old->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr,
                    srv6_ero_new->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_node_addr, 16)) return true;

                if (memcmp(srv6_ero_old->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr,
                    srv6_ero_new->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_node_addr, 16)) return true;

                if (srv6_ero_old->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id !=
                        srv6_ero_new->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_local_intf_id) return true;

                if (srv6_ero_old->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id !=
                        srv6_ero_new->rse_nai.u.rsen_linklocal_adj_ipv6.rsen_remote_intf_id) return true;
                break;
            default:
                TRACE_RPD("Unknown NAI Type for exisint ERO .Type is %d", srv6_ero_old->rse_nai.rsen_type);
                break;
        }

        if (srv6_ero_old->rse_srv6_sid_structure.lb_length != srv6_ero_new->rse_srv6_sid_structure.lb_length) return true;
        if (srv6_ero_old->rse_srv6_sid_structure.ln_length != srv6_ero_new->rse_srv6_sid_structure.ln_length) return true;
        if (srv6_ero_old->rse_srv6_sid_structure.fun_length != srv6_ero_new->rse_srv6_sid_structure.fun_length) return true;
        if (srv6_ero_old->rse_srv6_sid_structure.arg_length != srv6_ero_new->rse_srv6_sid_structure.arg_length) return true;
    }
    return false;
}

static bool
pccd_rpd_compare_intended_metric(const struct pccd_rpd_lsp_info *lsp,
        const rpd_extctrl_lsp_config_status_info_t *info)
{
    struct lsp_metric_s *intended_metric = NULL, *tmp;
    uint32_t i = 0, rpd_lsp_metric_counter = 0 , info_optimize_metric_counter = 0, info_bound_metric_counter = 0;


    SLIST_FOREACH_SAFE(intended_metric, &lsp->intended_attrs.intended_metric_head, metric_next, tmp) {
        rpd_lsp_metric_counter++;
    }

    if (info->optimization_metric_list) {
        info_optimize_metric_counter += info->optimization_metric_list->list_len;
    }
    if (info->bound_metric_list) {
        uint32_t skip_info_bound_metric_counter = 0;

        for (uint32_t itr = 0; itr < info->bound_metric_list->list_len; itr++) {
            if (pccd_rpd_ignore_rpd_bound_metric(info->bound_metric_list->metric[itr].metric_type,
                    info->control_status)) {
                skip_info_bound_metric_counter++;
            }
        }
        if (skip_info_bound_metric_counter) {
            TRACE_RPD("Skipping %d bound metrics sent by RPD ", skip_info_bound_metric_counter);
        }

        info_bound_metric_counter += (info->bound_metric_list->list_len - skip_info_bound_metric_counter);
    }

    if (rpd_lsp_metric_counter != (info_optimize_metric_counter + info_bound_metric_counter))
        return true;

    SLIST_FOREACH_SAFE(intended_metric, &lsp->intended_attrs.intended_metric_head, metric_next, tmp) {
        if (i < info_optimize_metric_counter) {
            if (intended_metric->metric_info.metric_type != info->optimization_metric_list->metric_type[i])
                return true;
            if (intended_metric->metric_info.bound_flag != 0)
                return true;
        } else {
            uint32_t j = i - info_optimize_metric_counter;

            if (!info->bound_metric_list) {
                return true;
            }
            while (pccd_rpd_ignore_rpd_bound_metric(info->bound_metric_list->metric[j].metric_type,
                    info->control_status)) {
                //Skip current metric and move to next metric
                i++;
                j = i - info_optimize_metric_counter;

                if (j >= info->bound_metric_list->list_len)
                    return true;
            }
            if (intended_metric->metric_info.metric_type != info->bound_metric_list->metric[j].metric_type)
                return true;
            if (intended_metric->metric_info.metric != (u_int32_t)info->bound_metric_list->metric[j].metric_val)
                return true;
            if (intended_metric->metric_info.bound_flag != 1)
                return true;
        }
        i++;
    }
    return false;
}

static bool
pccd_rpd_compare_actual_metric(const struct pccd_rpd_lsp_info *lsp,
        const rpd_extctrl_lsp_config_status_info_t *info)
{
    struct lsp_metric_s *actual_metric = NULL, *tmp;
    uint32_t i = 0, rpd_lsp_metric_counter = 0, info_metric_counter = 0;


    SLIST_FOREACH_SAFE(actual_metric, &lsp->actual_metric_head, metric_next, tmp) {
        rpd_lsp_metric_counter++;
    }

    if (info->actual_metric_list) {
        info_metric_counter = info->actual_metric_list->list_len;
    }
    if (rpd_lsp_metric_counter != info_metric_counter)
        return true;

    SLIST_FOREACH_SAFE(actual_metric, &lsp->actual_metric_head, metric_next, tmp) {
        if (actual_metric->metric_info.metric_type != info->actual_metric_list->metric[i].metric_type)
            return true;
        if (actual_metric->metric_info.metric != (u_int32_t)info->actual_metric_list->metric[i].metric_val)
            return true;
        i++;
    }
    return false;
}

static boolean
pccd_rpd_pcreq_is_notify_controller(struct pccd_rpd_lsp_info *lsp,
                                    const rpd_extctrl_lsp_config_status_info_t *info)
{
    uint32_t i = 0;

    if (lsp == NULL) return true;

    if (lsp->is_lsp_src_dst_addr_type_ipv6 != info->is_lsp_src_dst_addr_type_ipv6) return true;
    if (!info->is_lsp_src_dst_addr_type_ipv6) {
        if (lsp->srcaddr.v4 != info->srcaddr_u.v4) return true;
        if (lsp->dstaddr.v4 != info->dstaddr_u.v4) return true;
    } else {
        if (memcmp(lsp->srcaddr.v6, info->srcaddr_u.v6, 16)) return true;
        if (memcmp(lsp->dstaddr.v6, info->dstaddr_u.v6, 16)) return true;
    }
    if (lsp->type != info->type) return true;
    if (lsp->state != info->state) return true;
    if (lsp->control_status != info->control_status) return true;
    if (lsp->lsp_flags != info->lsp_flags) return true;
    if (lsp->path_flags != info->path_flags) return true;
    if (lsp->prli_admin_grp_exclude_any != info->relcsi_admin_grp_exclude_any) return true;
    if (lsp->prli_admin_grp_include_any != info->relcsi_admin_grp_include_any) return true;
    if (lsp->prli_admin_grp_include_all != info->relcsi_admin_grp_include_all) return true;
    if (lsp->setup_prio != info->setup_prio) return true;
    if (lsp->hold_prio != info->hold_prio) return true;
    if (lsp->bandwidth != info->bandwidth) return true;
    if (lsp->auto_bandwidth != info->auto_bandwidth) return true;
    if (lsp->lsp_id != info->lsp_id) return true;
    if (lsp->tunnel_id != info->tunnel_id) return true;
    if (BIT_ISSET(info->msg_trigger_reason,
                  RPD_MSG_REASON_LSP_PATH_NEW_AUTO_BW)) return true;
    if (lsp->max_segment_list != info->max_segment_list) return true;

    /*ERO*/
    if (lsp->ero_len != info->ero_len) return true;
    if (lsp->ero_len && info->ero_len &&
        bcmp(lsp->ero_info, info->ero_info, lsp->ero_len) != 0) return true;

    /*RRO*/
    if (lsp->rro_len != info->rro_len) return true;
    if (lsp->rro_len && info->rro_len &&
        bcmp(lsp->rro_info, info->rro_info, lsp->rro_len) != 0) return true;

    /* SR-ERO */
    if (lsp->srte_total_ero_count != info->srte_total_ero_count) {
        return true;
    }
    int counter = 0;
    rpd_sr_ero_list_t *rpd_lsp_list = lsp->srte_ero_info;
    rpd_sr_ero_list_t *info_list = info->srte_ero_info;
    if (lsp->srte_ero_info && info->srte_ero_info) {
        for (counter=0; counter<info->srte_total_ero_count; counter++) {
            if (rpd_lsp_list->rsel_type != info_list->rsel_type) {
                return true;
            }
            if (info_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
                if (pccd_rpd_compare_sr_ero(rpd_lsp_list, info_list)) {
                    return true;
                }
            } else {
                if (pccd_rpd_compare_srv6_ero(rpd_lsp_list, info_list)) {
                    return true;
                }
            }
            rpd_lsp_list = (rpd_sr_ero_list_t *)&(rpd_lsp_list->rsel_ero[rpd_lsp_list->rsel_n_eros]);
            info_list = (rpd_sr_ero_list_t *)&(info_list->rsel_ero[info_list->rsel_n_eros]);
        }
    }

    /* SR-RRO */
    if (lsp->srte_total_rro_count != info->srte_total_rro_count) {
        return true;
    }
    rpd_lsp_list = lsp->srte_rro_info;
    info_list = info->srte_rro_info;
    if (lsp->srte_rro_info && info->srte_rro_info) {
        for (counter=0; counter<info->srte_total_rro_count; counter++) {
            if (rpd_lsp_list->rsel_type != info_list->rsel_type) {
                return true;
            }
            if (info_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
                if (pccd_rpd_compare_sr_ero(rpd_lsp_list, info_list)) {
                    return true;
                }
            } else {
                if (pccd_rpd_compare_srv6_ero(rpd_lsp_list, info_list)) {
                    return true;
                }
            }
            rpd_lsp_list = (rpd_sr_ero_list_t *)&(rpd_lsp_list->rsel_ero[rpd_lsp_list->rsel_n_eros]);
            info_list = (rpd_sr_ero_list_t *)&(info_list->rsel_ero[info_list->rsel_n_eros]);
        }
    }

    /*If not sent error previously then notify controller*/
    if (lsp->error_spec_obj_len != info->error_spec_obj_len) return true;
    
    /*If error obj is same then don't notify*/
    if (lsp->error_spec_obj_len && info->error_spec_obj_len &&
        bcmp(lsp->error_spec_obj, info->error_spec_obj, lsp->error_spec_obj_len) != 0) return true;

    if (lsp->num_assoc_info != info->num_assoc_info) return true;

    while(i < info->num_assoc_info) {
        if (lsp->assoc_info[i].assoc_type != info->assoc_info[i].assoc_type)
            return true;
        if (lsp->assoc_info[i].assoc_grp_id != info->assoc_info[i].assoc_grp_id)
            return true;
        if (lsp->assoc_info[i].assoc_flags != info->assoc_info[i].assoc_flags)
            return true;
        if (lsp->assoc_info[i].is_assoc_src_ipv6 != info->assoc_info[i].is_assoc_src_ipv6)
            return true;
        if ((lsp->assoc_info[i].sr_srpag_t.color != info->assoc_info[i].sr_srpag_t.color) ||
            ((lsp->assoc_info[i].sr_srpag_t.is_srpag_endpoint_ipv6 != info->assoc_info[i].sr_srpag_t.is_srpag_endpoint_ipv6)) ||
            ((!info->assoc_info[i].sr_srpag_t.is_srpag_endpoint_ipv6) &&
             (lsp->assoc_info[i].sr_srpag_t.srpag_endpoint_addr_u.v4 != info->assoc_info[i].sr_srpag_t.srpag_endpoint_addr_u.v4)) ||
            ((info->assoc_info[i].sr_srpag_t.is_srpag_endpoint_ipv6) &&
             (lsp->assoc_info[i].sr_srpag_t.srpag_endpoint_addr_u.v6 != info->assoc_info[i].sr_srpag_t.srpag_endpoint_addr_u.v6)) ||
            (lsp->assoc_info[i].sr_srpag_t.sr_proto_origin != info->assoc_info[i].sr_srpag_t.sr_proto_origin) ||
            (lsp->assoc_info[i].sr_srpag_t.originator_asn != info->assoc_info[i].sr_srpag_t.originator_asn) ||
            ((lsp->assoc_info[i].sr_srpag_t.is_srpag_originator_ipv6 != info->assoc_info[i].sr_srpag_t.is_srpag_originator_ipv6)) ||
            ((!info->assoc_info[i].sr_srpag_t.is_srpag_originator_ipv6) &&
             (lsp->assoc_info[i].sr_srpag_t.originator_addr_u.v4 != info->assoc_info[i].sr_srpag_t.originator_addr_u.v4)) ||
            ((info->assoc_info[i].sr_srpag_t.is_srpag_originator_ipv6) &&
             (lsp->assoc_info[i].sr_srpag_t.originator_addr_u.v6 != info->assoc_info[i].sr_srpag_t.originator_addr_u.v6)) ||
            (lsp->assoc_info[i].sr_srpag_t.discriminator != info->assoc_info[i].sr_srpag_t.discriminator) ||
            (lsp->assoc_info[i].sr_srpag_t.preference_valid != info->assoc_info[i].sr_srpag_t.preference_valid) ||
            ((lsp->assoc_info[i].sr_srpag_t.preference_valid == true) && 
            (lsp->assoc_info[i].sr_srpag_t.preference != info->assoc_info[i].sr_srpag_t.preference)))
            return true;
        i++;
    }
    i = 0;
    if (!pccd_rpd_ignore_rpd_dag_info(lsp->control_status, info->control_status, info->type)) {
        if (info->div_assoc_info_count != lsp->div_assoc_info_count) {
            return true;
        }
        while (i < info->div_assoc_info_count) {
            if (info->div_assoc_info[i].assoc_grp_id != lsp->div_assoc_info[i].assoc_grp_id) {
                return true;
            }
            if (info->div_assoc_info[i].is_assoc_src_ipv6 != lsp->div_assoc_info[i].is_assoc_src_ipv6) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info_valid !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info_valid) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info_valid !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info_valid) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.link_diverse !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.link_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.node_diverse!=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.node_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.srlg_diverse!=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.srlg_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.strictness !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.strictness) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.shortest_first !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_status_info.shortest_first) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.link_diverse !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.link_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.node_diverse!=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.node_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.srlg_diverse!=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.srlg_diverse) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.strictness !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.strictness) {
                return true;
            }
            if (info->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.shortest_first !=
                    lsp->div_assoc_info[i].disjoint_assoc_list.assoc_conf_info.shortest_first) {
                return true;
            }
            i++;
        }
    }

    if (lsp->metric != info->metric) return true;
    if (lsp->num_paths != info->num_paths) return true;

    if (info->assoc_requested) return true;
    
    if ((lsp->path_flags & LSP_PATH_TYPE_P2MP) && (NULL != lsp->p2mp_lsp)) {
        if (lsp->p2mp_lsp->p2mp_id != info->p2mp_id) return true;
        if (strcmp(lsp->p2mp_lsp->p2mp_name, info->p2mp_name) !=0) return true;
    }
    if (lsp->binding_type != info->lsp_binding_sid.binding_type) return true;
    if (lsp->binding_value != info->lsp_binding_sid.binding_value) return true; 

    if (!pccd_rpd_ignore_rpd_metric(lsp->control_status, info->control_status, info->type)) {
        if (pccd_rpd_compare_intended_metric(lsp,info)) {
            return true;
        }
        if (pccd_rpd_compare_actual_metric(lsp,info)) {
            return true;
        }
    }

    return false;
}

static void
pccd_rpd_handle_name_conflict(rpd_session_handle handle, 
                const u_int32_t context, 
                pccd_rpd_name_tree_key *name_tree_key,
                boolean *is_reconfig_done, 
                const rpd_extctrl_lsp_config_status_info_t *info,
                char *name)
{
    struct pccd_rpd_lsp_info *rpd_lsp = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    if (LSP_TYPE_EXTERNALLY_PROVISIONED != info->type) {
        if (BIT_ISSET(info->path_flags, LSP_PATH_TYPE_P2MP)) {        
            p2mp_lsp = pccd_get_p2mp_lsp_by_name(info->p2mp_name);
            if (p2mp_lsp) {
                if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                    TRACE_RPD("LSP %s was externally provisioned p2mp lsp, but now is "
                              "locally configured.", p2mp_lsp->p2mp_name);
                    /* 
                        Delete all the branches of externally-provisioned p2mp LSP
                        Send delete to rpd also.
                        Send delete to PCE server.
                        Send error to PCE server telling name conflict.
                    */
                    pccd_core_handle_name_conflict(p2mp_lsp, NULL, TRUE, TRUE);

                    pccd_rpd_lsp_err(handle, NULL, p2mp_lsp,
                        TAG_EXTCTRL_ERROR_P2MP_LSP_NAME_CONFLICT);
                }
            } else {
                rpd_lsp = pccd_rpd_get_lsp_by_name_and_preference(info->p2mp_name,
                name_tree_key->type, name_tree_key->sub_type);
                if (rpd_lsp) {
                    if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {                        
                        TRACE_RPD("LSP with lsp_name %s,path_name %s was externally provisioned "
                            "p2p or p2mp branch lsp, but now is locally configured p2mp lsp.", 
                            rpd_lsp->lsp_name, rpd_lsp->path_name);
                        /* delete p2p lsp and send delete to pce server and send error to pce */
                        pccd_core_handle_name_conflict(NULL, rpd_lsp, FALSE, TRUE);
                        
                        pccd_rpd_lsp_err(handle, rpd_lsp, NULL,
                            TAG_EXTCTRL_ERROR_LSP_NAME_CONFLICT);
                    }
                }
            }
        }  

        p2mp_lsp = pccd_get_p2mp_lsp_by_name(name);
        if (p2mp_lsp) {
            if (p2mp_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                TRACE_RPD("LSP %s was externally provisioned p2mp lsp, but now is "
                          "locally configured p2p or p2mp branch lsp.", p2mp_lsp->p2mp_name);
                /* 
                    Delete all the branches of externally-provisioned p2mp LSP
                    Send delete to rpd also.
                    Send delete to PCE server.
                    Send error to PCE server telling name conflict.
                */
                pccd_core_handle_name_conflict(p2mp_lsp, NULL, TRUE, TRUE);
                
                pccd_rpd_lsp_err(handle, NULL, p2mp_lsp, 
                    TAG_EXTCTRL_ERROR_P2MP_LSP_NAME_CONFLICT);
            }
        } else {
            boolean is_notify = FALSE;
            rpd_lsp = pccd_rpd_get_lsp_by_name_and_preference(name,
                name_tree_key->type, name_tree_key->sub_type);
            if (rpd_lsp) {
                if (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                        TRACE_RPD("LSP %s was externally provisioned p2p or p2mp branch lsp, but now is "
                                  "locally configured p2p or p2mp branch lsp.", info->name);
                        /** 
                         *  Send delete to rpd for SR LSP.
                         *  Send delete to PCE server.
                         *  Delete LSP from db
                         */
                        pccd_core_handle_name_conflict(NULL, rpd_lsp, FALSE, FALSE);

                        /* Send delete message to controller and delete LSP from db */
                        pccd_rpd_lsp_del(handle, rpd_lsp->lsp_name, rpd_lsp->path_name);

                } else if (BIT_ISSET(info->path_flags, LSP_PATH_TYPE_P2MP))  {
                    if ((rpd_lsp->p2mp_lsp) 
                        && (strcmp(rpd_lsp->p2mp_lsp->p2mp_name, info->p2mp_name))) {
                        /* info is for p2mp lsp and p2mp name in rpd lsp and info is not same
                             then it is case of pattern replace. */
                        
                        /*we should remove this branch from existing p2mp tree */
                        pccd_p2mp_remove_branch_lsp(rpd_lsp, false);
                        /*make p2mp lsp pointer to NULL*/
                        rpd_lsp->p2mp_lsp = NULL;
                        /* call pccd_rpd_reconfig_lsp to handle rest of things
                             like add new p2mp node or find existing if any and add branch to that p2mp node.*/
                        pccd_rpd_reconfig_lsp(rpd_lsp, context, info, FALSE, &is_notify);
                        /*make notify to true */
                        *is_reconfig_done = true;
                    }
                }
            }
        }
    }

    return;
}

/*
 * Copy lsp key info from src to dest
 * This functions is for filling up temporary lsp info ds
 */
static void
pccd_rpd_copy_lsp_key_info (struct pccd_rpd_lsp_info *dest, struct pccd_rpd_lsp_info * src)
{
    memset(dest, 0, sizeof(struct pccd_rpd_lsp_info));
    /* copy key attributes */
    snprintf(dest->lsp_name,
             sizeof(dest->lsp_name), "%s",
             src->lsp_name);
    if (strnlen(src->path_name, RPD_LSP_NAME_SIZE)) {
        snprintf(dest->path_name,
                 sizeof(dest->path_name), "%s",
                 src->path_name);
    }
    dest->id = src->id;
    dest->p2mp_lsp = src->p2mp_lsp;
    dest->prefix_root = src->prefix_root;
}

void
pccd_rpd_pcreq_status(struct pccd_rpd_lsp_info *rpd_lsp, rpd_session_handle handle, u_int32_t ctx,
                      u_int16_t return_code,
                      const rpd_extctrl_lsp_config_status_info_t *info)
{
    boolean is_notify = TRUE;
    boolean is_reconfig_done = FALSE;
    boolean is_p2mp_lsp;
    pccd_rpd_name_tree_key name_tree_key;
    const lsp_type_info_t *lsp_type_info;

    TRACE_RPD("PCREQ/STATUS hndl %p ctx %"PRIu32" ret %"PRIu16, handle, ctx,
              return_code);
    if (!info) {
        TRACE_RPD("pointer to lsp config status info is NULL");
        return;
    }

    lsp_type_info = &info->lsp_type_info;
    pccd_rpd_debug_lsp_info("rx pcreq", info);

    switch(pccd_rpd_state) {
    case PCCD_RPD_STATE_CLOSED:
    case PCCD_RPD_STATE_CONNECTING:
    case PCCD_RPD_STATE_CONNECTED:
    case PCCD_RPD_STATE_ACC:
        LOGGING_ERR("Received pcreq/info status message in bad state: %d",
                    pccd_rpd_state);
        return;
    case PCCD_RPD_STATE_UP: {
        int created = false;

    char name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE+1)];
    bzero(name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));

    if(strlen(info->path_name)) {
        snprintf(name, sizeof(name), "%s/%s", info->name, info->path_name);

    } else {
        snprintf(name, sizeof(name), "%s", info->name);

    }

        is_p2mp_lsp = (info->path_flags & LSP_PATH_TYPE_P2MP);
        name_tree_key = pccd_rpd_create_name_tree_key(lsp_type_info->setup_type, 
                                            lsp_type_info->sub_type, is_p2mp_lsp);
        if (LSP_TYPE_EXTERNALLY_PROVISIONED != info->type) {
            if(!rpd_lsp) {
                pccd_rpd_handle_name_conflict(handle, ctx, &name_tree_key,
                    &is_reconfig_done, info, (char *)name);
            }
            // storing and reporting not allowed unless any pce is spring capable
            if (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {

                struct lsp_vector *lsp_vec = NULL;
                const struct pccd_rpd_lsp_info *rpd_lsp_info =
                                                pccd_rpd_get_lsp_by_name(name);
                bool is_return = false;

                if (NULL != rpd_lsp_info) {
                    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp_info->id);
                }

                /**
                    When SRTE delegated LSP is present, return control message should be sent
                    to RPD when main PCE is neither spring capable not SPRING capable
                    Usecase:
                    Pre-requisite:
                    1. SRTE delegated LSP is present
                    2. SPRING capability is deleted for main PCE(using PCCD CLI)
                    
                    Flow:
                    3. Session is re-established with PCE
                    4. LSP reports are received from RPD. For SRTE LSPs, if LSP is externally
                       controlled, return control message will be sent to RPD
                */
                if (LSP_EXTERNALLY_CONTROLLED == info->control_status) {
                    struct pce_cfg_core *main_pce = pccd_core_get_main_pce();
                    bool main_pce_spring_capable = false;

                    if (NULL != main_pce) {
                        main_pce_spring_capable = ((main_pce->pc_state > PCE_STATE_CONNECTED) &&
                                                pccd_core_pce_spring_capability(main_pce));
                    }

                    if (!main_pce_spring_capable) {
                        is_return = true;
                        TRACE_RPD("Sending return control message for lsp_name %s and "
                                    "path_name %s as main pce is neither spring capable nor UP",
                                    info->name, info->path_name);

                        if (lsp_vec) {
                            lsp_vec->lv_ack_delegated = false;
                        }

                        if (pccd_rpd_lsp_return_control_send(pccd_rpd_ses_hndl, info->name,
                                            info->path_name, lsp_type_info->setup_type,
                                            lsp_type_info->sub_type, ctx)) {
                            LOGGING_ERR("Failed to send return control message to RPD for"
                                            "lsp_name '%s' and path_name '%s' with error: %d '%s'",
                                            info->name, info->path_name, errno, strerror(errno));
                        }
                    }
                }

                if (!pccd_core_has_any_spring_pce()) {
                    is_return = true;

                    if (rpd_lsp_info) {
                        if (lsp_vec) {
                            pccd_core_delete_lsp(lsp_vec);
                        }
                    }
                    pccd_rpd_remove_lsp(name);
                }

                if (is_return) {
                    TRACE_RPD("Returning as main pce/no pce is not spring capable and UP");
                    return;
                }
            } else if (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
                struct lsp_vector *lsp_vec = NULL;
                const struct pccd_rpd_lsp_info *rpd_lsp_info =
                                                pccd_rpd_get_lsp_by_name(name);
                bool is_return = false;

                if (NULL != rpd_lsp_info) {
                    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp_info->id);
                }

                /**
                    When SRv6 delegated LSP is present, return control message should be sent
                    to RPD when main PCE is not SRv6 capable
                    Usecase:
                    Pre-requisite:
                    1. SRv6 delegated LSP is present
                    2. SRv6 capability is deleted for main PCE(using PCCD CLI)

                    Flow:
                    3. Session is re-established with PCE
                    4. LSP reports are received from RPD. For SRv6 LSPs, if LSP is externally
                       controlled, return control message will be sent to RPD
                */
                if (LSP_EXTERNALLY_CONTROLLED == info->control_status) {
                    struct pce_cfg_core *main_pce = pccd_core_get_main_pce();
                    bool main_pce_srv6_capable = false;

                    if (NULL != main_pce) {
                        main_pce_srv6_capable = ((main_pce->pc_state > PCE_STATE_CONNECTED) &&
                                                        pccd_core_pce_srv6_capability(main_pce));
                    }

                    if (!main_pce_srv6_capable) {
                        is_return = true;
                        TRACE_RPD("Sending return control message for lsp_name %s and "
                                "path_name %s as main pce is neither SRv6 capable nor UP",
                                info->name, info->path_name);

                        if (lsp_vec) {
                            lsp_vec->lv_ack_delegated = false;
                        }

                        if (pccd_rpd_lsp_return_control_send(pccd_rpd_ses_hndl, info->name,
                                info->path_name, lsp_type_info->setup_type,
                                lsp_type_info->sub_type, ctx)) {
                            LOGGING_ERR("Failed to send return control message to RPD for"
                                    "lsp_name '%s' and path_name '%s' with error: %d '%s'",
                                    info->name, info->path_name, errno, strerror(errno));
                        }
                    }
                }

                if (!pccd_core_has_any_srv6_pce()) {
                    is_return = true;

                    if (rpd_lsp_info) {
                        if (lsp_vec) {
                            pccd_core_delete_lsp(lsp_vec);
                        }
                    }
                    pccd_rpd_remove_lsp(name);
                }

                if (is_return) {
                    TRACE_RPD("Returning as main pce/no pce is not srv6 capable and UP");
                    return;
                }

            }
        }

        if (!rpd_lsp) {
            struct pccd_rpd_lsp_info *rpd_lsp_pcinit = NULL;

            if (info->msg_trigger_reason 
                & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN) {
                TRACE_RPD("RPD sent RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN " 
                          "for unknown lsp %s", info->name);
                return;
            }
            
            TRACE_RPD("New LSP '%s' with path %s info came in",
                                      info->name, info->path_name);

            /**
             * Adding to color tree here to prevent below scenario
             *  1. PCE-Init LSP is created with a set of SRPAG identifiers
             *  2. PCCD is restarted
             *  3. New LSP is created with same SRPAG identifiers
             *  4. PCInit is sent to claim the LSP added in (1)
             *  5. Now, both the LSPs , which are having the same SRPAG identifiers will exist
             */
            pccd_rpd_handle_pce_init_sr_cpath (info);

            if (pccd_rpd_store_new_lsp(info, ctx)) {
                TRACE_RPD("Storing of lsp '%s' path_name failed",
                                     info->name, info->path_name);
                return;
            }

            rpd_lsp_pcinit = pccd_rpd_get_specific_lsp(name,
                            name_tree_key.type, name_tree_key.sub_type);

            /* If PCE-Initiated LSP is not present in PCCD DB and RPD sends the PCE-Initiated LSP,
             * Intended BW of PCE-Initiated LSP must be the one sent by RPD
             */
            if (rpd_lsp_pcinit) {
                if(rpd_lsp_pcinit->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                    rpd_lsp_pcinit->intended_attrs.bw = info->configured_bandwidth;
                    if (rpd_lsp_pcinit->intended_attrs.bw) {
                        rpd_lsp_pcinit->intended_attrs.bw_valid = TRUE;
                    }
                }
            }
        } else {
            /* Check if this pc_req_status msg is a duplicate or not and *
             * based on that only we need to inform controller about it */
            is_notify = pccd_rpd_pcreq_is_notify_controller(rpd_lsp, info);
        
            if (info->msg_trigger_reason 
                & RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN) {
                struct pccd_rpd_lsp_info old_lsp_info;

                TRACE_RPD("RPD sent RPD_MSG_REASON_LSP_PATH_OLD_INS_DOWN " 
                          "for lsp %s, lsp-id %d", info->name, info->lsp_id);                
                pccd_rpd_copy_lsp_key_info(&old_lsp_info, rpd_lsp);
                pccd_rpd_reconfig_lsp(&old_lsp_info, ctx, info, FALSE, &is_notify);
                pccd_rpd_lsp_report(&old_lsp_info, true, false, is_notify);
                /* As old instance is deleted, clear the old lsp id */
                rpd_lsp->old_lsp_id = 0;
                pccd_rpd_free_lsp_buffers(&old_lsp_info);
                
                return;
            }

            /*
             * Check if the report is for failed MBB case i.e.
             * LSP id would be different, MBB-in-progress would be marked and
             * the report will contain RSVP Errorspec
             */
            if (rpd_lsp->lsp_id != info->lsp_id && info->error_spec_obj &&
                        BIT_ISSET(info->path_flags, LSP_PATH_MBB_IN_PROGRESS)) {
                /*
                 * Don't reconfig this LSP, just send the report as it is to PCE
                 * We will be creating a temporary rpd_lsp_info struct for this report
                 */
                struct pccd_rpd_lsp_info rpd_lsp_info_tmp;

                TRACE_RPD("Report came from RPD with RSVP Errorspec for LSP: name %s"
                          " Received LSP ID from RPD %d and PCCD Active LSP ID %d &"
                          " PCCD old LSP ID %d", name, info->lsp_id, rpd_lsp->lsp_id,
                          rpd_lsp->old_lsp_id);
                pccd_rpd_copy_lsp_key_info(&rpd_lsp_info_tmp, rpd_lsp);
                pccd_rpd_reconfig_lsp(&rpd_lsp_info_tmp, ctx, info, FALSE, &is_notify);
                pccd_rpd_lsp_report(&rpd_lsp_info_tmp, true, created, is_notify);
                pccd_rpd_free_lsp_buffers(&rpd_lsp_info_tmp);
                return;
            }

            /* After receiving LSP Id 0, PCCD will clean all instances of this LSP by sending *
             * report with all parameters zero to controller to delete those instances */
            if ((0 != rpd_lsp->lsp_id) && (rpd_lsp->lsp_id != info->lsp_id) &&
                 (!BIT_ISSET(info->path_flags, LSP_PATH_MBB_IN_PROGRESS))) {
		struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
		if (lsp_vec == NULL) {
		    LOGGING_ERR("Could not retrieve LSP in internal list");
		    return;
		}

                /* Check is to avoid duplicate reports going to controller */
                if (is_notify) {
                    TRACE_RPD("Received LSP %s with type %u for notifying the controller",
                              name, rpd_lsp->type);
                    if (rpd_lsp->type == LSP_TYPE_CLI_REGULAR_SIGNALLED) {
                        TRACE_RPD("Sending Delete lsp to controller for old lsp "
                                  "ids for LSP Name %s,"
                                  " Received LSP ID from RPD %d and PCCD Active LSP ID %d &"
                                  " PCCD old LSP ID %d", name, info->lsp_id, rpd_lsp->lsp_id,
                                  rpd_lsp->old_lsp_id);
                        pccd_core_report_deleted_lsp(lsp_vec->lv_pce,
                                                     rpd_lsp, SRP_ID_RESV1);
                   }
                }
            }

            if ((0 != rpd_lsp->old_lsp_id) && (rpd_lsp->old_lsp_id == info->lsp_id)) {
                TRACE_RPD("LSP status update for old LSP dropped,"
                          " LSP Name %s, Active LSP ID %d, old LSP ID %d",
                          name, rpd_lsp->lsp_id, rpd_lsp->old_lsp_id);
                return;
            }
            
            if ((rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) &&
                (rpd_lsp->state == LSP_STATE_CREATION_PENDING)) {
                created = true;
            }

            TRACE_RPD("Status info about already known LSP: '%s' as %s",
                                    info->name, name);
            if (!is_reconfig_done) {
                pccd_rpd_reconfig_lsp(rpd_lsp, ctx, info, FALSE, &is_notify);
            }
        }
        
        if (pccd_rpd_in_get_all_lsps_info) {
            /* Only updating information about LSPs, no actual reports are
             * sent until the NO_MORE_LSPS msg from RPD. */
            TRACE_RPD("pccd_rpd_in_get_all_lsps_info is set, returning from here");
            return;
        }

        if (!rpd_lsp) {
            /* New LSP added, call lsp_added callback from the pccd_rpd client */
            rpd_lsp = pccd_rpd_get_specific_lsp(name, 
                name_tree_key.type, name_tree_key.sub_type);
            TRACE_RPD("seaching lsp %s and got rpd_lsp %p ",
                                    name, rpd_lsp);

            INSIST_ERR(rpd_lsp);

            pccd_rpd_lsp_added(rpd_lsp, true);
        } else {
            pccd_rpd_lsp_report(rpd_lsp, true, created, is_notify);
        }
        return; /* STATE_UP */
    }
    }
    LOGGING_ERR("Unexpected PCCD<->RPD state: %d", pccd_rpd_state);
    abort();
}


/**
 * pccd_rpd_compare_priority_of_lsps_with_same_name
 *
 * Called when an new LSP is created with the same name as LSP present in name tree
 *
 * @param[in] curr_rpd_lsp        : lsp present in name_tree
 *            recv_setup_type     : setup_type of new lsp received from rpd
 *            recv_sub_type       : sub_type of new lsp received from rpd
 *
 * @return  Returns true, if received lsp has more priority over lsp in name_tree.
 *          Returns false, if received lsp has less priority over lsp in name tree
 */
bool
pccd_rpd_compare_priority_of_lsps_with_same_name(struct pccd_rpd_lsp_info *curr_rpd_lsp,
            uint8_t recv_setup_type, uint8_t recv_sub_type)
{
/**
 *
 * When two locally controlled lsps are having same name, only 1 lsp is stored as symbolic path 
 * name is unique in PCEP.
 * priority of LSPs for retaining is as follows:
 * 1. RSVP P2P/ RSVP P2MP
 * 2. RSVP BYPASS
 * 3. SR STATIC 
 * 4. SR DTM
 * 5. SR DEFAULT
 *
 */

    if(curr_rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
        if(recv_setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
            TRACE_FUNCTION_RETURN(false);
        } else {  
            /* Curr is RSVP_P2P/P2MP , Recv is RSVP_P2P/P2MP. 
            P2P LSP is converted to P2MP LSP or P2MP LSP is converted to P2P LSP
            Return True as received update needs to be processed */
            TRACE_FUNCTION_RETURN(true);
        }
    } else if(curr_rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        if(recv_setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
            TRACE_FUNCTION_RETURN(false);   //Curr is RSVP_BYPASS, Recv is SR(STATIC/DTM/DEFAULT)
        } else {
            TRACE_FUNCTION_RETURN(true);    //Curr is RSVP_BYPASS, Recv is RSVP(P2P/P2MP)
        }
    } else if((curr_rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
              (curr_rpd_lsp->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        if((recv_setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) || 
            (recv_setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
            TRACE_FUNCTION_RETURN(true);    //Curr is SR(STATIC/DTM/DEFAULT), Recv is RSVP(P2P/P2MP)/RSVP_BYPASS
        } else {    //Recv is SR(STATIC/DTM/DEFAULT)
            if(curr_rpd_lsp->sub_type == RPD_EXTCTRL_SPRING_TE_LSP_SUB_TYPE_STATIC) {
                TRACE_FUNCTION_RETURN(false); //Curr is SR STATIC, Recv is  SR DTM/SR DEFAULT
            } else if(curr_rpd_lsp->sub_type == RPD_EXTCTRL_SPRING_TE_LSP_SUB_TYPE_DTM) {
                if(recv_sub_type == RPD_EXTCTRL_SPRING_TE_LSP_SUB_TYPE_STATIC) {
                    TRACE_FUNCTION_RETURN(true); //Curr is SR DTM, Recv is  SR STATIC
                } else {
                    TRACE_FUNCTION_RETURN(false); //Curr is SR DTM, Recv is  SR DEFAULT
                }
            } else {    //Curr is SR DEFAULT
                TRACE_FUNCTION_RETURN(true);    //Curr is SR DEFAULT, Recv is  SR STATIC/SR DTM
            }
        }
    }
	TRACE_FUNCTION_RETURN(false);
}

void
pccd_rpd_lsp_del(rpd_session_handle handle,
                 const char name[RPD_LSP_NAME_SIZE +1],
                 const char path_name[RPD_LSP_NAME_SIZE +1])
{
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    pccd_rpd_get_lsp_name(lsp_full_name, RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1), 
        name, path_name);

    TRACE_RPD("RPD's delete request received for lsp '%s'", name);
    pccd_rpd_remove_lsp(lsp_full_name);
}

void
pccd_rpd_lsp_err_rmv_lsp(struct pccd_rpd_lsp_info *rpd_lsp)
{
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    pccd_rpd_lsp *lsp = NULL;

    INSIST_ERR(rpd_lsp != NULL);

    /*PCCD debugging utility*/
    pccd_rpd_update_instance(rpd_lsp, LAST_PCERR_SENT);

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
        rpd_lsp->lsp_name, rpd_lsp->path_name);

    /* Delete the LSP from the rpd info */
    lsp = pccd_rpd_delete_lsp_from_name_tree(lsp_full_name);
    pccd_rpd_sr_color_cpath_delete(lsp);

    if (BIT_ISSET(rpd_lsp->path_flags, LSP_PATH_TYPE_P2MP)) {

        pccd_p2mp_remove_branch_lsp(rpd_lsp, true);

        if (LSP_TYPE_EXTERNALLY_PROVISIONED != rpd_lsp->type) {

            junos_redblack_delete(lspid_tree, &lsp->lsp_node);
            pccd_rpd_decrement_lsp_count();
        }
    } else {
        junos_redblack_delete(lspid_tree, &lsp->lsp_node);
        pccd_rpd_decrement_lsp_count();
    }
    pccd_rpd_free_lsp_buffers(rpd_lsp);
    pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
    pccd_rpd_free_pce_proposed_ero(rpd_lsp);
    pccd_rpd_free_intended_metric(rpd_lsp);
    pccd_rpd_free_actual_metric(rpd_lsp);

    /* Delete all prefix info from lsp */
    pccd_rpd_lsp_delete_all_prefix_info(rpd_lsp->prefix_root);
    rpd_lsp->prefix_root = NULL;

    free(lsp);
}

void
pccd_rpd_lsp_err(rpd_session_handle handle,
                struct pccd_rpd_lsp_info *rpd_lsp, struct pccd_p2mp_lsp_info *p2mp_lsp,
                uint16_t rpd_lsp_error)
{
    pccd_pce_err_type_val_t pce_err;

    TRACE_FUNCTION_ENTRY();

    TRACE_RPD("RPD LSP Error: %s (errno:%d), lsp_name: '%s', path_name: %s",
	    tag_extctrl_error_get_string(rpd_lsp_error),
            rpd_lsp_error, rpd_lsp->lsp_name, rpd_lsp->path_name);

    pccd_repl_handle_lsp_error(rpd_lsp);
    
    /*
     * Process the errors sent by RPD.
     */
     switch(rpd_lsp_error){

	 case TAG_EXTCTRL_ERROR_BAD_SRCADDR:
	 case TAG_EXTCTRL_ERROR_LSP_NOT_FOUND:
	 case TAG_EXTCTRL_ERROR_LSP_NAME_CONFLICT:
	 case TAG_EXTCTRL_ERROR_NO_MEMORY:
         case TAG_EXTCTRL_ERROR_INVALID_SR_ERO:
	    TRACE_RPD("Deleting lsp with lsp_name: '%s', path_name '%s' from local db", 
			rpd_lsp->lsp_name, rpd_lsp->path_name);
	    pce_err.pce_err_type = PCEP_ERR_TYPE_INTERNAL_ERROR;
	    pce_err.pce_err_val = PCEP_ERR_VALUE_INTERNAL_ERROR;
		
	    if (!rpd_lsp) {
		TRACE_RPD("Can't find lsp with lsp_name: '%s', path_name '%s' in local LSP cache", 
			rpd_lsp->lsp_name, rpd_lsp->path_name);
		break;
	    }

	    /* Delete the lsp fom local db */
	    if(!(pccd_core_del_lspvec_senderr (rpd_lsp->id, true, true, pce_err))){
		TRACE_RPD("Failed to cleanup the LSP from local db and send msg");
	    }

            pccd_rpd_lsp_err_rmv_lsp(rpd_lsp);
	    break;

         case TAG_EXTCTRL_ERROR_CREATE_LOCAL_LSP:
	    TRACE_RPD("Unable to create LSP hence "
		      "Deleting lsp with lsp_name: '%s', path_name '%s' from local db", 
		      rpd_lsp->lsp_name, rpd_lsp->path_name);
	    pce_err.pce_err_type = PCEP_ERR_TYPE_PCCREATE;
	    pce_err.pce_err_val = PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM;
		
	    if (!rpd_lsp) {
		TRACE_RPD("Can't find lsp with lsp_name: '%s', path_name '%s' in local LSP cache", 
			rpd_lsp->lsp_name, rpd_lsp->path_name);
		break;
	    }

	    /* Delete the lsp fom local db */
	    if(!(pccd_core_del_lspvec_senderr (rpd_lsp->id, true, true, pce_err))){
		TRACE_RPD("Failed to cleanup the LSP from local db and send msg");
	    }

            pccd_rpd_lsp_err_rmv_lsp(rpd_lsp);
	    break;

	 case TAG_EXTCTRL_ERROR_UPDATE_LOCAL_LSP:
	 case TAG_EXTCTRL_ERROR_DELETE_LOCAL_LSP:
	    TRACE_RPD("Unable to Update/Delete LSP with lsp_name: '%s', path_name '%s' hence "
		      "send error msg to PCE", rpd_lsp->lsp_name, rpd_lsp->path_name);
	    pce_err.pce_err_type = PCEP_ERR_TYPE_PCCREATE;
	    pce_err.pce_err_val = PCEP_ERR_VAL_INTERNAL_ERROR;
		
	    if (!rpd_lsp) {
		TRACE_RPD("Can't find lsp with lsp_name: '%s', path_name '%s' in local LSP cache", 
			rpd_lsp->lsp_name, rpd_lsp->path_name);
		break;
	    }

	    /* send the error back to pce DONOT delete LSP*/
	    if(!(pccd_core_del_lspvec_senderr (rpd_lsp->id, false,
                                               true, pce_err))){
		TRACE_RPD("Failed to send error to pce");
	    }

            /*PCCD debugging utility*/
            pccd_rpd_update_instance(rpd_lsp, LAST_PCERR_SENT);

	    break;

        case TAG_EXTCTRL_ERROR_P2MP_LSP_NAME_CONFLICT:
        {
            struct pccd_rpd_lsp_info *del_lsp = NULL;
            struct pccd_rpd_lsp_info *tmp_lsp = NULL;
            bool deleted_all = false;

            TRACE_RPD("Deleting p2mp lsp '%s' and all branches from local db", 
                p2mp_lsp->p2mp_name);
            pce_err.pce_err_type = PCEP_ERR_TYPE_INTERNAL_ERROR;
            pce_err.pce_err_val = PCEP_ERR_VALUE_INTERNAL_ERROR;
            if (!p2mp_lsp) {
              TRACE_RPD("Can't find lsp '%s' in local LSP cache", p2mp_lsp->p2mp_name);
              break;
            }

            /* Delete the lsp fom local db */
            if(!(pccd_core_del_lspvec_senderr (p2mp_lsp->plsp_id, true, true, pce_err))){
              TRACE_RPD("Failed to cleanup the LSP from local db and send msg");
            }

            /* Delete the LSPs from the rpd info */
            SLIST_FOREACH_SAFE(del_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {

            char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
            struct pccd_rpd_lsp_info *rpd_lsp_del = NULL;

            pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name), 
                del_lsp->lsp_name, del_lsp->path_name);
            
            rpd_lsp_del = pccd_rpd_get_specific_lsp(lsp_full_name, 
                          SETUP_TYPE_RSVP, RSVP_P2MP_LEAF);
            
            if (!rpd_lsp_del) {
                TRACE_RPD("Can't find lsp with lsp_name: '%s', path_name '%s' in "
                    "local LSP cache", del_lsp->lsp_name, del_lsp->path_name);
                continue;
                }
            
                if (1 == p2mp_lsp->branch_lsp_count) {
                    deleted_all = true;
                }

                pccd_rpd_lsp_err_rmv_lsp(rpd_lsp_del);
                if (deleted_all) {
                    break;
                }
            }

        }
        break;
            
        default:
	    TRACE_RPD("Invalid RPD LSP Error");
     }

    TRACE_FUNCTION_EXIT();
}


/**
 * pccd_rpd_remove_local_sr_lsps
 *
 * Remove all locally stored SR LSP's if none
 * of PCE is SR capable.
 *
 * @return void
 */

static void
pccd_rpd_remove_local_sr_lsps(void)
{
    name_node_t *_curr = NULL;
    name_node_t *_next = NULL;

    TRACE_FUNCTION_ENTRY();

    if (lspid_tree) {
        for(uint8_t sub_type = 0; sub_type < SR_SUBTYPE_MAX; sub_type++) {
            name_tree_t *tree_name = pccd_rpd_get_name_tree(SETUP_TYPE_SR,
                sub_type);
            if(NULL == tree_name) {
                LOGGING_ERR("Error finding internal storage while deleting all SR LSPs");
                TRACE_FUNCTION_RETURN();
            }
            for (_curr = name_tree_next_node(tree_name, NULL);
                _curr;_curr = _next){
                pccd_rpd_lsp *rpd_lsp = NULL;

                _next = name_tree_next_node(tree_name, _curr);
                rpd_lsp = (pccd_rpd_lsp *)_curr->data;

		// Check if any PCE is SR capable
                if (pccd_rpd_remove_local_sr_lsp(&rpd_lsp->lsp_info)) {
                    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
                    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                    rpd_lsp->lsp_info.lsp_name, rpd_lsp->lsp_info.path_name);

                    TRACE_RPD("Deleting lsp with lsp_name:'%s',path_name '%s' from local db",
                        rpd_lsp->lsp_info.lsp_name, rpd_lsp->lsp_info.path_name);

                    INSIST_ERR(name_tree_delete(tree_name, lsp_full_name) != NULL);
                    if (pccd_rpd_rbtree_delete(&rpd_lsp->lsp_node)) {
                        LOGGING_ERR("Could not delete lsp with lsp_name '%s' , path_name '%s' "
                            "from RB tree", rpd_lsp->lsp_info.lsp_name,
                            rpd_lsp->lsp_info.path_name);
                    }
                    pccd_rpd_decrement_lsp_count();
                    pccd_rpd_free_lsp_buffers(&rpd_lsp->lsp_info);
                    pccd_rpd_free_lsp_div_assoc_info(&rpd_lsp->lsp_info);
                    pccd_rpd_free_pce_proposed_ero(&rpd_lsp->lsp_info);
                    pccd_rpd_free_intended_metric(&rpd_lsp->lsp_info);
                    pccd_rpd_free_actual_metric(&rpd_lsp->lsp_info);

                    /* Delete all prefix info from lsp */
                    pccd_rpd_lsp_delete_all_prefix_info(rpd_lsp->lsp_info.prefix_root);
                    rpd_lsp->lsp_info.prefix_root = NULL;

                    free(rpd_lsp);
                }
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}


/**
 * pccd_rpd_remove_local_srv6_lsps
 *
 * Remove all locally stored SRv6 LSP's
 * from name tree and id tree(pccd_core_remove_local_srv6_lsp_cb)
 * if none of PCE is SR capable.
 *
 * @return void
 */

static void
pccd_rpd_remove_local_srv6_lsps(void)
{
    name_node_t *_curr = NULL;
    name_node_t *_next = NULL;

    TRACE_FUNCTION_ENTRY();

    if (lspid_tree) {
        for(uint8_t sub_type = 0; sub_type < SRv6_SUBTYPE_MAX; sub_type++) {
            name_tree_t *tree_name = pccd_rpd_get_name_tree(SETUP_TYPE_SRv6,
                sub_type);
            if(NULL == tree_name) {
                LOGGING_ERR("Error finding internal storage while deleting all SRv6 LSPs");
                TRACE_FUNCTION_RETURN();
            }
            for (_curr = name_tree_next_node(tree_name, NULL);
                _curr;_curr = _next){
                pccd_rpd_lsp *rpd_lsp = NULL;

                _next = name_tree_next_node(tree_name, _curr);
                rpd_lsp = (pccd_rpd_lsp *)_curr->data;

        // Check if any PCE is SRv6 capable
                if (pccd_rpd_remove_local_srv6_lsp(&rpd_lsp->lsp_info)) {
                    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
                    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                    rpd_lsp->lsp_info.lsp_name, rpd_lsp->lsp_info.path_name);

                    TRACE_RPD("Deleting lsp with lsp_name:'%s',path_name '%s' from local db",
                        rpd_lsp->lsp_info.lsp_name, rpd_lsp->lsp_info.path_name);

                    INSIST_ERR(name_tree_delete(tree_name, lsp_full_name) != NULL);
                    if (pccd_rpd_rbtree_delete(&rpd_lsp->lsp_node)) {
                        LOGGING_ERR("Could not delete lsp with lsp_name '%s' , path_name '%s' "
                            "from RB tree", rpd_lsp->lsp_info.lsp_name,
                            rpd_lsp->lsp_info.path_name);
                    }
                    pccd_rpd_decrement_lsp_count();
                    pccd_rpd_free_lsp_buffers(&rpd_lsp->lsp_info);
                    pccd_rpd_free_lsp_div_assoc_info(&rpd_lsp->lsp_info);
                    pccd_rpd_free_pce_proposed_ero(&rpd_lsp->lsp_info);
                    pccd_rpd_free_intended_metric(&rpd_lsp->lsp_info);
                    pccd_rpd_free_actual_metric(&rpd_lsp->lsp_info);

                    /* Delete all prefix info from lsp */
                    pccd_rpd_lsp_delete_all_prefix_info(rpd_lsp->lsp_info.prefix_root);
                    rpd_lsp->lsp_info.prefix_root = NULL;

                    free(rpd_lsp);
                }
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}

/* NSR Begin */
/*
 * Send request all flowspec info to RPD
 */
void
pccd_rpd_request_all_flowspec_info (void)
{
    int res;

    TRACE_FUNCTION_ENTRY();

    res = pccd_rpd_ipc_extr_flowspec_send_get_all_info(pccd_rpd_ses_hndl);
    if (res) {
        TRACE_RPD("Error in sending FlowSpec all info");
        return;
    }
    
    pccd_rpd_get_all_flowspec_info = true;

    TRACE_FUNCTION_EXIT();
}
/* NSR End */

static void
pccd_rpd_lsp_no_conf(rpd_session_handle handle)
{
    rbnode *_curr = NULL;
    rbnode *_prev = NULL;
    struct pccd_rpd_lsp_info *last_extern = NULL;
    struct pccd_rpd_lsp_info *last = NULL;

    TRACE_FUNCTION_ENTRY();

    /**
     * When pccd requests get all lsp from RPD,
     * RPD inturn requests this from TAG, RSVP and SPRING-TE modules and
     * at last from RPD module for flowspec configured.
     * Each module will send all lsp info to PCCD followed by end of marker.
     * Once PCCD receives end of marker from every modules, 
     * PCCD will sync all lsp to pce.
     */
    pccd_rpd_lsp_batch_end_count = pccd_rpd_lsp_batch_end_count + 1;
    if (pccd_rpd_lsp_batch_end_count != PCCD_RPD_MAX_BATCH_END_COUNT) {
        TRACE_RPD("pccd_rpd lsp batch end count = %d",
                  pccd_rpd_lsp_batch_end_count);

        if (!pccd_rpd_get_all_flowspec_info && 
		    (pccd_rpd_lsp_batch_end_count == (PCCD_RPD_MAX_BATCH_END_COUNT - 1))) {
            /**
             * For P2MP LSP, FlowSpec might be configured,
             * We need to ask RPD about configured fs instance.
             * By this time RSVP LSP should be stored in PCCD
             */
            pccd_rpd_request_all_flowspec_info();
        }
        TRACE_FUNCTION_EXIT();
        return;
    } else {
        pccd_rpd_lsp_batch_end_count = 0;
    }

    /*
     * If pce is not spring capable, then statically configured
     * SR LSP will not be reported and need to be removed from local db.
     */
    pccd_rpd_remove_local_sr_lsps();
    /*
     * If pce is not SRv6 capable, then statically configured
     * SRv6 LSP will not be reported and need to be removed from local db.
     */
    pccd_rpd_remove_local_srv6_lsps();

    TRACE_RPD("We have %u lsps stored locally", pccd_rpd_get_lsp_count());
    /* Go through the list of LSPs and send 'reports' to pccd_rps'
     * clients */

    if (lspid_tree) {
	for (_curr = junos_redblack_find_next(lspid_tree, NULL);
	     _curr;_curr = junos_redblack_find_next(lspid_tree, _prev)){
	    pccd_rpd_lsp *lsp_curr_struct = pccd_rpd_node_to_struct(_curr);
            if (!last_extern && (lsp_curr_struct->lsp_info.type == LSP_TYPE_EXTERNALLY_CONTROLLED)) {
            	last_extern = &lsp_curr_struct->lsp_info;
		
            	continue;
            }
	    if (!last) {
		last = &lsp_curr_struct->lsp_info;
		continue;
	    }
	    if(!_prev)
	    {
		_prev = _curr;
		continue;
    	    }
            pccd_rpd_lsp_report(last, false, false, true);
	    last = &lsp_curr_struct->lsp_info;
	    _prev = _curr;
	}
    }

    if (p2mp_tree) {
    	struct pccd_rpd_lsp_info *p2mp_br = NULL;
    	struct pccd_rpd_lsp_info *p2mp_tmp = NULL;
	for (_curr = junos_redblack_find_next(p2mp_tree, NULL);
             _curr;_curr = junos_redblack_find_next(p2mp_tree, _prev)){
            pccd_rpd_p2mp_lsp *p2mp_node = pccd_rpd_p2mp_node_to_struct(_curr);
	    SLIST_FOREACH_SAFE(p2mp_br, &p2mp_node->info.p2mp_branch_lsps, lv_p2mp_lsps, p2mp_tmp) {
		if (!last_extern && (p2mp_br->type == LSP_TYPE_EXTERNALLY_CONTROLLED)) {
                    last_extern = p2mp_br;
                    continue;
                }
            	if (!last) {
                    last = p2mp_br;
                    continue;
                }
                pccd_rpd_lsp_report(last, false, false, true);
                last = p2mp_br;
	    }
	    _prev = _curr;
	}
    }

    if (last_extern) {
        if (last) {
            pccd_rpd_lsp_report(last, false, false, true);
        }
        pccd_rpd_lsp_report(last_extern, true, false, true);
    } else {
        if (last) {
            pccd_rpd_lsp_report(last, true, false, true);

            if (last->type == LSP_TYPE_EXTERNALLY_PROVISIONED){
                /* Send Report with no LSP */
                TRACE_RPD("Sending End of Marker Sync LSP");
                pccd_rpd_lsp_report(NULL, true, false, true);
            }
        }
    }
    pccd_rpd_in_get_all_lsps_info = false;
    pccd_rpd_get_all_flowspec_info = false;

    if(!pccd_rpd_get_lsp_count()){
	/* Send Report with no LSP */
        pccd_rpd_lsp_report(NULL, true, false, true);
    }

    /* process all replication lsps for backup pccd */
    /* NSR Begin */
    if (!pccd_nsr_master()) {
        pccd_repl_process_all_lsp();
        pccd_repl_process_all_fs();
    }
    /* NSR End */
    
    TRACE_FUNCTION_EXIT();
}

static void
pccd_rpd_lsp_ext_ctrl_acc(rpd_session_handle handle, boolean accepted)
{
    TRACE_FUNCTION_ENTRY();
    if (!accepted) {
	LOGGING_ERR("\"pccd\" has not been accepted by RPD as external "
                    "controller");
        pccd_rpd_session_close(pccd_rpd_ev_ctx, handle);
        pccd_rpd_transition_to_closed();
        pccd_rpd_schedule_reconnect();
        TRACE_FUNCTION_RETURN();
    }

    pccd_rpd_transition_to_up();

    TRACE_FUNCTION_EXIT();
}

struct rpd_client_jnx_funs jnx_funcs = {
        .rsvp_lsp_info = NULL,
        .rsvp_p2mp_lsp_info = NULL,
        .ldp_fec_info = NULL,
        .ldp_p2mp_fec_info = NULL,
        .igp_fec_info = NULL,
        .vpn_pfx_info = NULL,
        .l2vpn_info = NULL,
        .l2vpn_fec129_info = NULL,
        .l2ckt_info = NULL,
        .endpt_info = NULL,
        .bgp_fec_info = NULL,
        .lspmon_info = NULL,
        .static_lsp_info = NULL,
        .mib2d_tdm_info = NULL,
        .pcreq_status_recv = pccd_rpd_pcrequest_recv,
        .lsp_del_recv = pccd_rpd_lsp_del_recv,
        .lsp_err_recv = pccd_rpd_lsp_err_recv,
        .lsp_no_conf = pccd_rpd_lsp_no_conf,
        .lsp_ext_ctrl_acc = pccd_rpd_lsp_ext_ctrl_acc,
        .lsys_nsr_port_info = NULL,
        .pccd_flow_spec_msg_cfg = pccd_rpd_ipc_extr_flowspec_recv_cfg_upd,
        .pccd_flow_spec_msg_rpt = pccd_rpd_ipc_extr_flowspec_recv_rpt,
        .srte_frag_pcreq_status_recv = pccd_rpd_pcrequest_frag_recv
};

static void
pccd_rpd_sock_readable_cb(evContext ctx UNUSED, void *uap UNUSED, int fd,
                          int evmask)
{
    if (evmask != EV_READ && evmask != (EV_READ & EV_WRITE)) {
        LOGGING_ERR("Invalid event mask: %d", evmask);
        exit(EX_SOFTWARE);
    }

    TRACE_RPD("There's something to read on rpd's fd %d", fd);

    if (-1 == rpd_session_reply_get(pccd_rpd_ses_hndl)) {
        LOGGING_ERR("rpd_session_reply_get failed: %d %s", errno,
                    strerror(errno));
    }
}

static int
pccd_rpd_handle_setup(rpd_session_handle *hndl)
{
    static boolean set_up = false;

    if (set_up) {
        return 0;
    }

    if (rpd_session_handle_alloc(hndl, &funcs) != 0) {
        if (errno == EINVAL) {
            LOGGING_ERR("rpd_ses_hndl %p or funcs %p is NULL",
                        *hndl, &funcs);
            return -1;
        } else if (errno == ENOMEM) {
            LOGGING_ERR("No free memory");
            return -1;
        } else {
            LOGGING_ERR("Unknown err from rpd_session_handle_alloc: %d "
                        "- %s", errno, strerror(errno));
            return -1;
        }
    }

    if (rpd_session_bind_private_funs(*hndl, &jnx_funcs) == -1) {
        LOGGING_ERR("rpd_ses_hndl %p or jnx_funs %p is NULL",
                    *hndl, &jnx_funcs);
        return -1;
    }

    set_up = true;
    return 0;
}

int
pccd_rpd_reg_state_change(pccd_rpd_state_change_fn cb)
{
    pccd_rpd_state_change = cb;
    return 0;
}

int
pccd_rpd_reg_lsp_added(pccd_rpd_lsp_added_fn cb)
{
    pccd_rpd_lsp_added = cb;
    return 0;
}

int
pccd_rpd_reg_lsp_deleted(pccd_rpd_lsp_deleted_fn cb)
{
    pccd_rpd_lsp_deleted = cb;
    return 0;
}

int
pccd_rpd_reg_lsp_report(pccd_rpd_lsp_report_fn cb)
{
    pccd_rpd_lsp_report = cb;
    return 0;
}

int
pccd_rpd_reg_lsp_deleg_chg(pccd_rpd_lsp_deleg_fn cb)
{
    pccd_rpd_lsp_deleg = cb;
    return 0;
}

int
pccd_rpd_reg_lsp_request(pccd_rpd_lsp_request_fn cb)
{
    pccd_rpd_lsp_request = cb;
    return 0;
}

int
pccd_rpd_reg_remove_local_sr_lsp(pccd_rpd_remove_local_sr_lsp_fn cb)
{
    pccd_rpd_remove_local_sr_lsp = cb;
    return 0;
}

int
pccd_rpd_reg_remove_local_srv6_lsp(pccd_rpd_remove_local_srv6_lsp_fn cb)
{
    pccd_rpd_remove_local_srv6_lsp = cb;
    return 0;
}

/**
 * Search for LSP with (c) id in local RB tree cache. Return pointer to the
 * local (c) pccd_rpd_lsp_info.
 * @param id[in] ID of the LSP to search for.
 * @return pointer to (c) pccd_rpd_lsp_info if LSP with ID was found, otherwise
 *         NULL.
 */
struct pccd_rpd_lsp_info *
pccd_rpd_get_lsp_by_id(const uint32_t id)
{
    rbnode *lsp_node = pccd_rpd_rbtree_get_node(id);
    pccd_rpd_lsp *lsp_struct;
    if(!lsp_node)
    {
	return NULL;
    }
    lsp_struct =  pccd_rpd_node_to_struct(lsp_node);
    return &lsp_struct->lsp_info;
}

/**
 * Search for P2MP LSP with (c) id in local RB tree cache. Return pointer to the
 * local (c) pccd_rpd_p2mp_lsp.
 * @param id[in] ID of the P2MP LSP to search for.
 * @return pointer to (c) pccd_rpd_p2mp_lsp if LSP with ID was found, otherwise
 *         NULL.
 */
struct pccd_p2mp_lsp_info *
pccd_rpd_get_p2mp_lsp_by_id(uint32_t id)
{
    rbnode *p2mp_node = pccd_rpd_p2mp_rbtree_get_node(id);
    pccd_rpd_p2mp_lsp *p2mp_struct;
    if(!p2mp_node)
    {
	return NULL;
    }
    p2mp_struct =  pccd_rpd_p2mp_node_to_struct(p2mp_node);
    return &p2mp_struct->info;
}

void 
pccd_rpd_get_lsp_name(char *lsp_full_name, uint8_t size,const char *name,
	const char *path_name)
{
	if(path_name && strlen(path_name)) {
	snprintf(lsp_full_name, size, "%s/%s", name, path_name);
	TRACE_RPD("name is %s , path_name is %s and lsp_full_name is %s",name, path_name, lsp_full_name);
    } else {
	snprintf(lsp_full_name, size, "%s", name);
	TRACE_RPD("name is %s and lsp_full_name is %s",name, lsp_full_name);
    }
}

void
pccd_rpd_update_instance(struct pccd_rpd_lsp_info *rpd_lsp, PCC_INSTANCE instance)
{
    TRACE_FUNCTION_ENTRY();
	
    if(!rpd_lsp){
        TRACE_FUNCTION_RETURN();
        return;
    }

    switch (instance){
        case LAST_PC_REQ_RPT:
            rpd_lsp->last_pc_req_rpt = time(NULL);
            break;
        case LAST_PCUPD_SENT:
            rpd_lsp->last_pcupd_sent = time(NULL);
            break;
        case LAST_PCERR_SENT:
            rpd_lsp->last_pcerr_sent = time(NULL);
            break;
        case LAST_PC_UPD_CRT:
            rpd_lsp->last_pc_upd_crt = time(NULL);
            break;
        default:
            LOGGING_ERR("pccd_rpd_update_instance : received incorrect instance");
    }        

    TRACE_FUNCTION_RETURN();
}

pccd_rpd_name_tree_key 
pccd_rpd_create_name_tree_key(uint8_t setup_type, uint8_t sub_type, bool is_p2mp_lsp)
{
    pccd_rpd_name_tree_key name_tree_key = {SETUP_TYPE_RSVP, RSVP_P2P};
    if(setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) {
        name_tree_key.type = SETUP_TYPE_RSVP;
        if(is_p2mp_lsp) {
            name_tree_key.sub_type = RSVP_P2MP_LEAF;
        } else {
            name_tree_key.sub_type = RSVP_P2P;
        }
    } else if(setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        name_tree_key.type = SETUP_TYPE_RSVP;
        name_tree_key.sub_type = RSVP_BYPASS;
    } else if(setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) {
        name_tree_key.type = SETUP_TYPE_SR;
        name_tree_key.sub_type = SR_P2P;
    } else if(setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE) {
        name_tree_key.type = SETUP_TYPE_SRv6;
        name_tree_key.sub_type = SRv6_P2P;
    } else {
        LOGGING_ERR("Invalid setup type %d and sub type %d received", setup_type, sub_type);
    }
    return name_tree_key;
}


const char*
pccd_rpd_get_lsp_state_str(uint16_t state)
{
    switch (state) {
    case LSP_STATE_UP:
        return "Up ";
    case LSP_STATE_DOWN:
        return "Down";
    case LSP_STATE_CREATION_PENDING:
        return "Creating";
    default:
        return "Unknown";
    }
}

/**
 *@brief
 * Tear down the path of a LSP signalled using RSVP. This functionality is not
 * applicable for SPRING because, we always want the controller to give path to
 * the router, the router as such don't have the ability to compute the path.
 *
 *@param[in] name
 *  lsp name
 *@param[in] path_name
 *  path name
 *
 *@return
 * pccd_ret_code_t pass/fail status
 */
pccd_ret_code_t
pccd_rpd_rsvp_tear_down_lsp (const char *name, const char* path_name, const u_int16_t type,
                                        const u_int32_t context)
{
    rpd_extctrl_lsp_config_status_info_t info;

    TRACE_FUNCTION_ENTRY();

    if (pccd_rpd_state != PCCD_RPD_STATE_UP) {
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));
    strncpy(info.name, name, sizeof(info.name));
    info.name[sizeof(info.name) - 1] = '\0';
    if (sizeof(info.name) < sizeof(name) &&
            strlen(name) >= sizeof(info.name)) {
        TRACE_RPD("LSP name buffer not big enough to store LSP name");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    if(strlen(path_name)) {
	strncpy(info.path_name, path_name, sizeof(info.path_name));
	info.path_name[sizeof(info.path_name) - 1] = '\0';
	if (sizeof(info.path_name) < sizeof(path_name) &&
	    strlen(path_name) >= sizeof(info.path_name)) {
	    TRACE_RPD("LSP path name buffer not big enough to store LSP name");
	    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	}
    }

    info.path_flags |= LSP_PATH_HINT_TEAR_DOWN;
    info.type = type;
    info.ero_info = NULL;
    info.ero_len = 0;
    info.lsp_type_info.setup_type = RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE;
    TRACE_RPD("LSP(%s/%s), sending disable request", info.name, info.path_name);

    if (pccd_rpd_pcupdate_send_delete(pccd_rpd_ses_hndl, context, PCCD_RPD_CLIENT_ID,
                               &info)) {
        TRACE_RPD("     failed, err(%d %s)", errno, strerror(errno));
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

/**
 *@brief
 * Update the divversity assoication information for the LSP when a PCUpd is received
 * In case of unexpected operations, ignore the updates in the messagge
 *
 *@param[in] rpd_lsp
 *  lsp information in PCCD
 *@param[in] info
 *  lsp information received in the PCUpd
 *
 *@return
 *  none
 */
static void
pccd_rpd_update_divassoc_info (struct pccd_rpd_lsp_info             *rpd_lsp,
                               rpd_extctrl_lsp_config_status_info_t *info)
{
    uint32_t              count = 0, lsp_counter = 0, add_counter = 0, delete_counter = 0, temp_count = 0;
    uint32_t              update_counter = 0;
    boolean               assoc_to_delete = false, assoc_to_update = false;
    lsp_association_info *temp = NULL;
    uint32_t              upd_pos[8] = {0,0,0,0,0,0,0,0};
    uint32_t              cur_pos[8]  = {0,0,0,0,0,0,0,0};

    TRACE_RPD("DAG: PCUpd - current div-assoc-count in pccd %u, div_assoc incoming count %u",
              rpd_lsp->div_assoc_info_count, info->div_assoc_info_count);
    /*
     * 1. Parse through the received dag_info in PCUpd and identify the count of
     *    association entries to be added or deleted or modified
     */
    while (count < info->div_assoc_info_count) {
        if (info->div_assoc_info[count].assoc_flags == 1) {
            lsp_counter = 0;
            assoc_to_delete = false;
            while (lsp_counter < rpd_lsp->div_assoc_info_count) {
                if (info->div_assoc_info[count].assoc_grp_id ==
                                            rpd_lsp->div_assoc_info[lsp_counter].assoc_grp_id) {
                    rpd_lsp->div_assoc_info[lsp_counter].assoc_flags = 1;
                    assoc_to_delete = true;
                    cur_pos[lsp_counter] = PCUPD_DAG_OP_DEL;
                    delete_counter++;
                    break;
                }
                lsp_counter++;
            }
            if (assoc_to_delete == false) {
                TRACE_RPD("DAG: association group to be delete is not found. Ignoring the DAG updates");
                return;
            }
            upd_pos[count] = PCUPD_DAG_OP_DEL;
        } else {
            lsp_counter = 0;
            assoc_to_update = false;
            while (lsp_counter < rpd_lsp->div_assoc_info_count) {
                if (info->div_assoc_info[count].assoc_grp_id ==
                                             rpd_lsp->div_assoc_info[lsp_counter].assoc_grp_id) {
                    assoc_to_update = true;
                    break;
                }
                lsp_counter++;
            }
            if (assoc_to_update) {
                update_counter++;
                cur_pos[lsp_counter] = PCUPD_DAG_OP_UPD;
                upd_pos[count] = PCUPD_DAG_OP_UPD;
            } else {
                add_counter++;
                upd_pos[count] = PCUPD_DAG_OP_ADD;
            }
        }
        count++;
    }
    TRACE_RPD("DAG: %s - div-assoc groups to be added: %u modified: %u deleted:%u", info->name,
              add_counter, update_counter, delete_counter);

    /*
     * 2. If delete entries are found in the association obj, delete the entries in dag_info in 
     *    pccd structure
     *    a) if all the entries in pccd structure are to be deleted, delete all the stored entries
     *       and add the new entries in received message
     *    b) if more entries are to be deleted than the info count in pccd, ignore the message
     *    c) if only a subset of entries are to be deleted, delete specific entries and add the 
     *       new entries
     */
    if (delete_counter) {
        if (rpd_lsp->div_assoc_info_count == delete_counter) {
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info_count = 0;
            /*
             * Add the entries received in PCUpd
             */
            if (update_counter) {
                TRACE_RPD("DAG: Unexpected update counter %u. Ignoring update operations", update_counter);
            }
            temp = NULL;
            if (add_counter) {
                temp = xmalloc(sizeof(lsp_association_info) * add_counter);
                count  = 0;
                temp_count = 0;
                while (count < info->div_assoc_info_count) {
                    if (upd_pos[count] == PCUPD_DAG_OP_DEL) {
                        count++;
                        continue;
                    }
                    memcpy(&temp[temp_count].assoc_grp_id,
                           &info->div_assoc_info[count].assoc_grp_id,
                           sizeof(lsp_association_info));
                    count++;
                    temp_count++;
                }
            }
            rpd_lsp->div_assoc_info = temp;
            rpd_lsp->div_assoc_info_count = add_counter;
            return;
        } else if (delete_counter > rpd_lsp->div_assoc_info_count) {
            TRACE_RPD("DAG: more delete assoc groups than existing number of groups, ignoring updates");
            return;
        } else {
            count = 0;
            temp_count = 0;
            temp = xmalloc(sizeof(lsp_association_info) * 
                           (rpd_lsp->div_assoc_info_count - delete_counter + add_counter));
            /*
             * First delete the required entries in pccd structure
             */
            while (count < rpd_lsp->div_assoc_info_count) {
                if ((cur_pos[count] == PCUPD_DAG_OP_DEL) ||
                    (cur_pos[count] == PCUPD_DAG_OP_UPD)) {
                    count++;
                    continue;
                }
                memcpy(&temp[temp_count].assoc_grp_id,
                       &rpd_lsp->div_assoc_info[count].assoc_grp_id,
                       sizeof(lsp_association_info));
                temp_count++;
                count++;
            }
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info_count = temp_count;
            rpd_lsp->div_assoc_info = temp;
            /*
             * Add any new dag entries from the received PCUpd
             */
            if (add_counter || update_counter) {
                count = 0;
                while (count < info->div_assoc_info_count) {
                    if (upd_pos[count] == PCUPD_DAG_OP_DEL) {
                        count++;
                        continue;
                    }
                    memcpy(&rpd_lsp->div_assoc_info[rpd_lsp->div_assoc_info_count].assoc_grp_id,
                           &info->div_assoc_info[count].assoc_grp_id,
                           sizeof(lsp_association_info));
                    rpd_lsp->div_assoc_info_count++;
                    count++;
                }
            }
            TRACE_CORE("DAG: deleted objs %u added objs %u updated objs %u", delete_counter, add_counter,
                       update_counter);
            return;
        }
    }

    /*
     * Incase no delete operation in PCUpd message for any group, follow the below flow
     */
    if (update_counter) {
        if (rpd_lsp->div_assoc_info_count == update_counter) {
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info_count = 0;
            /*
             * Add the entries received in PCUpd
             */
            rpd_lsp->div_assoc_info = info->div_assoc_info;
            rpd_lsp->div_assoc_info_count = info->div_assoc_info_count;
            return;
        } else if (update_counter > rpd_lsp->div_assoc_info_count) {
            TRACE_RPD("DAG: more update assoc groups than existing number of groups, ignoring updates");
            return;
        } else {
            count = 0;
            temp_count = 0;
            temp = xmalloc(sizeof(lsp_association_info) *
                           (rpd_lsp->div_assoc_info_count + add_counter));
            /*
             * First delete the required entries in pccd structure
             */
            while (count < rpd_lsp->div_assoc_info_count) {
                if ((cur_pos[count] == PCUPD_DAG_OP_DEL) ||
                    (cur_pos[count] == PCUPD_DAG_OP_UPD)) {
                    count++;
                    continue;
                }
                memcpy(&temp[temp_count].assoc_grp_id,
                       &rpd_lsp->div_assoc_info[count].assoc_grp_id,
                       sizeof(lsp_association_info));
                temp_count++;
                count++;
            }
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info_count = temp_count;
            rpd_lsp->div_assoc_info = temp;
            /*
             * Add any new dag entries from the received PCUpd
             */
            count = 0;
            while (count < info->div_assoc_info_count) {
                memcpy(&rpd_lsp->div_assoc_info[rpd_lsp->div_assoc_info_count].assoc_grp_id,
                       &info->div_assoc_info[count].assoc_grp_id,
                       sizeof(lsp_association_info));
                rpd_lsp->div_assoc_info_count++;
                count++;
            }
            return;
        }
    }

    if (add_counter) {
        if (rpd_lsp->div_assoc_info_count == 0) {
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info_count = info->div_assoc_info_count;
            rpd_lsp->div_assoc_info = info->div_assoc_info;
        } else {
            count = 0;
            temp_count = 0;
            temp = xmalloc(sizeof(lsp_association_info) *
                           (rpd_lsp->div_assoc_info_count + add_counter));
            while (count < info->div_assoc_info_count) {
                memcpy(&temp[temp_count].assoc_grp_id,
                       &info->div_assoc_info[count].assoc_grp_id,
                       sizeof(lsp_association_info));
                count++;
                temp_count++;
            }
            count = 0;
            while (count < rpd_lsp->div_assoc_info_count) {
                memcpy(&temp[temp_count].assoc_grp_id,
                       &rpd_lsp->div_assoc_info[count].assoc_grp_id,
                       sizeof(lsp_association_info));
                count++;
                temp_count++;
            }
            pccd_rpd_free_lsp_div_assoc_info(rpd_lsp);
            rpd_lsp->div_assoc_info = temp;
            rpd_lsp->div_assoc_info_count += add_counter;
        }
    }
}

bool
pccd_rpd_pcupdate(struct pccd_rpd_lsp_info *rpd_lsp, rpd_extctrl_lsp_config_status_info_t *info)
{
    //FIXME: check for the RPD connection state
    if (pccd_rpd_state != PCCD_RPD_STATE_UP) {
        return false;
    }

    /* send SRPAG for colored SR LSPs if not received in PCUpd */
    pccd_rpd_update_srpag(rpd_lsp, info);

    TRACE_RPD("sending update request to RPD for lsp: '%s'", info->name);
    pccd_rpd_debug_lsp_info("tx pcupd", info);

    /* Update PCE Proposed ERO for PCE Provisioned/Controlled LSP */
    pccd_rpd_update_pce_proposed_info(info);

    /* Update diversity association status flags */
    pccd_rpd_update_divassoc_info(rpd_lsp, info);

    if (pccd_rpd_pcupdate_send(rpd_lsp, pccd_rpd_ses_hndl, PCCD_RPD_CLIENT_ID,
                               info)) {
        LOGGING_ERR("rpd_pcupdate failed: %d '%s'", errno, strerror(errno));
        return false;
    }
    return true;
}

/*
 * Send all the p2mp branches to RPD which have already not been sent
 */
void
pccd_rpd_p2mp_pcupdate(struct pccd_p2mp_lsp_info *p2mp_lsp)
{
	bool trig_mbb = true;
	struct pccd_rpd_lsp_info *p2mp_br = NULL;
	struct pccd_rpd_lsp_info *p2mp_tmp = NULL;
    void *ero_info = NULL;
    uint32_t ero_len = 0;
    
	rpd_extctrl_lsp_config_status_info_t lcs;
    
	TRACE_FUNCTION_ENTRY();

	memcpy(&lcs, p2mp_lsp->lcs_pce, sizeof(lcs));
	SLIST_FOREACH_SAFE(p2mp_br, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, p2mp_tmp) {
		lcs.dstaddr_u.v4 = p2mp_br->dstaddr.v4;
		strncpy(lcs.name, p2mp_br->lsp_name, sizeof(lcs.name));
		lcs.name[sizeof(lcs.name) - 1] = '\0';
		if (trig_mbb) {
			lcs.p2mp_mbb_flag = TAG_EXTCTRL_P2MP_MBB_TRIGGER;
			trig_mbb = false;
		} else {
			lcs.p2mp_mbb_flag = 0;
		}

        /* Temporary fix, until proposed_ero_info is properly filled */
        ero_info = NULL;
        ero_len = 0;
        if (p2mp_br->pce_proposed_ero_info) {
            ero_info = p2mp_br->pce_proposed_ero_info;
		    ero_len = ntohs(((RouteObj *)(p2mp_br->pce_proposed_ero_info))->hdr.obj_length);
        } else {
            ero_info = p2mp_br->ero_info;
            ero_len = p2mp_br->ero_len;
        }

        if (ero_len) {
            lcs.ero_info = (void *)xmalloc(ero_len);
    		memcpy(lcs.ero_info, ero_info, ero_len);
    		lcs.ero_len = ero_len;
        }

	    TRACE_RPD("sending update request to RPD for lsp: '%s", lcs.name);
	    pccd_rpd_debug_lsp_info("tx pcupd", &lcs);
		if (pccd_rpd_pcupdate_send(p2mp_br, pccd_rpd_ses_hndl, PCCD_RPD_CLIENT_ID, &lcs)) {
			TRACE_RPD("Could not send PCUpdate to RPD");
			LOGGING_ERR("rpd_pcupdate failed: %d '%s'", errno, strerror(errno));
		}
        if (lcs.ero_info)
		    free(lcs.ero_info);
		lcs.ero_info = NULL;
	}
	free(p2mp_lsp->lcs_pce);
	p2mp_lsp->lcs_pce = NULL;
	BIT_RESET(p2mp_lsp->flags, IS_MBB_NEEDED);
	TRACE_FUNCTION_EXIT();
}

bool
pccd_rpd_pccreate(const rpd_extctrl_lsp_config_status_info_t *info)
{
    TRACE_FUNCTION_ENTRY();
    if (pccd_rpd_state != PCCD_RPD_STATE_UP) {
        return false;
    }
    TRACE_RPD("sending create request to RPD for LSP: '%s'", info->name);
    pccd_rpd_debug_lsp_info("tx pccreate", info);
    if (pccd_rpd_pcupdate_send(NULL, pccd_rpd_ses_hndl, PCCD_RPD_CLIENT_ID,
                               info)) {
        LOGGING_ERR("rpd_pccreate failed: %d '%s'", errno, strerror(errno));
        return false;
    }
    if (pccd_rpd_store_new_lsp(info, 0)) {
        return false;
    }

    /* Update PCE Proposed ERO for PCE Provisioned/Controlled LSP */
    pccd_rpd_update_pce_proposed_info(info);

    TRACE_FUNCTION_RETURN(true);
}

bool
pccd_rpd_delete_lsp(const struct pccd_rpd_lsp_info *rpd_lsp)
{
    rpd_extctrl_lsp_config_status_info_t info;

    TRACE_FUNCTION_ENTRY();

    if (pccd_rpd_state != PCCD_RPD_STATE_UP) {
        return false;
    }
    memset(&info, 0, sizeof(rpd_extctrl_lsp_config_status_info_t));
    strncpy(info.name, rpd_lsp->lsp_name, sizeof(info.name));
    info.name[sizeof(info.name) - 1] = '\0';
    if (sizeof(info.name) < sizeof(rpd_lsp->lsp_name) &&
            strlen(rpd_lsp->lsp_name) >= sizeof(info.name)) {
        LOGGING_ERR("LSP name buffer not big enough to store LSP name");
        abort();
    }
    if(strlen(rpd_lsp->path_name)) {
	strncpy(info.path_name, rpd_lsp->path_name, sizeof(info.path_name));
	info.path_name[sizeof(info.path_name) - 1] = '\0';
	if (sizeof(info.path_name) < sizeof(rpd_lsp->path_name) &&
	    strlen(rpd_lsp->path_name) >= sizeof(info.path_name)) {
	    LOGGING_ERR("LSP path name buffer not big enough to store LSP name");
	    abort();
	}
    }else {
	bzero(info.path_name, sizeof(info.path_name));
    }

    info.lsp_flags = TAG_EXTCTRL_LSP_FLAGS_DELETE;
    info.ero_info = NULL;
    info.ero_len = 0;
    info.srte_ero_info = NULL;
    info.lsp_type_info.setup_type = rpd_lsp->setup_type;
    if (!rpd_lsp->is_lsp_src_dst_addr_type_ipv6) {
        info.srcaddr_u.v4 = rpd_lsp->srcaddr.v4;
        info.dstaddr_u.v4 = rpd_lsp->dstaddr.v4;
    } else {
        memcpy(info.srcaddr_u.v6, rpd_lsp->srcaddr.v6, 16);
        memcpy(info.dstaddr_u.v6, rpd_lsp->dstaddr.v6, 16);
    }
    info.path_flags = rpd_lsp->path_flags;
    info.type = rpd_lsp->type;
    
    if (info.lsp_type_info.setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        info.rbyp_params.rbp_nhaddr.rbn_ipv4_addr = rpd_lsp->bypass_info.bp_nhaddr;
        info.rbyp_params.rbp_prot_type = rpd_lsp->bypass_info.bp_prot_type;
        info.rbyp_params.rbp_subscr = (uint32_t)rpd_lsp->bypass_info.bp_subscr;
    }
    
    TRACE_RPD("sending delete request to RPD for LSP '%s' "
	      "and path_name: '%s'", info.name, info.path_name);

    if (pccd_rpd_pcupdate_send_delete(pccd_rpd_ses_hndl, rpd_lsp->context, PCCD_RPD_CLIENT_ID,
                               &info)) {
        LOGGING_ERR("rpd_pcdelete failed: %d '%s'", errno, strerror(errno));
        return false;
    }
    TRACE_FUNCTION_RETURN(true);
}

bool
pccd_rpd_lsp_get_control_all(void)
{
    TRACE_FUNCTION_ENTRY();

    /* NSR Begin */
    if (!pccd_nsr_master()) {
        TRACE_FUNCTION_RETURN(true);
    }
    /* NSR End */

    if (pccd_rpd_lsp_get_controll_all_send(pccd_rpd_ses_hndl)) {
        LOGGING_ERR("pccd_rpd_lsp_get_control_all failed: %d %s", errno,
                    strerror(errno));
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_FUNCTION_RETURN(true);
}

bool
pccd_rpd_lsp_return_control_all(void)
{
    TRACE_FUNCTION_ENTRY();

    /* NSR Begin */
    if (!pccd_nsr_master())
        TRACE_FUNCTION_RETURN(true);
    /* NSR End */

    if (pccd_rpd_lsp_return_control_all_send(pccd_rpd_ses_hndl)) {
        LOGGING_ERR("pccd_rpd_lsp_return_control_all_send failed: %d %s", errno,
                    strerror(errno));
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_FUNCTION_RETURN(true);
}

bool
pccd_rpd_lsp_get_control(const struct pccd_rpd_lsp_info *lsp)
{
    TRACE_FUNCTION_ENTRY();
    if (!lsp) {
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_RPD("Sending get_control request to RPD for lsp '%s'", lsp->lsp_name);
    if (pccd_rpd_lsp_get_control_send(pccd_rpd_ses_hndl, lsp->lsp_name, lsp->path_name,
             lsp->setup_type, lsp->sub_type, lsp->context)) {
        LOGGING_ERR("pccd_rpd_lsp_get_control_send failed: %d '%s'", errno,
                    strerror(errno));
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_FUNCTION_RETURN(true);
}

bool
pccd_rpd_lsp_return_control(const struct pccd_rpd_lsp_info *lsp)
{
    TRACE_FUNCTION_ENTRY();
    if (!lsp) {
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_RPD("Sending return_control request to RPD for lsp with lsp_name '%s', path_name '%s'", 
		lsp->lsp_name,lsp->path_name);
    if (pccd_rpd_lsp_return_control_send(pccd_rpd_ses_hndl, lsp->lsp_name,
                                         lsp->path_name, lsp->setup_type,
                                         lsp->sub_type, lsp->context)) {
        LOGGING_ERR("rpd_lsp_return_control failed: %d '%s'", errno,
                    strerror(errno));
        TRACE_FUNCTION_RETURN(false);
    }
    TRACE_FUNCTION_RETURN(true);
}

void
pccd_rpd_delete_all_provisioned_lsps(void)
{
    rbnode *_curr = NULL;
    rbnode *_next = NULL;

    TRACE_FUNCTION_ENTRY();

    if (lspid_tree) {
        for (_curr = junos_redblack_find_next(lspid_tree, NULL);
             _curr; _curr = _next){
            pccd_rpd_lsp *lsp_struct = NULL;

            _next = junos_redblack_find_next(lspid_tree, _curr);
            lsp_struct = pccd_rpd_node_to_struct(_curr);
            if (lsp_struct->lsp_info.type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                pccd_rpd_delete_lsp(&lsp_struct->lsp_info);
            }
        }
    }

    if (p2mp_tree) {
        for (_curr = junos_redblack_find_next(p2mp_tree, NULL);
             _curr; _curr = junos_redblack_find_next(p2mp_tree, _curr)){
            pccd_rpd_p2mp_lsp *p2mp_node = pccd_rpd_p2mp_node_to_struct(_curr);
            struct pccd_rpd_lsp_info *p2mp_br = NULL;
            struct pccd_rpd_lsp_info *p2mp_tmp = NULL;
            SLIST_FOREACH_SAFE(p2mp_br, &p2mp_node->info.p2mp_branch_lsps, lv_p2mp_lsps, p2mp_tmp) {
                if (p2mp_br->type == LSP_TYPE_EXTERNALLY_PROVISIONED) {
                    pccd_rpd_delete_lsp(p2mp_br);
                }
            }
        }
    }

    TRACE_FUNCTION_EXIT();
}

/* Checks for the RPD connection state */
bool
pccd_rpd_is_up(void)
{
    return pccd_rpd_state == PCCD_RPD_STATE_UP;
}

static int
pccd_rpd_reconnect(void)
{
    if (pccd_rpd_session_close(pccd_rpd_ev_ctx, pccd_rpd_ses_hndl)) {
	LOGGING_ERR("Could not close connection with RPD gracefully.");
    }
    if (pccd_rpd_state != PCCD_RPD_STATE_CLOSED) {
        pccd_rpd_transition_to_closed();
    }


    if (pccd_rpd_connect(pccd_rpd_ev_ctx)) {
        LOGGING_ERR("Could not reconnect with RPD");
        return -1;
    }
    return 0;
}

static void
pccd_rpd_scheduled_reconnect(evContext ctx UNUSED, void *uap UNUSED,
                             struct timespec due UNUSED,
                             struct timespec inter UNUSED)
{
    if (pccd_rpd_reconnect()) {
        if (pccd_rpd_schedule_reconnect()) {
            exit(EX_SOFTWARE);
        }
    }
}

static int
pccd_rpd_schedule_reconnect(void)
{
    INSIST_ERR(pccd_rpd_state == PCCD_RPD_STATE_CLOSED);


    if (-1 == evSetTimer(pccd_rpd_ev_ctx, pccd_rpd_scheduled_reconnect, NULL,
                         evAddTime(evNowTime(), evConsTime(PCCD_RPD_RECONNECT, 0)),
                         evConsTime(0,0), NULL)) {
        LOGGING_ERR("Scheduling of RPD reconnection timer failed");
        return -1;
    }

    return 0;
}

static int
pccd_rpd_connect(evContext ctx)
{
    sockaddr_un *sock;
    int path_len = (strlen(RPD_SERVER_PATH) + 1) + sizeof(sock->un);
    int rpd_fd = 0;
    int nlen = 0;
    int ret = 0;

    TRACE_RPD("Connecting to RPD socket: %s", RPD_SERVER_PATH);

    nlen = ROUNDUP(path_len, (int)sizeof(u_long));

    sock = calloc(1, nlen);
    sock->un.gun_len = nlen;
    sock->un.gun_family = GF_UNIX;
    strlcpy(sock->un.gun_path, RPD_SERVER_PATH, sizeof(RPD_SERVER_PATH));

    if (evTestID(pccd_rpd_read_id)) {
        if (evDeselectFD(ctx, pccd_rpd_read_id)) {
            LOGGING_ERR("Could not release previous RPD's FD from eventlib");
            exit(EX_SOFTWARE);
        }
        evInitID(&pccd_rpd_read_id);
    }

    if (evTestID(pccd_rpd_write_id)) {
        if (evDeselectFD(ctx, pccd_rpd_write_id)) {
            LOGGING_ERR("Could not release previous RPD's FD from eventlib");
            exit(EX_SOFTWARE);
        }
        evInitID(&pccd_rpd_write_id);
    }

    pccd_rpd_transition_to_connecting();
    ret = rpd_session_connect(pccd_rpd_ses_hndl, sock, 0);
    
    /* free this previously allocated sock structure */
    free(sock);

    if (ret) {
        int s = 0;
        int n = 0;
        fd_set wset;
        struct timeval connect_timeout;

        if (errno != EINPROGRESS) {
            LOGGING_ERR("connect to routing subsystem failed, code=%d %s",
                        errno, strerror(errno));
            pccd_rpd_transition_to_closed();
            return -1;
        }
        /*
         * EINPROGRESS: give it some time to connect
         */
        s = rpd_session_handle_descriptor(pccd_rpd_ses_hndl);
        if (s == -1) {
            LOGGING_ERR("Could not extract file descriptor from librpd "
                        "session handle");
            pccd_rpd_transition_to_closed();
            return -1;
        }

        FD_ZERO(&wset);
        FD_SET(s, &wset);

        connect_timeout.tv_sec = PCCD_RPD_CONNECT_TIMEOUT_SECS;
        connect_timeout.tv_usec = 0;

        n = select(1, NULL, &wset, NULL, &connect_timeout);
        if (n < 0) {
            LOGGING_ERR("Connecting to routing subsystem failed %d %s",
                        errno, strerror(errno));
            pccd_rpd_transition_to_closed();
            return -1;
        } else if (n == 0){
            LOGGING_ERR("Connect timeout to routing subsystem");
            pccd_rpd_transition_to_closed();
            return -1;
        }

        //Connected, receive first message
        rpd_session_reply_get(pccd_rpd_ses_hndl);
        if (pccd_rpd_state != PCCD_RPD_STATE_CONNECTED) {
            LOGGING_ERR("Connecting to routing subsystem failed");
            pccd_rpd_transition_to_closed();
            return -1;
        }
    }

    rpd_fd = rpd_session_handle_descriptor(pccd_rpd_ses_hndl);
    if (rpd_fd == -1) {
        LOGGING_ERR("librpd declared the session as established, but "
                    "can't retrieve socket FD");
        pccd_rpd_transition_to_closed();
        return -1;
    }

    TRACE_RPD("evSelectFD on RPD's FD %d", rpd_fd);
    if (evSelectFD(ctx, rpd_fd, EV_READ, pccd_rpd_sock_readable_cb,
                   pccd_rpd_ses_hndl, &pccd_rpd_read_id) == -1) {
        LOGGING_ERR("evSelectFD failed for: %p, %d, EV_READ, %p, NULL, %p",
                    ctx.opaque, rpd_fd, pccd_rpd_sock_readable_cb,
                    pccd_rpd_read_id.opaque);
        /* Can't store RPD's socket FD in eventlib, PCCD <--> RPD communication
         * won't ever work - die. */
        exit(EX_SOFTWARE);
    }

    return 0;
}

int
pccd_rpd_init(evContext ctx, boolean is_master)
{
    uint8_t type = 0;
    uint8_t sub_type = 0;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(!evTestID(pccd_rpd_ev_ctx));
    pccd_rpd_ev_ctx = ctx;

    if (pccd_rpd_handle_setup(&pccd_rpd_ses_hndl)) {
	LOGGING_ERR("Failed to set up rpd_session_handle");
	TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }

	if (pccd_rpd_connect(ctx)) {
	    LOGGING_ERR("Could not connect to RPD");
	    if (pccd_rpd_schedule_reconnect()) {
		TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	    }
	}

    do {
        name_tree_t *tree_name = pccd_rpd_get_name_tree(type,sub_type);
        if(NULL == tree_name) {
           LOGGING_ERR("Error finding internal storage while initializing");
           TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        if(name_tree_init(tree_name) == FALSE) {
           LOGGING_ERR("Could not initialize LSPs name tree");
           TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
        }
        sub_type++;
        if(sub_type >= pccd_rpd_get_subtype_tree_count(type)) {
           type++;
           sub_type = 0;
        }
    }while(type < SETUP_TYPE_MAX);

    if (name_tree_init(&pccd_p2mp_lsps) == FALSE) {
        LOGGING_ERR("Could not initialize P2MP LSPs name tree");
        TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
    }
    pccd_rpd_rbtree_init();
    pccd_rpd_rbtree_p2mp_init();
    pccd_rpd_sr_color_cpath_table_init();

    pccd_rpd_in_get_all_lsps_info = false;
    pccd_rpd_get_all_flowspec_info = false;

    total_lsps = 0;

    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

int
pccd_rpd_connect_to_rpd(evContext ctx)
{
    TRACE_FUNCTION_ENTRY();
    if (pccd_rpd_connect(ctx)) {
	LOGGING_ERR("Could not connect to RPD");
	if (pccd_rpd_schedule_reconnect()) {
	    TRACE_FUNCTION_RETURN(PCCD_RET_FAIL);
	}
    }
    TRACE_FUNCTION_RETURN(PCCD_RET_SUCCESS);
}

struct pccd_p2mp_lsp_info *pccd_get_p2mp_lsp_by_name(const char name[RPD_LSP_NAME_SIZE+1])
{
    pccd_rpd_p2mp_lsp *p2mp_lsp_node = name_tree_lookup(&pccd_p2mp_lsps, name);
    return p2mp_lsp_node ? &p2mp_lsp_node->info : NULL;
}

/*
pass *node to NULL to get first element 
to get next pass the previous name node
*/
struct pccd_p2mp_lsp_info *pccd_get_p2mp_lsp_next(void **node)
{
    name_node_t* next_node = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    
    next_node = name_tree_next_node(&pccd_p2mp_lsps, (name_node_t *)*node);
    if (NULL != next_node) {
        p2mp_lsp = &((pccd_rpd_p2mp_lsp *)next_node->data)->info;
    }

    *node = (void *)next_node;
    return p2mp_lsp;
}

/*
 * Clear p2mp_lsp->lcs_pce
 * The attributes which came with pcupdate message
 */
void
pccd_rpd_clear_p2mp_pcupdate_params (struct pccd_p2mp_lsp_info *p2mp_lsp)
{
	TRACE_FUNCTION_ENTRY();

	BIT_RESET(p2mp_lsp->flags, IS_MBB_NEEDED);
	if (p2mp_lsp)
		if (p2mp_lsp->lcs_pce) {
			free(p2mp_lsp->lcs_pce);
			p2mp_lsp->lcs_pce = NULL;
		}

	TRACE_FUNCTION_EXIT();
}

int
pccd_remove_p2mp_lsp (char *name)
{
    pccd_rpd_p2mp_lsp *p2mp_lsp_node = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    TRACE_FUNCTION_ENTRY();
    TRACE_RPD("Deleting p2mp lsp '%s' from local db", name);

    p2mp_lsp_node = name_tree_lookup(&pccd_p2mp_lsps, name);
    if (!p2mp_lsp_node) {
        TRACE_RPD("Can't find p2mp lsp '%s' in local P2MP LSP cache", name);
        TRACE_FUNCTION_RETURN(0);
    }

    p2mp_lsp = &p2mp_lsp_node->info;

    if (0 != p2mp_lsp->branch_lsp_count){
        TRACE_RPD("Number(%d) of LSPs is non-zero", p2mp_lsp->branch_lsp_count);
        TRACE_FUNCTION_RETURN(0);
    }

    INSIST_ERR(name_tree_delete(&pccd_p2mp_lsps, name) != NULL);

    if ((p2mp_lsp->plsp_id) &&
        (NULL != pccd_rpd_get_p2mp_lsp_by_id(p2mp_lsp->plsp_id))) {

        junos_redblack_delete(p2mp_tree, &p2mp_lsp_node->p2mp_node);
        pccd_rpd_decrement_lsp_count();
    }

    pccd_core_p2mp_lsp_clear_frag_tid(p2mp_lsp);
    pccd_rpd_clear_p2mp_pcupdate_params(p2mp_lsp);
    free(p2mp_lsp_node);

    TRACE_FUNCTION_RETURN(0);
}

lsp_op_value_t
pccd_rpd_get_p2mp_lsp_op_value (const struct pccd_p2mp_lsp_info *p2mp_lsp, 
                        u_int16_t rpd_lsp_id, bool match_lsp_id)
{
    lsp_op_value_t state = LSP_OP_DOWN;
    struct pccd_rpd_lsp_info *rpd_lsp= NULL;
    struct pccd_rpd_lsp_info *tmp_lsp = NULL;

    INSIST_ERR(p2mp_lsp != NULL);

    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp_lsp) {
        if (match_lsp_id && (rpd_lsp_id != rpd_lsp->lsp_id)) {
            continue;
        }
        switch (rpd_lsp->state) {
        case LSP_STATE_ACTIVE:
            return LSP_OP_ACTIVE;
        case LSP_STATE_UP:
            state = LSP_OP_UP;
            break;
        default:
            break;
        }
    }

    return state;
}

struct pccd_p2mp_lsp_info *pccd_add_p2mp_lsp(const rpd_extctrl_lsp_config_status_info_t *info)
{
    pccd_rpd_p2mp_lsp *p2mp_lsp_node = NULL;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(info != NULL);
    INSIST_ERR(strlen(info->p2mp_name)  != 0);
    
    p2mp_lsp_node = calloc(1, sizeof(*p2mp_lsp_node));
    bzero(p2mp_lsp_node, sizeof(pccd_rpd_p2mp_lsp));

    p2mp_lsp = &p2mp_lsp_node->info;
    
    snprintf(p2mp_lsp->p2mp_name, sizeof(p2mp_lsp->p2mp_name), "%s", info->p2mp_name);    

    /* Insert the P2MP LSP into name tree, so that we can retrieve P2MP LSP by the name. */
    if (!name_tree_add(&pccd_p2mp_lsps, p2mp_lsp->p2mp_name, p2mp_lsp_node)) {
        LOGGING_ERR("name_tree_add failed");
        abort();
    }

    TRACE_RPD("Stored new P2MP LSP : %s with p2mp id : %d ",
                                p2mp_lsp->p2mp_name, p2mp_lsp->p2mp_id);
    
    TRACE_FUNCTION_RETURN(p2mp_lsp);
}

struct pccd_p2mp_lsp_info *pccd_p2mp_add_branch_lsp(const rpd_extctrl_lsp_config_status_info_t *info, 
               struct pccd_rpd_lsp_info *branch_lsp)
{
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(info != NULL);
    INSIST_ERR(branch_lsp != NULL);

    p2mp_lsp = pccd_get_p2mp_lsp_by_name(info->p2mp_name);
    if (branch_lsp->p2mp_lsp != NULL) {
        if (branch_lsp->p2mp_lsp != p2mp_lsp){
            TRACE_RPD("P2MP LSP conflict: LSP(%s) with p2mp lsp name(%s) tried to add in diff p2mp lsp(%s)", 
                 branch_lsp->lsp_name, branch_lsp->p2mp_lsp->p2mp_name, info->p2mp_name);            
            TRACE_FUNCTION_RETURN(NULL);
        } else {
            TRACE_RPD("LSP(%s) already presnt in p2mp lsp name(%s) branch list", 
                branch_lsp->lsp_name, branch_lsp->p2mp_lsp->p2mp_name);  
            p2mp_lsp->p2mp_id = info->p2mp_id;
            p2mp_lsp->type = info->type;
            p2mp_lsp->control_status = info->control_status;
            TRACE_FUNCTION_RETURN(p2mp_lsp);
        }
    }

    if (NULL == p2mp_lsp) {
        p2mp_lsp = pccd_add_p2mp_lsp(info);
    }

    p2mp_lsp->p2mp_id = info->p2mp_id;
    p2mp_lsp->type = info->type;
    p2mp_lsp->control_status = info->control_status;

    SLIST_INSERT_HEAD(&p2mp_lsp->p2mp_branch_lsps, branch_lsp, lv_p2mp_lsps);
    p2mp_lsp->branch_lsp_count++;
    branch_lsp->p2mp_lsp = p2mp_lsp;        
    TRACE_RPD("P2MP LSP(%s): branch lsp(%s) added, total branch LSPs(%d)", 
                                p2mp_lsp->p2mp_name, branch_lsp->lsp_name, p2mp_lsp->branch_lsp_count);

    TRACE_FUNCTION_RETURN(p2mp_lsp);
}


void pccd_p2mp_remove_branch_lsp(struct pccd_rpd_lsp_info *branch_lsp, bool del_lsp_vec)
{
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    u_int32_t plsp_id = 0;

    TRACE_FUNCTION_ENTRY();

    INSIST_ERR(branch_lsp != NULL);

    if (NULL == branch_lsp->p2mp_lsp){
        TRACE_FUNCTION_EXIT();
        return;
    }

    p2mp_lsp = branch_lsp->p2mp_lsp;
    plsp_id = p2mp_lsp->plsp_id ? p2mp_lsp->plsp_id : branch_lsp->id;
    
    SLIST_REMOVE(&p2mp_lsp->p2mp_branch_lsps, branch_lsp, 
		pccd_rpd_lsp_info, lv_p2mp_lsps);
    p2mp_lsp->branch_lsp_count--;
    branch_lsp->p2mp_lsp = NULL;
    TRACE_RPD("P2MP LSP(%s): branch lsp(%s) removed, remaining branch LSPs(%d)", 
                                p2mp_lsp->p2mp_name, branch_lsp->lsp_name, 
                                p2mp_lsp->branch_lsp_count);

    if (0 == p2mp_lsp->branch_lsp_count) {
        if ((del_lsp_vec) && (plsp_id)) {
            struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(plsp_id);
            if (lsp_vec) {
                pccd_core_delete_lsp(lsp_vec);
            }
        }
        (void)pccd_remove_p2mp_lsp(p2mp_lsp->p2mp_name);
        p2mp_lsp = NULL;
    }

    TRACE_FUNCTION_EXIT();
}

bool
pccd_rpd_cleanup ()
{
    pccd_rpd_session_close(pccd_rpd_ev_ctx, pccd_rpd_ses_hndl);
    pccd_rpd_transition_to_closed();
    memset(&pccd_rpd_ev_ctx, 0, sizeof(evContext));
    return true;
}

void
pccd_rpd_handle_flowspec_report (rpd_extr_flow_spec_info_t *rpd_fs_info)
{
    struct lsp_vector *lsp_vec;
    struct pccd_p2mp_lsp_info *p2mp_lsp;
    struct pccd_flowspec_info_s *fs_info;
    const struct pccd_rpd_lsp_info *p2mp_br;

    p2mp_lsp = pccd_get_p2mp_lsp_by_name(rpd_fs_info->lsp_name);
    if (!p2mp_lsp) {
        TRACE_RPD("P2MP LSP %s, not found", rpd_fs_info->lsp_name);
        return;
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(p2mp_lsp->plsp_id);
    if (!lsp_vec) {
        /**
         * If the LSP vector doesn't exist, check that it might be
         * restart case. If that is, we need to store this
         * FS info into tmp list
         */
        if (!pccd_rpd_get_all_flowspec_info) {
            return;
        }

        fs_info = (struct pccd_flowspec_info_s *)xmalloc(sizeof(*fs_info));

        fs_info->remove = false;

        fs_info->fs_id = rpd_fs_info->fs_id;

        fs_info->flow_type = PCCD_FLOW_TYPE_MULTICAST;
        fs_info->afi = FS_AFI_IPV4;
        fs_info->mcast_info = (pccd_fs_mcast_info_t *)xmalloc(sizeof(pccd_fs_mcast_info_t));

        fs_info->mcast_info->source_prefix = rpd_fs_info->src_prefix.ip_addr.ipv4;
        fs_info->mcast_info->src_len = rpd_fs_info->src_prefix.ip_mask;

        fs_info->mcast_info->multi_group_prefix = rpd_fs_info->mc_grp_prefix.ip_addr.ipv4;
        fs_info->mcast_info->mgp_len = rpd_fs_info->mc_grp_prefix.ip_mask;

        fs_info->mcast_info->rd_upper = rpd_fs_info->rd.rti_rd_upper;
        fs_info->mcast_info->rd_lower = rpd_fs_info->rd.rti_rd_lower;

        fs_info->mcast_info->ptnl_flags = rpd_fs_info->ptnl_flags;

        fs_info->mcast_info->ptnl_fan_out_threshold = rpd_fs_info->threshold.ptnl_fan_out_threshold;
        fs_info->mcast_info->ptnl_seg_threshold_rate = rpd_fs_info->threshold.ptnl_seg_threshold_rate;
        
        fs_info->mcast_info->error_code = EXTR_FLOW_SPEC_ERR_NO;

        SLIST_INSERT_HEAD(&p2mp_lsp->p2mp_tmp_fs_list, fs_info, fs_tmp);
    } else {
        bool is_configured = FALSE;

        fs_info = pccd_core_get_pce_fs_by_id(lsp_vec->lv_pce, rpd_fs_info->fs_id);
        if (!fs_info) {
            return;
        }

        if (!fs_info->mcast_info) {
            TRACE_RPD("Error, Multicast info not found for fs-id: %u",
                            fs_info->fs_id);
            return;
        }

        if (fs_info->remove) {
            /* it should not reach here */
            TRACE_RPD("FS-ID %u, remove is set. Received error: %s", fs_info->fs_id,
                      rpd_extr_flowspec_error_get_string(rpd_fs_info->error_code));
            pccd_core_delete_flowspec_info(lsp_vec, fs_info->fs_id, true);
            return;
        } 
        
        is_configured = fs_info->mcast_info->is_configured;
        
        if ((rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_OP_REPORT_CFG_DEL) ||
          (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_OP_UNBIND_MAPPING)){
            fs_info->mcast_info->is_configured = false;
            fs_info->mcast_info->error_code = rpd_fs_info->error_code;
        } else {
            fs_info->mcast_info->error_code = rpd_fs_info->error_code;
            if (fs_info->mcast_info->error_code == 0) {
                fs_info->mcast_info->is_configured = true;
            } else {
                fs_info->mcast_info->is_configured = false;
            }
        }

        /* NSR Begin */
        pccd_repl_handle_update_fs(fs_info, lsp_vec->lv_pce->pc_pce.pce_id);
        /* NSR End */
        
        /* If get all FS in enabled, ignore sending report */
        if (pccd_rpd_get_all_flowspec_info) {
            return;
        }

        /* For now sending report only for first branch of P2MP LSP
           as we do not bundle p2mp sub-lsp report in 1 mesage for now */
        p2mp_br = SLIST_FIRST(&p2mp_lsp->p2mp_branch_lsps);
        if (fs_info->mcast_info->is_configured != is_configured) {
            pccd_rpd_lsp_report(p2mp_br, false, false, true);
        }
    }
}

bool
pccd_rpd_send_flowspec_update (struct pccd_flowspec_info_s *fs_info)
{
    int res;
    rpd_extr_flow_spec_info_t *rpd_fs_info;
    struct pccd_p2mp_lsp_info *p2mp_lsp;

    if (!pccd_rpd_is_up()) {
        return false;
    }

    if (!fs_info->mcast_info) {
        TRACE_RPD("Error, Multicast info not found for fs-id: %u",
                        fs_info->fs_id);
        return false;
    }

    p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(fs_info->fs_plsp_id);
    rpd_fs_info = (rpd_extr_flow_spec_info_t *)xmalloc(sizeof(*rpd_fs_info));
    memset(rpd_fs_info, 0, sizeof(*rpd_fs_info));    

    rpd_fs_info->fs_id = fs_info->fs_id;

    snprintf(rpd_fs_info->lsp_name, sizeof(rpd_fs_info->lsp_name), "%s", p2mp_lsp->p2mp_name);

    rpd_fs_info->src_prefix.ip_addr.ipv4 = fs_info->mcast_info->source_prefix;
    rpd_fs_info->src_prefix.ip_mask = fs_info->mcast_info->src_len;

    rpd_fs_info->mc_grp_prefix.ip_addr.ipv4 = fs_info->mcast_info->multi_group_prefix;
    rpd_fs_info->mc_grp_prefix.ip_mask = fs_info->mcast_info->mgp_len;

    rpd_fs_info->rd.rti_rd_upper = fs_info->mcast_info->rd_upper;
    rpd_fs_info->rd.rti_rd_lower = fs_info->mcast_info->rd_lower;

    rpd_fs_info->ptnl_flags = fs_info->mcast_info->ptnl_flags;
    rpd_fs_info->addr_family = MCAST_AF_IPV4; /* IPv4 */

    if (fs_info->remove) {
        rpd_fs_info->ptnl_flags = (rpd_fs_info->ptnl_flags | RPD_EXTR_FLOW_SPEC_OP_UNBIND_MAPPING);
    }

    TRACE_RPD("sending update request to RPD(flow spec) for lsp: '%s'", rpd_fs_info->lsp_name);

    res = pccd_rpd_ipc_extr_flowspec_send_update(pccd_rpd_ses_hndl, 0, PCCD_RPD_CLIENT_ID,
                                         rpd_fs_info);
    if (res) {
        LOGGING_ERR("pccd_rpd_send_flowspec_update failed: %d '%s'", errno, strerror(errno));
        free(rpd_fs_info);
        return false;
    }

    free(rpd_fs_info);
    return true;
}


/**
 * Search FS based on parameter received from RPD
 * if FS not found, return NULL
 */
void
pccd_rpd_find_fs_req_msg(rpd_extr_flow_spec_info_t *rpd_fs_info)
{    
    if (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_OP_REQ_CFG_UPDATE) {
        TRACE_RPD("Request to update instance(%u %u) recieved",
            rpd_fs_info->rd.rti_rd_upper, rpd_fs_info->rd.rti_rd_lower);
        pccd_core_flowspec_foreach_pce_do(rpd_fs_info, pccd_core_send_update_all_fs_by_rd);
    } else if (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_OP_REPORT_CFG_DEL) {
        TRACE_RPD("Received flow delete msg from RPD for instance(%u %u)",
            rpd_fs_info->rd.rti_rd_upper, rpd_fs_info->rd.rti_rd_lower);
        pccd_rpd_handle_flowspec_report(rpd_fs_info);
    }
}


/**
 * pccd_rpd_add_prefix
 *
 * Add corresponding lsp prefix node in prefix tree root using passed prefix info
 *
 * @param[out]   root         ptr to prefix tree root
 * @param[in]    addr_family  prefix address family
 * @param[in]    prefix       ptr to prefix
 * @param[in]    length       prefix length
 */
lsp_prefix_info_t*
pccd_rpd_add_prefix(radix_root_t* root, uint8_t addr_family, ipprefix_t* prefix,
              uint8_t length)
{
    lsp_prefix_info_t* entry;

    entry = pccd_rpd_get_prefix(root, length, prefix);
    if (entry)
        return entry;

    entry = calloc(1, sizeof(lsp_prefix_info_t));
    INSIST_ERR(entry != NULL);

    PCCD_RADIX_NODE_INIT(&entry->prefix_node, length, length);

    entry->prefix = *prefix;
    entry->length = length;
    entry->refcnt = 1;
    entry->addr_family = addr_family;

    if (PCCD_RADIX_NODE_ADD(root, &entry->prefix_node)) {
        LOGGING_ERR("add_prefix: radix_add failed: '%s'", strerror(errno));
        free(entry);
        return NULL;
    }

    return entry;
}

/**
 * pccd_rpd_delete_prefix
 *
 * Delete passed lsp prefix node from prefix tree root
 *
 * @param[out]   root         ptr to prefix tree root
 * @param[in]    entry        ptr to lsp prefix node
 */
void
pccd_rpd_delete_prefix(radix_root_t* root, lsp_prefix_info_t* entry)
{
    PCCD_RADIX_NODE_DELETE(root, &entry->prefix_node);
    free(entry);
}


/**
 * pccd_rpd_get_prefix
 *
 * Get lsp prefix node from prefix tree root matching with passed prefix and length
 *
 * @param[in]   root         ptr to prefix tree root
 * @param[in]   length       prefix length
 * @param[in]   prefix       ptr to prefix
 *
 * @return  lsp prefix node, If get is successful
 *          NULL, if get fails
 */
lsp_prefix_info_t*
pccd_rpd_get_prefix(radix_root_t* root, uint8_t length, ipprefix_t* prefix)
{
    rnode_t* node;
    node = PCCD_RADIX_NODE_GET(root, length, (char*)prefix);
    if (node)
        return prefix_node2struct(node);
    return NULL;
}


/**
 * pccd_rpd_lsp_delete_all_prefix_info
 *
 * Delete all prefixes and also prefix root
 *
 * @param[in]  root    ptr to lsp prefix tree root
 */
void
pccd_rpd_lsp_delete_all_prefix_info(radix_root_t* root)
{
    rnode_t* node;
    lsp_prefix_info_t* entry = NULL;

    if (!root) return;

    while ((node = PCCD_RADIX_NODE_FIND_NEXT(root, NULL)) != NULL) {
        entry = prefix_node2struct(node);
        pccd_rpd_delete_prefix(root, entry);;
    }

    PCCD_RADIX_ROOT_DELETE(root);
}


/**
 * pccd_rpd_update_prefix_in_lcs_info
 *
 * Update prefix info in rpd interface structure lcs_info from lsp prefix tree
 *
 * @param[in]  root    ptr to prefix tree root
 * @param[out] info    ptr to rpd interface structure lcs_info
 */
void
pccd_rpd_update_prefix_in_lcs_info(rpd_extctrl_lsp_config_status_info_t* info,
         radix_root_t* prefix_root)
{
    char buffer[1024];
    char *buf = buffer;
    uint32_t length = 0;
    uint32_t prefix_idx = 0;
    rnode_t* node;
    lsp_prefix_info_t* entry = NULL;

    TRACE_FUNCTION_ENTRY();

    if (!prefix_root) return;

    /**
     * Allocating big buffer at first to accomodate maximum count of prefixes
     * supported at pccd as we don't know the count of prefixes in lsp, it will
     * be freed after sending update to rpd
     * MAX_PREFIX_SUPPORTED_PER_FLOWSPEC*MAX_FLOWSPEC_SUPPORTED_PER_LSP
     */
    info->install_prefix_info =
        xmalloc(RPD_PREFIX_BUFF_ESTIMATE_LEN(MAX_PREFIX_SUPPORTED_PER_FLOWSPEC*MAX_FLOWSPEC_SUPPORTED_PER_LSP));

    length+= snprintf(buf + length, sizeof(buffer) -length,
                        "Sending prefixes to rpd: ");

    for (node = PCCD_RADIX_NODE_FIND_NEXT(prefix_root, NULL); node;
         node = PCCD_RADIX_NODE_FIND_NEXT(prefix_root, node)) {
        entry = prefix_node2struct(node);

        length+= snprintf(buf + length, sizeof(buffer) -length,
                        "%s/%u ", inet_ntoa(entry->prefix.ipv4addr),
                        entry->length);

        info->install_prefix_info->pfx_buff[prefix_idx].mask =
                                    entry->length;
        info->install_prefix_info->pfx_buff[prefix_idx].addr =
                                    entry->prefix.ipv4addr;
        prefix_idx++;
    }

    if (prefix_idx) {
        /* Update the correct count of prefixes */
        info->install_prefix_info->pfx_cnt = prefix_idx;
    } else {
        xfree(info->install_prefix_info);
        info->install_prefix_info = NULL;
    }

    TRACE_RPD("%s", buf);

    TRACE_FUNCTION_EXIT();
}

/**
 * pccd_rpd_proc_prefix_in_pcreq_status
 *
 * Process received prefixes from rpd in pcreq_status message
 *
 * @param[out]  rpd_lsp    ptr to rpd lsp info
 * @param[out]  is_notify  ptr to is_notify, used to indicate if pc report
 *                         need to be sent or not
 * @param[in]   install_prefix_info    ptr to install prefix info received
 */
void
pccd_rpd_proc_prefix_in_pcreq_status(struct pccd_rpd_lsp_info *rpd_lsp,
              const prefix_info_t *install_prefix_info, boolean* is_notify)
{
    TRACE_FUNCTION_ENTRY();
    char buffer[150];
    char *buf = buffer;
    uint32_t buff_len = 0;
    lsp_prefix_info_t* entry = NULL;
    ipprefix_t prefix;
    rnode_t *node = NULL, *node_nxt = NULL;

    if (install_prefix_info) {
        for (uint32_t i = 0; i < install_prefix_info->pfx_cnt; i++) {
            buff_len = 0;
            memset(buf, 0, sizeof(buffer));

            memcpy(&prefix.ipv4addr, &install_prefix_info->pfx_buff[i].addr,
                        sizeof(struct in_addr));

            buff_len += snprintf(buf + buff_len, sizeof(buffer) - buff_len,
                            "Received prefix (%s/%u) from rpd ",
                            inet_ntoa(prefix.ipv4addr),
                            install_prefix_info->pfx_buff[i].mask);

            entry = pccd_rpd_get_prefix(rpd_lsp->prefix_root,
                          install_prefix_info->pfx_buff[i].mask, &prefix);
            if (entry) {
                buff_len += snprintf(buf + buff_len, sizeof(buffer) - buff_len,
                            "already exist in lsp");
                TRACE_RPD("%s", buf);
            } else {
                /**
                 * Prefixes received at this point and not found in lsp prefix tree
                 * are locally configured prefixes so need to add it now
                 */
                entry = pccd_rpd_add_prefix(rpd_lsp->prefix_root, AF_INET,
                                &prefix, install_prefix_info->pfx_buff[i].mask);
                if (!entry) {
                    buff_len += snprintf(buf + buff_len, sizeof(buffer) - buff_len,
                            "not found and failed to add in lsp");
                    TRACE_RPD("%s", buf);

                    /* Need to process rest of the received prefixes */
                    continue;
                }

                BIT_SET(entry->flags, PCCD_RPD_LSP_PREFIX_ADDED_NEW);

                /* Update flag to send out report to controller */
                *is_notify = TRUE;

                buff_len += snprintf(buf + buff_len, sizeof(buffer) - buff_len,
                            "not found, so added in lsp");

                TRACE_RPD("%s", buf);
            }

            /**
             * Mark all prefixes recevied in this status report from rpd as refreshed
             */
            BIT_SET(entry->flags, PCCD_RPD_LSP_PREFIX_REFRESHED);
        }
    }

    for (node = PCCD_RADIX_NODE_FIND_NEXT(rpd_lsp->prefix_root, NULL); node;
         node = node_nxt) {

        node_nxt = PCCD_RADIX_NODE_FIND_NEXT(rpd_lsp->prefix_root, node);

        entry = prefix_node2struct(node);

        /**
         * All prefixes which are not refreshed, are stale entries and need to
         * be deleted
         */
        if (!BIT_ISSET(entry->flags, PCCD_RPD_LSP_PREFIX_REFRESHED)) {
            TRACE_RPD("Prefix (%s/%u) deleted from lsp prefix tree",
                            inet_ntoa(entry->prefix.ipv4addr),
                            entry->length);

            // Delete prefix from lsp prefix tree
            pccd_rpd_delete_prefix(rpd_lsp->prefix_root, entry);
        } else {
            BIT_RESET(entry->flags, PCCD_RPD_LSP_PREFIX_REFRESHED);
        }
    }
    TRACE_FUNCTION_EXIT();
}


/**
 *@brief
 * Adds a colored SR LSP to sr_color_name_tree if cooked up name 
 * is not found in sr_color_name_tree.
 *
 *@param[in] rpd_extctrl_lsp_config_status_info_t
 *
 *@return
 * true:  If cooked up name is found in sr_color_name_tree. Caller 
 *        needs to send PCErr in this case
 * false: If no action is needed by the caller
 */
bool
pccd_rpd_handle_pce_init_sr_cpath (const rpd_extctrl_lsp_config_status_info_t *info)
{
    int i = 0;
    bool found_srpag_assoc = false;
    char name[RPD_LSP_NAME_SIZE+1];

    if (((info->lsp_type_info.setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) &&
        (info->lsp_type_info.setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))||
        (info->type != LSP_TYPE_EXTERNALLY_PROVISIONED)) {
        return false;
    }

    while (i < info->num_assoc_info) {
        if(info->assoc_info[i].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG) {
            found_srpag_assoc = true;
            break;
        }
        i++;
    }

    if (!found_srpag_assoc) {
        return false;
    }

    pccd_rpd_construct_sr_cpath_name(info->assoc_info[i].sr_srpag_t, name);

    if (pccd_rpd_sr_color_cpath_find (name)) {
        TRACE_RPD("send delete for received LSP");
        return true;
    }

    pccd_rpd_sr_color_cpath_add(name, info->name);

    return false;
}

char*
pccd_rpd_sr_color_cpath_find (char name[RPD_LSP_NAME_SIZE+1])
{
    char *value = NULL;
    value = name_tree_lookup(&sr_color_cpath_table, name);
    return value;
}

void
pccd_rpd_sr_color_cpath_table_init()
{
    if (name_tree_init(&sr_color_cpath_table) == FALSE) {
        LOGGING_ERR("Could not initialize sr color name tree");
    }
}

void
pccd_rpd_sr_color_cpath_add (char cpath_name[RPD_LSP_NAME_SIZE+1], const char lsp_name[RPD_LSP_NAME_SIZE +1])
{
    char *value = NULL;

    if (pccd_rpd_sr_color_cpath_find (cpath_name)) {
        TRACE_RPD("Returning, Entry is already present in SR color candidate path table with name: '%s'",
            cpath_name);
        return;
    }
    
    value = calloc(1, (RPD_LSP_NAME_SIZE +1)); 
    strncpy(value, lsp_name, (RPD_LSP_NAME_SIZE +1));

    if (!name_tree_add(&sr_color_cpath_table, cpath_name, value)) {
        LOGGING_ERR("name_tree_add failed");
        return;
    }

    TRACE_RPD("added key: '%s', value: '%s' to sr color candidate path table", cpath_name, value);
}

void
pccd_rpd_sr_color_cpath_delete (pccd_rpd_lsp *lsp)
{
    struct pccd_rpd_lsp_info *rpd_lsp;
    int i = 0;
    bool found_srpag_assoc = false;
    char name[RPD_LSP_NAME_SIZE+1];
    char *value = NULL;

    if(NULL == lsp) {
        return;
    }

    rpd_lsp = &lsp->lsp_info;

    if (((rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) &&
        (rpd_lsp->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) ||
        (rpd_lsp->type != LSP_TYPE_EXTERNALLY_PROVISIONED)) {
        return;
    }

    while (i < rpd_lsp->num_assoc_info) {
        if(rpd_lsp->assoc_info[i].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG) {
            found_srpag_assoc = true;
            break;
        }
        i++;
    }

    if (!found_srpag_assoc) {
        return;
    }

    pccd_rpd_construct_sr_cpath_name(rpd_lsp->assoc_info[i].sr_srpag_t ,name);
    value = name_tree_delete(&sr_color_cpath_table, name);
    INSIST_ERR(value != NULL);
    free(value);

    TRACE_RPD("deleted '%s' from sr color candidate path table", name);
}

void
pccd_rpd_construct_sr_cpath_name(const rpd_sr_srpag_t srpag, char name[RPD_LSP_NAME_SIZE+1])
{
    char endpoint_str[INET6_ADDRSTRLEN];
    char originator_str[INET6_ADDRSTRLEN];
    bzero(name, (RPD_LSP_NAME_SIZE+1));

    if (!srpag.is_srpag_endpoint_ipv6) {
        struct in_addr addr;
        addr.s_addr = (in_addr_t) srpag.srpag_endpoint_addr_u.v4;
        memcpy(endpoint_str, inet_ntoa(addr), 20);

        addr.s_addr = (in_addr_t) srpag.originator_addr_u.v4;
        memcpy(originator_str, inet_ntoa(addr), 20);
    } else {
        struct in6_addr v6_addr;
        memcpy(&v6_addr, srpag.srpag_endpoint_addr_u.v6, 16);
        inet_ntop(AF_INET6, &v6_addr, endpoint_str, sizeof(endpoint_str));

        memcpy(&v6_addr, srpag.originator_addr_u.v6, 16);
        inet_ntop(AF_INET6, &v6_addr, originator_str, sizeof(originator_str));
    }

    snprintf(name, (RPD_LSP_NAME_SIZE+1), "%d/%s/%d/%d/%s", srpag.color, endpoint_str, srpag.sr_proto_origin,
        srpag.originator_asn, originator_str);

    TRACE_RPD("cookedup candidate path is: '%s'", name);
}

/* NSR Begin */
void
pccd_rpd_extctrl_lcs_info_cleanup (rpd_extctrl_lsp_config_status_info_t *info)
{
    // Free ERO
    if (info->ero_info) {
        free(info->ero_info);
        info->ero_info = NULL;
        info->ero_len = 0;
    }
    // Free RRO
    if (info->rro_info) {
        free(info->rro_info);
        info->rro_info = NULL;
        info->rro_len = 0;
    }
    // Free SR-ERO
    if (info->srte_ero_info) {
        free(info->srte_ero_info);
        info->srte_ero_info = NULL;
    }
    // Free SR-RRO
    if (info->srte_rro_info) {
        free(info->srte_rro_info);
        info->srte_rro_info = NULL;
    }
	// Free install prefix info
	if (info->install_prefix_info) {
		free(info->install_prefix_info);
		info->install_prefix_info = NULL;
	}
}

/**
 * returns true if synch with rpd is in progress
 */
bool
pccd_rpd_sync_in_progress (void)
{
    return pccd_rpd_in_get_all_lsps_info;
}
/* NSR End */
