/*
 * $Id: pccd_ui.c 1332395 2023-04-26 17:08:22Z gchandraseka $
 *
 * pccd_ui.c
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/queue.h>

#include <isc/eventlib.h>
#include <jnx/jtimers.h>
#include <jnx/xmlrpc.h>
#include <jnx/mgmt_sock_pub.h>
#include <jnx/jnx_types.h>
#include <jnx/ms_parse.h>
#include <jnx/ms_peer.h>
#include <jnx/ms_io.h>
#include <jnx/daemon_names.h>

#include <jnx/bits.h>
#include <jnx/patricia.h>
#include <jnx/thread.h>

#include <xmltags/pccd_odl.h>

#include <jnx/js_error.h>
#include <jnx/xmllib.h>
#include <jnx/libpcep_objects.h>
#include <jnx/mirror_data_node.h>
#include <jnx/mirror_data.h>

#include "pccd_queue_stubs.h"
#include "pccd_ui.h"
#include "pccd_log.h"
#include "pccd_trace.h"
#include "pccd_stats.h"
#include "pccd_core.h"
#include "pccd_core_flowspec.h"
#include "pccd_core_util.h"
#include "pccd_ret_code.h"
#include "pccd_util.h"
#include "pccd_rpd.h"
#include "pccd_ro.h"
#include "pccd_mirror.h"

#define DIVERSITY_TYPE_STR_MAX 64
#define ROUTE_INFO_STRING_MAX_SIZE 2048
#define MULTI_ROUTE_INFO_STRING_MAX_SIZE (65536 * 16)
#define PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE 2048

extern uint8_t maximum_srmpls_segment_list_depth;
extern bool propagate_lsp_max_segmentlist_depth;

extern boolean pccd_nsr_master(void);

static int
pccd_ui_show_pccd_lsp_extensive_display (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
                       char *unparsed);

static int
pccd_lsp_show_extensive_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce UNUSED, 
                                                    const struct pccd_rpd_lsp_info* lsp, uint32_t flag UNUSED);

///////////////////////////////////////////////////////////////////////////////
// ui helpers
/**
 * Fill output XML with general configuration data.
 */
static void
pccd_statistics_add_common (mgmt_sock_t *mgmt_sock, struct pce_cfg_core* pce,
                            struct pce_statistics *pce_statistics, 
			    bool detailed, bool ismain)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_COMMON);

    char dest_ip_str[INET6_ADDRSTRLEN] = {0};
    pccd_core_pce_get_dest_ip_str(pce, dest_ip_str);
    XML_ELT(mgmt_sock, ODCI_PCE_IP, "%s", dest_ip_str);

    char local_ip_str[INET6_ADDRSTRLEN] = {0};
    pccd_core_pce_get_local_ip_str(pce, local_ip_str);
    XML_ELT(mgmt_sock, ODCI_LOCAL_IP, "%s", local_ip_str);

    XML_ELT(mgmt_sock, ODCI_PCE_PRIORITY, "%d",
            pccd_core_pce_get_priority(pce)); //TBD: prio depending on pce type ???
    //XML_ELT(mgmt_sock, ODCI_PCE_CONNECTION, "%s", "DUMMY:connecion status"); // TODO: e.g. connecting/connected, disconnected)
    XML_ELT(mgmt_sock, ODCI_PCE_STATUS, "%s",
            pccd_core_get_pce_state_name(pce));
    XML_ELT(mgmt_sock, ODCI_PCE_SESSION_TYPE, "%s",
            pccd_core_get_pce_type_name(pce));
    XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONING, "%s",
            pccd_core_pce_lsp_provisioning(pce) ? "On" : "Off");
    //XML_ELT(mgmt_sock, ODCI_SPRING_CAPABILITY, "%s",
      //      pccd_core_pce_spring_capability(pce) ? "On" : "Off");
    if (detailed && pccd_core_pce_lsp_provisioning(pce)) {
        XML_ELT(mgmt_sock, ODCI_LSP_CLEANUP_TIMER, "%lu",
                pccd_core_get_pce_lsp_cleanup_timer_value(pce));
    }
    if (detailed) {
        XML_ELT(mgmt_sock, ODCI_PCUPDATE_EMPTY_ERO_ACTION, "%s",
                              pccd_core_get_pcupdate_empty_ero_action_str(pce));
    }
    XML_ELT(mgmt_sock, ODCI_P2MP_LSP_REPORTING, "%s",
            pccd_core_pce_p2mp_lsp_reporting(pce) ? "On" : "Off");
    XML_ELT(mgmt_sock, ODCI_P2MP_LSP_UPDATE, "%s",
            pccd_core_pce_p2mp_lsp_update(pce) ? "On" : "Off");
    XML_ELT(mgmt_sock, ODCI_P2MP_LSP_INIT, "%s",
            pccd_core_pce_p2mp_lsp_init(pce) ? "On" : "Off");

    XML_ELT(mgmt_sock, ODCI_SRV6_SESSION_CAP, "%s",
            pccd_core_pce_srv6_capability(pce) ? "Yes" : "No");

    if (ismain) {
        XML_ELT(mgmt_sock, ODCI_PCE_MASTERSHIP, "%s", "main");
    } else {
        XML_ELT(mgmt_sock, ODCI_PCE_MASTERSHIP, "%s", "backup");
    }

    XML_ELT(mgmt_sock, ODCI_PCE_TRAFFIC_STEERING, "%s",
            pccd_core_get_pce_flowspec_capability(pce) ? "On" : "Off");
    XML_ELT(mgmt_sock, ODCI_PCE_MULTIPATH, "%s",
            pce->pc_params.remote.proposition.multipath_capability ? "On" : "Off");
    XML_ELT(mgmt_sock, ODCI_PCC_MULTIPATH, "%s",
            pce->pc_params.local.proposition.multipath_capability ? "On" : "Off");

    //XML_ELT(mgmt_sock, ODCI_PCE_SESSION_STATE, "%s", "DUMMY:session-state"); // TODO: State of the connected session if applicable, as in handshake, status update, live
    XML_ELT(mgmt_sock, ODCI_PCC_TLS_ENABLED, "%s",
            pce->pc_params.local.tls_enable ? "Yes" : "No");
    XML_ELT(mgmt_sock, ODCI_PCE_TLS_ENABLED, "%s",
            pce->pc_params.remote.tls_enable ? "Yes" : "No");
    XML_ELT(mgmt_sock, ODCI_SESSION_TLS_ENABLED, "%s",
            pce->pc_params.pceps_session ? "Yes" : "No");
    XML_ELT(mgmt_sock, ODCI_PCE_DISJOINT_ASSOCIATION, "%s",
            pce->pc_params.remote.proposition.disjoint_assoc_capability ? "Yes" : "No");
    XML_ELT(mgmt_sock, ODCI_PCC_DISJOINT_ASSOCIATION, "%s",
            pce->pc_params.local.proposition.disjoint_assoc_capability ? "Yes" : "No");

    if (detailed) {
        struct pce_common_opts *pec_opts = NULL;
        time_t time_now = time(NULL);

        XML_ELT(mgmt_sock, ODCI_PCE_MAX_UNKNOWN_MSGS, "%d",
                pccd_core_pce_get_max_unknown_msgs(pce));
        XML_ELT(mgmt_sock, ODCI_KEEPALIVES_RECEIVED, "%lu",
                pce_statistics->pcep_statistics.keepalive_recv);
        XML_ELT(mgmt_sock, ODCI_KEEPALIVES_SENT, "%lu",
                pce_statistics->pcep_statistics.keepalive_sent);
        XML_ELT(mgmt_sock, ODCI_DEAD_TIMER, "%lu",
                pce_statistics->pcep_statistics.deadtimer);
        if (pce_statistics->primary_elapsed_current) {
            XML_ELT(mgmt_sock, ODCI_ACTIVE_STATE_CURRENT, "%d",
                    pce_statistics->primary_elapsed_current);
            XML_ELT(mgmt_sock, ODCI_ACTIVE_STATE_TOTAL, "%d",
                    pce_statistics->primary_elapsed_previous +
                    pce_statistics->primary_elapsed_current);
        } else {
            XML_ELT(mgmt_sock, ODCI_ACTIVE_STATE_TOTAL, "%d",
                    pce_statistics->primary_elapsed_previous);
        }
        XML_ELT(mgmt_sock, ODCI_UNKNOWN_RATIO, "%lu",
                pce_statistics->pcep_statistics.unknown_messages_rate);
        XML_ELT(mgmt_sock, ODCI_SESSION_FAILURES, "%lu",
                pce_statistics->session_failures);
        XML_ELT(mgmt_sock, ODCI_CORRUPTED_MESSAGES, "%lu",
                pce_statistics->pcep_statistics.corrupted_messages);
        pec_opts = pccd_core_pce_get_common_opts(pce);
        XML_ELT(mgmt_sock, ODCI_DELEGATION_TIMEOUT_SET, "%u",
                pec_opts->pco_delegation_cleanup_timeout);
        if (pec_opts->pco_delegation_cleanup_timeout > 0) {
        int dlgtn_tmt = (pec_opts->pco_delegation_cleanup_timeout -
                         (time_now - pce_statistics->pcep_connection_down));
            XML_ELT(mgmt_sock, ODCI_DELEGATION_TIMEOUT, "%u",
                    (pec_opts->pco_delegation_cleanup_timeout &&
                     dlgtn_tmt > 0) ? dlgtn_tmt : 0);
        } else {
            XML_ELT(mgmt_sock, ODCI_DELEGATION_TIMEOUT, "-");
        }
        XML_ELT(mgmt_sock, ODCI_DELEGATION_FAILURES, "%lu",
                pce_statistics->delegation_failures);
        if (pce_statistics->pcep_connection_active) {
            XML_ELT(mgmt_sock, ODCI_CONNECTION_ACTIVE, "%d",
                (time_now - pce_statistics->pcep_connection_active));
        } else {
            XML_ELT(mgmt_sock, ODCI_CONNECTION_DOWN, "%d",
                    pce_statistics->pcep_connection_down ? 
                    (time_now - pce_statistics->pcep_connection_down) : 0);
        }

    }
    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_COMMON);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with single time based counter data.
 */
static void
pccd_statistics_add_counter (mgmt_sock_t *mgmt_sock, const char* name,
                             struct pce_stat_timed_summary *data)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_COUNTER);
    XML_ELT(mgmt_sock, ODCI_COUNTER_NAME, "%s", name);
    XML_ELT(mgmt_sock, ODCI_COUNT_TOTAL, "%lu", data->total);
    XML_ELT(mgmt_sock, ODCI_COUNT_5MIN, "%lu", data->last5min);
    XML_ELT(mgmt_sock, ODCI_COUNT_HOUR, "%lu", data->lasthour);
    XML_CLOSE(mgmt_sock, ODCI_PCE_COUNTER);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with time based counter statistics.
 */
static void
pccd_statistics_add_counters (mgmt_sock_t *mgmt_sock,
                              struct pce_statistics *pce_statistics)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_COUNTERS);

    pccd_statistics_add_counter(mgmt_sock, "PCReqs", &pce_statistics->pc_reqs);
    pccd_statistics_add_counter(mgmt_sock, "PCReps", &pce_statistics->pc_reps);
    pccd_statistics_add_counter(mgmt_sock, "PCRpts", &pce_statistics->pc_rpts);
    pccd_statistics_add_counter(mgmt_sock, "PCUpdates",
                                &pce_statistics->pc_updates);
    pccd_statistics_add_counter(mgmt_sock, "PCCreates",
                                &pce_statistics->pc_creates);

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_COUNTERS);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with timers statistics.
 */
static void
pccd_statistics_add_timers (mgmt_sock_t *mgmt_sock, struct pce_cfg_core* pce)
{
    struct pcep_connect_parameters *params = NULL;
    pcep_conn_state_t state;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_TIMERS);

    params = pccd_core_pce_get_connect_parameters(pce);

    if (pce->pc_conn) {
        state = pcep_get_conn_state(pce->pc_conn);
    } else {
        state = PCEP_CONN_TCPPENDING;
    }

    /* Local */
    XML_OPEN(mgmt_sock, ODCI_PCE_TIMER);
    XML_ELT(mgmt_sock, ODCI_TIMER_NAME, "Local");

    if ((state == PCEP_CONN_TCPPENDING) ||
        (state >= PCEP_CONN_CLOSING)) {

        XML_ELT(mgmt_sock, ODCI_TIMER_KEEPALIVE, "0");
        XML_ELT(mgmt_sock, ODCI_TIMER_DEAD, "0");

    } else if (state == PCEP_CONN_OPENWAIT ||
               state == PCEP_CONN_OPENWAIT2 ||
               state == PCEP_CONN_KEEPWAIT) {

        XML_ELT(mgmt_sock, ODCI_TIMER_KEEPALIVE, "%d",
                pce->pc_params.local.proposal.keepalive);
        XML_ELT(mgmt_sock, ODCI_TIMER_DEAD, "%d",
                pce->pc_params.local.proposal.peer_deadtimer);

    } else if (state == PCEP_CONN_SESSIONUP) {

        XML_ELT(mgmt_sock, ODCI_TIMER_KEEPALIVE, "%d",
                params->local.active.keepalive);
        XML_ELT(mgmt_sock, ODCI_TIMER_DEAD, "%d",
                params->local.active.deadtimer);
    }

    /*
     * Only when PCC is configured with LSP provisioning
     * LSP cleanup timer config is valid.
     */
    if (params->local.proposition.lsp_provisioning &&
        state == PCEP_CONN_SESSIONUP) {
        XML_ELT(mgmt_sock, ODCI_TIMER_LSP_CLEANUP, "%u",
                pccd_core_get_pce_lsp_cleanup_timer_value(pce));
    } else {
        XML_ELT(mgmt_sock, ODCI_TIMER_LSP_CLEANUP, "-");
    }
    XML_CLOSE(mgmt_sock, ODCI_PCE_TIMER);
    
    /* Remote */
    XML_OPEN(mgmt_sock, ODCI_PCE_TIMER);
    XML_ELT(mgmt_sock, ODCI_TIMER_NAME, "Remote");

    if (state == PCEP_CONN_SESSIONUP) {
        XML_ELT(mgmt_sock, ODCI_TIMER_KEEPALIVE, "%d",
            params->remote.active.keepalive);
        XML_ELT(mgmt_sock, ODCI_TIMER_DEAD, "%d",
            params->remote.active.deadtimer);
    } else {
        XML_ELT(mgmt_sock, ODCI_TIMER_KEEPALIVE, "%d",
            pce->pc_params.remote.proposal.keepalive);
        XML_ELT(mgmt_sock, ODCI_TIMER_DEAD, "%d",
            pce->pc_params.remote.proposal.peer_deadtimer);
    }

    if ((params->local.proposition.lsp_provisioning) &&
        (params->remote.active.lsp_provisioning) &&
        state == PCEP_CONN_SESSIONUP) { 
        XML_ELT(mgmt_sock, ODCI_TIMER_LSP_CLEANUP, "%u", 0); /* PCE doesn't communicate its LSP cleanup timer.
                                                                For backward compatibility of CLI o/p ,
                                                                assigning remote LSP cleanup timer value to 0 */
    } else {
        XML_ELT(mgmt_sock, ODCI_TIMER_LSP_CLEANUP, "-");
    }
    XML_CLOSE(mgmt_sock, ODCI_PCE_TIMER);

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_TIMERS);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with last sent and recv error data.
 */
static void
pccd_statistics_add_last_error (mgmt_sock_t *mgmt_sock,
                            struct pce_statistics *pce_statistics)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_LAST_ERROR);

    if(pce_statistics->pc_last_err_recv.count) {
        XML_OPEN(mgmt_sock, ODCI_PCE_LAST_ERROR);
        XML_ELT(mgmt_sock, ODCI_PCE_LAST_ERROR_NAME, "%s", "Last-PCErr-recv");
        XML_OPEN(mgmt_sock, ODCI_PCE_LAST_ERROR_ENTRY);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_TYPE, "%d", pce_statistics->pc_last_err_recv.type);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_VALUE, "%d", pce_statistics->pc_last_err_recv.value);
        XML_CLOSE(mgmt_sock, ODCI_PCE_LAST_ERROR_ENTRY);
        XML_CLOSE(mgmt_sock, ODCI_PCE_LAST_ERROR);
    }

    if(pce_statistics->pc_last_err_sent.count) {
        XML_OPEN(mgmt_sock, ODCI_PCE_LAST_ERROR);
        XML_ELT(mgmt_sock, ODCI_PCE_LAST_ERROR_NAME, "%s", "Last-PCErr-sent");
        XML_OPEN(mgmt_sock, ODCI_PCE_LAST_ERROR_ENTRY);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_TYPE, "%d", pce_statistics->pc_last_err_sent.type);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_VALUE, "%d", pce_statistics->pc_last_err_sent.value);
        XML_CLOSE(mgmt_sock, ODCI_PCE_LAST_ERROR_ENTRY);
        XML_CLOSE(mgmt_sock, ODCI_PCE_LAST_ERROR);
    }

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_LAST_ERROR);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with single error type data.
 */
static void
pccd_statistics_add_error (mgmt_sock_t *mgmt_sock, const char* name,
                           struct pce_stat_key_summary *data)
{
    struct pce_stat_key_elem* err = NULL;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_ERROR);
    XML_ELT(mgmt_sock, ODCI_PCE_ERROR_NAME, "%s", name);

    err = data->list.first;
    for (; NULL != err; err = err->next) {
        XML_OPEN(mgmt_sock, ODCI_PCE_ERROR_ENTRY);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_TYPE, "%d", err->type);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_VALUE, "%d", err->value);
        XML_ELT(mgmt_sock, ODCI_PCE_ERROR_COUNT, "%lu", err->count);
        XML_CLOSE(mgmt_sock, ODCI_PCE_ERROR_ENTRY);
    }

    XML_CLOSE(mgmt_sock, ODCI_PCE_ERROR);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with error statistics data.
 */
static void 
pccd_statistics_add_errors (mgmt_sock_t *mgmt_sock,
                            struct pce_statistics *pce_statistics)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_ERRORS);

    pccd_statistics_add_error(mgmt_sock, "PCErr-recv",
                              &pce_statistics->pc_errs_recv);
    pccd_statistics_add_error(mgmt_sock, "PCErr-sent",
                              &pce_statistics->pc_errs_sent);
    pccd_statistics_add_error(mgmt_sock, "PCE-PCC-NTFS",
                              &pce_statistics->pce_pcc_ntfs);
    pccd_statistics_add_error(mgmt_sock, "PCC-PCE-NTFS",
                              &pce_statistics->pcc_pce_ntfs);

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_ERRORS);

    TRACE_FUNCTION_EXIT();
}

static void
pccd_statistics_add_pcupdate_empty_ero_action (mgmt_sock_t *mgmt_sock,
                            struct pce_statistics *pce_statistics)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_PCUPDATE_EMPTY_ERO_ACTION);

    XML_ELT(mgmt_sock, ODCI_STATS_SEND_ERR, "%d",
            pce_statistics->pcupdate_action_stats.ppeeas_send_err);
    XML_ELT(mgmt_sock, ODCI_STATS_TEAR_DOWN_PATH, "%d",
            pce_statistics->pcupdate_action_stats.ppeeas_tear_down_path);
    XML_ELT(mgmt_sock, ODCI_STATS_ROUTING_DECISION, "%d",
            pce_statistics->pcupdate_action_stats.ppeeas_routing_decision);
    XML_ELT(mgmt_sock, ODCI_STATS_ROUTING_DECISION_FAILED, "%d",
            pce_statistics->pcupdate_action_stats.ppeeas_routing_decision_failed);

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_PCUPDATE_EMPTY_ERO_ACTION);

    TRACE_FUNCTION_EXIT();
}

/**
 * Fill output XML with statistics data.
 */
static void
pccd_statistics_add_response (mgmt_sock_t *mgmt_sock, struct pce_cfg_core* pce,
                              bool detailed, bool ismain)
{
    struct pce_statistics *pce_statistics = NULL;
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCE_STATISTICS_RESPONSE);

    XML_ELT(mgmt_sock, ODCI_PCE_ID, "%s", pccd_core_pce_get_id(pce));

    pce_statistics = pccd_core_get_statistics(pce);
    pccd_statistics_add_common(mgmt_sock, pce, pce_statistics, detailed, ismain);
    pccd_statistics_add_counters(mgmt_sock, pce_statistics);
    pccd_statistics_add_timers(mgmt_sock, pce);
    pccd_statistics_add_errors(mgmt_sock, pce_statistics);
    pccd_statistics_add_last_error(mgmt_sock, pce_statistics);
    pccd_statistics_add_pcupdate_empty_ero_action(mgmt_sock, pce_statistics);

    XML_CLOSE(mgmt_sock, ODCI_PCE_STATISTICS_RESPONSE);

    TRACE_FUNCTION_EXIT();
}

#define PCCD_SEND_ERROR_RESPONSE( _sock, _fmt, _args...) \
        do { \
            XML_OPEN(_sock, ODCI_PCCD_ERROR_RESPONSE); \
            XML_ELT(_sock, ODCI_PCCD_ERROR_MESSAGE, _fmt, ## _args); \
            XML_CLOSE(_sock, ODCI_PCCD_ERROR_RESPONSE); \
        } while(0);
///////////////////////////////////////////////////////////////////////////////
// callbacks
/**
 * Callback handler per PCE for show statistics cmd.
 *
 * @return 0 if success
 */
static int
pccd_statistics_show_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce,
                         bool detailed)
{
    TRACE_FUNCTION_ENTRY();

    pccd_statistics_add_response((mgmt_sock_t *)mgmt_sock, pce, detailed,
                                 pccd_core_pce_ismain(pce));

    TRACE_FUNCTION_RETURN(0);
}

/**
 * Callback handler per PCE for clear statistics cmd.
 *
 * @return 0 if success
 */
static int
pccd_statistics_clear_cb (mgmt_sock_t *mgmt_sock UNUSED,
                          struct pce_cfg_core *pce, bool detailed UNUSED)
{
    TRACE_FUNCTION_ENTRY();

    TRACE_CORE("Clear statistics of PCE with name \'%s\'",
               pccd_core_pce_get_id(pce));
    pccd_core_clear_statistics(pce);

    TRACE_FUNCTION_RETURN(0);
}
///////////////////////////////////////////////////////////////////////////////
// ui handlers
/**
 * "show pccd statistics ..." cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_statistics (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED, char *unparsed)
{
    bool detailed = false;
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

    if (unparsed && strstr(unparsed, "detail")) {
        detailed = true;
    }

    if (unparsed && strstr(unparsed, "all")) {
        if (pccd_core_foreach_pce_do(mgmt_sock, pccd_statistics_show_cb,
                                     detailed)) {
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
            XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
            TRACE_FUNCTION_RETURN(-1);
        }
    } else {
        pce = pccd_core_get_main_pce();
        if (NULL == pce) {
            XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
            TRACE_FUNCTION_RETURN(0);
        }
        pccd_statistics_add_response(mgmt_sock, pce, detailed, true);
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * "show pccd active-pce" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_active_pce (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
                              char *unparsed UNUSED)
{
    bool detailed = false;
    struct pce_cfg_core *active_pce = NULL;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

    if (unparsed && strstr(unparsed, "detail")) {
        detailed = true;
    }

    active_pce = pccd_core_get_main_pce();
    if (NULL != active_pce) {
        pccd_statistics_add_response(mgmt_sock, active_pce, detailed, true);
    } else {
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "No active PCE is set.");
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

    TRACE_FUNCTION_RETURN(0);
}
/* show path-computation-client lsp-retry-pending  */
static int
pccd_lsp_retry_delegation_show_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce, 
                                                        const struct pccd_rpd_lsp_info* lsp, uint32_t flag UNUSED)
{
    struct lsp_vector *lsp_vec;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
    TRACE_FUNCTION_ENTRY();

    if (lsp == NULL) {
        TRACE_FUNCTION_RETURN(-1);
    }

    lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp->id);
    if (lsp_vec == NULL)
        TRACE_FUNCTION_RETURN(-1);

    if ( !lsp_vec->lv_retry_delegation)
        TRACE_FUNCTION_RETURN(0);

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
        lsp->lsp_name, lsp->path_name);

    XML_OPEN(mgmt_sock, ODCI_PCC_LSP_RETRY_PENDING_ENTRY);
    XML_ELT(mgmt_sock, ODCI_LSP_RETRY_PENDING_NAME, "%s", lsp_full_name);
    XML_ELT(mgmt_sock, ODCI_LSP_RETRY_PENDING_STATUS, "%s", pccd_rpd_get_lsp_state_str(lsp->state));
    XML_ELT(mgmt_sock, ODCI_LSP_RETRY_PENDING_ID, "%lu", lsp->id);
    XML_ELT(mgmt_sock, ODCI_LSP_RETRY_PENDING_TYPE, "%s", tag_extctrl_lsp_type_get_string(lsp->type));
    XML_ELT(mgmt_sock, ODCI_LSP_RETRY_PENDING_CONTROLLER, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
    XML_CLOSE(mgmt_sock, ODCI_PCC_LSP_RETRY_PENDING_ENTRY);

    TRACE_FUNCTION_RETURN(0);
}

/*
 * Get displayed string for LSP PATH flags
 *
 * @param[in] flags  LSP PATH flags
 *
 * @return Displayed string for LSP PATH flags
 */
static const char *
pccd_rpd_lsp_path_flags_get_string (u_int16_t config_flags, uint16_t oper_state)
{
    static char flags_str[160];
    u_int32_t len = 0;

#if 0
    if (!config_flags) {
        return "0";
    }
#endif

    if (!oper_state) {
        return "0";
    }

    flags_str[0] = '\0';

    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_PRIMARY)) {
        snprintf(flags_str, sizeof(flags_str), "Primary");
	len = strlen(flags_str);
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_SECONDARY)) {
        snprintf((flags_str + len), sizeof(flags_str), "Sec");
	len = strlen(flags_str);
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_SECONDARY_STANDBY)) {
        snprintf((flags_str + len), sizeof(flags_str), "Sec-SB");
	len = strlen(flags_str);
    }
    if (BIT_ISSET(config_flags, LSP_PATH_TYPE_BYPASS)) {
        snprintf((flags_str + len), (sizeof(flags_str) - len), "Bypass");
        len = strlen(flags_str);
    }

    switch (oper_state) {
      case LSP_STATE_UP:
	  snprintf((flags_str + len), sizeof(flags_str), "(Up)");
	  break;
      case LSP_STATE_CREATION_PENDING:
      case LSP_STATE_DOWN:
	  snprintf((flags_str + len), sizeof(flags_str), "(Dn)");
	  break;
      case LSP_STATE_ACTIVE:
	  snprintf((flags_str + len), sizeof(flags_str), "(Act)");
	  break;
    }
    return flags_str;
}

/* show path-computation-client lsp extensive callback */
static int
pccd_lsp_show_extensive_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce UNUSED, 
                                                    const struct pccd_rpd_lsp_info* lsp, uint32_t flag UNUSED)
{
#define BUFFER_SIZE (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1) + 5)

    char lsp_name [BUFFER_SIZE] = "\0";
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)] = "\0";

    TRACE_FUNCTION_ENTRY();

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name), 
        lsp->lsp_name, lsp->path_name);

    strncat (lsp_name, "name ", BUFFER_SIZE - 1);
    strncat (lsp_name, lsp_full_name, BUFFER_SIZE - (strlen(lsp_name)*sizeof(char)) - 1);

    pccd_ui_show_pccd_lsp_extensive_display (mgmt_sock, NULL, lsp_name);

#undef BUFFER_SIZE

    TRACE_FUNCTION_RETURN(0);
}

/* show path-computation-client lsp callback */
static int
pccd_lsp_show_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce, 
                                    const struct pccd_rpd_lsp_info* lsp, uint32_t flag)
{
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];

    TRACE_FUNCTION_ENTRY();

    if (lsp == NULL) {
        TRACE_FUNCTION_RETURN(-1);
    }

    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name), 
        lsp->lsp_name, lsp->path_name);

    switch(flag){
        case LSP_DISPLAY_FLAG_DEFULT:
            XML_OPEN(mgmt_sock, ODCI_PCC_LSP_ENTRY);
            XML_ELT(mgmt_sock, ODCI_LSP_NAME, "%s", lsp_full_name);
            XML_ELT(mgmt_sock, ODCI_TEMPLATE_NAME, "%s", lsp->template_name);

            XML_ELT(mgmt_sock, ODCI_LSP_STATUS, "%s", pccd_rpd_lsp_path_flags_get_string(lsp->path_flags, lsp->state));
            XML_ELT(mgmt_sock, ODCI_LSP_ID, "%lu", lsp->id);
            XML_ELT(mgmt_sock, ODCI_LSP_TYPE, "%s", tag_extctrl_lsp_type_get_string(lsp->type));
            XML_ELT(mgmt_sock, ODCI_LSP_CONTROLLER, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
            XML_ELT(mgmt_sock, ODCI_LSP_SETUP_TYPE, "%s", tag_extctrl_path_setup_type_get_string(lsp->setup_type));
            XML_CLOSE(mgmt_sock, ODCI_PCC_LSP_ENTRY);
            break;
        case LSP_DISPLAY_FLAG_P2MP:
            XML_OPEN(mgmt_sock, ODCI_PCC_P2MP_LSP_ENTRY);
            XML_ELT(mgmt_sock, ODCI_LSP_NAME_P2MP, "%s", lsp_full_name);
            XML_ELT(mgmt_sock, ODCI_TEMPLATE_NAME_P2MP, "%s", lsp->template_name);

            XML_ELT(mgmt_sock, ODCI_LSP_STATUS_P2MP, "%s", pccd_rpd_lsp_path_flags_get_string(lsp->path_flags, lsp->state));
            XML_ELT(mgmt_sock, ODCI_LSP_ID_P2MP, "%lu", lsp->id);
            XML_ELT(mgmt_sock, ODCI_LSP_TYPE_P2MP, "%s", tag_extctrl_lsp_type_get_string(lsp->type));
            XML_ELT(mgmt_sock, ODCI_LSP_CONTROLLER_P2MP, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
            XML_ELT(mgmt_sock, ODCI_LSP_SETUP_TYPE_P2MP, "%s", tag_extctrl_path_setup_type_get_string(lsp->setup_type));
            XML_CLOSE(mgmt_sock, ODCI_PCC_P2MP_LSP_ENTRY);
            break;
    }
    TRACE_FUNCTION_RETURN(0);
}
static int
pccd_ui_show_pccd_lsp_retry_pending (mgmt_sock_t *mgmt_sock,
                                     parse_status_t *status UNUSED,
                                     char *unparsed UNUSED)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_RETRY_PENDING);

    if( pccd_core_foreach_lsp_do(mgmt_sock, pccd_lsp_retry_delegation_show_cb, 0)) {
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
                                    TRACE_FUNCTION_EXIT();
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_RETRY_PENDING);

    TRACE_FUNCTION_RETURN(0);
}

static void
pccd_ui_display_flowspec_route_distinguisher (mgmt_sock_t *mgmt_sock,
                                              uint32_t upper, uint32_t lower)
{
    uint16_t rd_type;
    struct in_addr ina;

    rd_type = upper >> 16;
    switch (rd_type) {
        /*
         * AS2 byte number followed by 4 byte admin number format.
         */
        case INETVPN_RD_AS_REL_FORMAT:
            XML_ELT(mgmt_sock, ODCI_ROUTE_DISTINGUISHER, "%u:%u",
                    (upper & 0x0000ffff), lower);
            break;
        /*
         * IPv4 address followed by a 2 byte admin number format.
         */
        case INETVPN_RD_IPADDR_REL_FORMAT:
            ina.s_addr = ((upper << 16) | (lower >> 16));
            XML_ELT(mgmt_sock, ODCI_ROUTE_DISTINGUISHER, "%s:%u",
                    inet_ntoa(ina), (lower & 0x0000ffff));
            break;
        /*
         * AS4 byte number followed by 2 byte admin number format.
         */
        case INETVPN_RD_AS4_REL_FORMAT:
            XML_ELT(mgmt_sock, ODCI_ROUTE_DISTINGUISHER, "%uL:%u",
                    ((upper << 16) | (lower >> 16)), (lower & 0x0000ffff));
            break;
        /* Should not come here*/
        default:
            break;
    }
}

static void
show_pccd_flowspec_info (mgmt_sock_t *mgmt_sock, struct pccd_flowspec_info_s *fs_info,
                         bool show_lsp)
{
    struct in_addr addr;
    struct pccd_p2mp_lsp_info *p2mp_lsp;

    XML_OPEN(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_ENTRY);

    XML_ELT(mgmt_sock, ODCI_FS_ID, "%u", fs_info->fs_id);
    XML_ELT(mgmt_sock, ODCI_SPEAKER_ID, "%s", fs_info->speaker_id);
    XML_ELT(mgmt_sock, ODCI_AFI, "%s", (fs_info->afi==1) ? "IPv4" : "IPv6");

    if (fs_info->mcast_info) {
        XML_ELT(mgmt_sock, ODCI_FLOW_TYPE, "Multicast");

        pccd_ui_display_flowspec_route_distinguisher(mgmt_sock,
                            fs_info->mcast_info->rd_upper,
                            fs_info->mcast_info->rd_lower);

        if (show_lsp) {
            p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(fs_info->fs_plsp_id);
            XML_ELT(mgmt_sock, ODCI_LSP_P2MP, "%s", p2mp_lsp->p2mp_name);
        }

        if (fs_info->mcast_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_SRC_GRP) {
            addr.s_addr = fs_info->mcast_info->source_prefix;
            XML_ELT(mgmt_sock, ODCI_SOURCE_PREFIX, "%s/%u", inet_ntoa(addr), fs_info->mcast_info->src_len);

            addr.s_addr = fs_info->mcast_info->multi_group_prefix;
            XML_ELT(mgmt_sock, ODCI_MULTI_GROUP_PREFIX, "%s/%u", inet_ntoa(addr), fs_info->mcast_info->mgp_len);
        } else if (fs_info->mcast_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_WCSRC_GRP) {
            XML_ELT(mgmt_sock, ODCI_SOURCE_PREFIX, "Wildcard");

            addr.s_addr = fs_info->mcast_info->multi_group_prefix;
            XML_ELT(mgmt_sock, ODCI_MULTI_GROUP_PREFIX, "%s/%u", inet_ntoa(addr), fs_info->mcast_info->mgp_len);
        } else if (fs_info->mcast_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_WCSRC_WCGRP) {
            XML_ELT(mgmt_sock, ODCI_SOURCE_PREFIX, "Wildcard");
            XML_ELT(mgmt_sock, ODCI_MULTI_GROUP_PREFIX, "Wildcard");
        }

        XML_ELT(mgmt_sock, ODCI_FS_STATE, "%s (%s)",
                fs_info->mcast_info->is_configured ? "Active" : "Inactive",
                rpd_extr_flowspec_error_get_string((u_int16_t)fs_info->mcast_info->error_code));
    } else if (fs_info->dest_pfx_info) {
        struct pccd_fs_dest_prefix_s *dest_pfx = NULL, *tmp_dest_pfx = NULL;
        char buffer[PCEP_TRACE_BUFFER_SIZE];
        char *buf = buffer;
        uint32_t length = 0;

        XML_ELT(mgmt_sock, ODCI_FLOW_TYPE, "Dest-Prefix");

        if (show_lsp) {
            char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
            const struct pccd_rpd_lsp_info *rpd_lsp =
                            pccd_rpd_get_lsp_by_id(fs_info->fs_plsp_id);

            pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                                        rpd_lsp->lsp_name, rpd_lsp->path_name);
            XML_ELT(mgmt_sock, ODCI_LSP, "%s", lsp_full_name);
        }

        SLIST_FOREACH_SAFE(dest_pfx, &fs_info->dest_pfx_info->dest_pfx_head,
                            dest_pfx_next, tmp_dest_pfx) {
            char ip_addr[INET_ADDRSTRLEN] = "";
            inet_ntop(AF_INET, &dest_pfx->prefix.ipv4addr, ip_addr,
                            INET_ADDRSTRLEN);
            length+= snprintf(buf + length, sizeof(buffer) -length,
                                        "%s/%u ",
                                        ip_addr, dest_pfx->mask);
        }
        XML_ELT(mgmt_sock, ODCI_DEST_PREFIX, "%s", buf);
    }

    XML_CLOSE(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_ENTRY);
}

static const char*
pccd_ui_get_assoc_type_string(uint8_t assoc_type)
{
    switch(assoc_type) {
        case LSP_ASSOCIATION_TYPE_PROTECTION:
            return "PROTECTION";
        case LSP_ASSOCIATION_TYPE_TE_PLUSPLUS:
            return "TE++";
        case LSP_ASSOCIATION_TYPE_SRPAG:
            return "SRPAG";
        case LSP_ASSOCIATION_TYPE_DISJOINT:
            return "DISJOINT";
        default:
            return "INVALID";
    }
}

static const char*
pccd_ui_get_sr_proto_origin_string(uint8_t  sr_proto_origin)
{
    switch(sr_proto_origin) {
        case RPD_SR_PROTO_ORIGIN_PCEP:
            return "PCEP";
        case RPD_SR_PROTO_ORIGIN_BGP:
            return "BGP";
        case RPD_SR_PROTO_ORIGIN_CONFIGURATION:
            return "CONFIGURATION";
        default:
            return "INVALID";
    }
}

static const char*
pccd_ui_get_binding_type_string(uint8_t binding_type)
{
    if (0 == binding_type) {
        return "MPLS_LABEL_20_BIT";
    } else  if (1 == binding_type) {
        return "MPLS_LABEL_32_BIT";
    } else {
        return "INVALID";
    }
}

static void
pccd_ui_get_metric_type_string(char *metric_str, uint8_t buffer_size, uint8_t metric_type)
{
    char temp[20] = {0};
    switch(metric_type) {
        case IGP_METRIC:
            snprintf( temp, sizeof(temp), "IGP");
            break;
        case TE_METRIC:
            snprintf( temp, sizeof(temp), "TE");
            break;
        case HOPCOUNT_METRIC:
            snprintf( temp, sizeof(temp), "HOP_COUNT");
            break;
        case PATH_DELAY_METRIC:
            snprintf( temp, sizeof(temp), "PATH_DELAY");
            break;
        case SEGMENT_ID_DEPTH:
            snprintf( temp, sizeof(temp), "SID_DEPTH");
            break;
        default:
            snprintf( temp, sizeof(temp), "METRIC_TYPE_%u", metric_type);
    }

    strlcat(metric_str, temp, (buffer_size - strlen(metric_str) - 1));
    return;
}

/**
 * "show pccd lsp extensive" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_lsp_extensive_display (mgmt_sock_t    *mgmt_sock,
                                         parse_status_t *status UNUSED,
                                         char           *unparsed)
{
    char                            *print_one_lsp = NULL;
    char                             route_info[ROUTE_INFO_STRING_MAX_SIZE];
    char                             multi_route_info[MULTI_ROUTE_INFO_STRING_MAX_SIZE];
    char                             attrbs_info[PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE];
    char                             buff[16], buff_bw[26];
    struct pce_cfg_core             *pce = NULL;
    const struct pccd_rpd_lsp_info*  lsp;
    struct in_addr                   addr;
    struct pccd_flowspec_info_s     *fs_info = NULL, *fs_info_tmp = NULL;
    struct lsp_vector               *lsp_vec = NULL;
    uint32_t                         counter = 0, dag_i = 0;
    rpd_sr_ero_list_t               *srte_ero_info = NULL, *srte_rro_info = NULL, *pce_srte_ero_list = NULL;
    char                             div_type[DIVERSITY_TYPE_STR_MAX];

    TRACE_FUNCTION_ENTRY();
    if (unparsed && strstr(unparsed, "name")) {
        print_one_lsp = unparsed + strlen("name ");
        /*
         * even when name is not the cli option, the ms_parse_substring()seem
         * to pass on the the unparsed varaibale with "name". anyway let us be
         * safe and handle this case. this is the reason why anywhere you check
         * for validity of print_one_lsp, you have to check if the strlen is
         * also valid for a lsp name.
         */
    }

    if (print_one_lsp && strlen(print_one_lsp)) {
        char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];
        lsp = pccd_rpd_get_lsp_by_name(print_one_lsp);
        if (lsp) {
            /* Intended BW */
            uint64_t intended_bw = 0;
            char mapped_fs_str[256] = {0};

            pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name), 
                lsp->lsp_name, lsp->path_name);
            XML_OPEN(mgmt_sock, ODCI_PCC_LSP_EXT_ENTRY);
            XML_ELT(mgmt_sock, ODCI_LSP_NAME, "%s", lsp_full_name);
            XML_ELT(mgmt_sock, ODCI_LSP_PATH_NAME, "%s", strlen(lsp->path_name) ? lsp->path_name : "-");
            if (!lsp->is_lsp_src_dst_addr_type_ipv6) {
                addr.s_addr = lsp->srcaddr.v4;
                XML_ELT(mgmt_sock, ODCI_LSP_SRC, "%s", inet_ntoa(addr));
            } else {
                char src[INET6_ADDRSTRLEN];
                struct in6_addr srcv6_addr;
                memset(src, 0, INET6_ADDRSTRLEN);
                memcpy(&srcv6_addr, lsp->srcaddr.v6, 16);
                inet_ntop(AF_INET6, &srcv6_addr, src, sizeof(src));
                XML_ELT(mgmt_sock, ODCI_LSP_SRC, "%s", src);
            }
            if (!lsp->is_lsp_src_dst_addr_type_ipv6) {
                addr.s_addr = lsp->dstaddr.v4;
                XML_ELT(mgmt_sock, ODCI_LSP_DST, "%s", inet_ntoa(addr));
            } else {
                char dst[INET6_ADDRSTRLEN];
                struct in6_addr dstv6_addr;
                memset(dst, 0, INET6_ADDRSTRLEN);
                memcpy(&dstv6_addr, lsp->dstaddr.v6, 16);
                inet_ntop(AF_INET6, &dstv6_addr, dst, sizeof(dst));
                XML_ELT(mgmt_sock, ODCI_LSP_DST, "%s", dst);
            }
            XML_ELT(mgmt_sock, ODCI_LSP_SETUP_TYPE, "%s", 
                        tag_extctrl_path_setup_type_get_string(lsp->setup_type));
            XML_ELT(mgmt_sock, ODCI_LSP_STATE, "%s", (LSP_STATE_DOWN != lsp->state) ? "Up" : "Down");
            XML_ELT(mgmt_sock, ODCI_LSP_ACTIVE_PATH, "%s",
                 (LSP_STATE_ACTIVE == lsp->state) ? "Yes" : "No");
            XML_ELT(mgmt_sock, ODCI_LSP_LINK, "%s", lsp->link_protection ? "desired" : "none");
            XML_ELT(mgmt_sock, ODCI_LSP_TYPE, "%s", tag_extctrl_lsp_type_get_string(lsp->type));
            XML_ELT(mgmt_sock, ODCI_LSP_P2MP, "%s", lsp->p2mp_lsp ? lsp->p2mp_lsp->p2mp_name : "NULL");
            XML_ELT(mgmt_sock, ODCI_LSP_CSPF, "%s", lsp->prli_local_cspf ? "local_cspf" :
                ((lsp->control_status == LSP_LOCALLY_CONTROLLED) ? "local_cspf" : "external_cspf"));
            lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp->id);
            if (lsp_vec) {
                if (lsp_vec->lv_ack_delegated == true) {
                    pce = lsp_vec->lv_pce;
                }
                XML_ELT(mgmt_sock, ODCI_LSP_CTRLR, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
            }
            XML_ELT(mgmt_sock, ODCI_LSP_TEMPLATE, "%s", strlen(lsp->template_name) ? lsp->template_name : "NULL");
            XML_ELT(mgmt_sock, ODCI_LSP_PLSP_ID, "%lu", lsp->id);
            XML_ELT(mgmt_sock, ODCI_LSP_ID, "%d", lsp->lsp_id);

            if (lsp->binding_value) {
                XML_OPEN(mgmt_sock, ODCI_LSP_PATH_BINDING_ENTRY);
                XML_ELT(mgmt_sock, ODCI_BINDING_TYPE, "%s",
                        pccd_ui_get_binding_type_string(lsp->binding_type));
                XML_ELT(mgmt_sock, ODCI_BINDING_VALUE, "%u", lsp->binding_value);
                XML_CLOSE(mgmt_sock, ODCI_LSP_PATH_BINDING_ENTRY);
            }

            XML_ELT(mgmt_sock, ODCI_LSP_RSVP_ERR, "0x%d", lsp->error_spec_obj ? ((ErrspecObj *)lsp->error_spec_obj)->addr : 0);

            memset(buff_bw, '\0', 26);
            pccd_core_get_bandwidth_str(lsp->auto_bandwidth, buff_bw, sizeof(buff_bw));
            XML_ELT(mgmt_sock, ODCI_LSP_ABW, "%s", buff_bw);

	        if ((RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE == lsp->setup_type) ||
		        (RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE == lsp->setup_type)) {
                memset(route_info, '\0', sizeof(route_info));
                pccd_core_construct_rro_info(route_info, sizeof(route_info), lsp->rro_info);
                XML_ELT(mgmt_sock, ODCI_LSP_RRO, "%s", strlen(route_info) ? route_info : "NULL");
                memset(route_info, '\0', sizeof(route_info));
                pccd_core_construct_ero_info(route_info, sizeof(route_info), lsp->pce_proposed_ero_info);
                XML_ELT(mgmt_sock, ODCI_LSP_PCE_ERO, "%s", strlen(route_info) ? route_info : "NULL");
                memset(route_info, '\0', sizeof(route_info));
                pccd_core_construct_ero_info(route_info, sizeof(route_info), lsp->ero_info);
                XML_ELT(mgmt_sock, ODCI_LSP_RPD_ERO, "%s", strlen(route_info) ? route_info : "NULL");

                /* Configured ERO display is not supported as RPD doesn't send
                 * configured ERO separately. It sends only one ERO information.
                 * Plan is to add this support with the support of IRO 
                 */
                XML_ELT(mgmt_sock, ODCI_LSP_CONF_ERO, "Not Supported");
	        } else  if ((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp->setup_type) ||
	                    (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp->setup_type)) {
                multi_route_info[0] = '\0';
	            if (lsp->srte_total_rro_count) {
                    srte_rro_info = (rpd_sr_ero_list_t *) lsp->srte_rro_info;
                    counter = 0;
                    while (counter < lsp->srte_total_rro_count) {
                        if (!srte_rro_info) {
                            break;
                        }
                        route_info[0] = '\0';
	                    if (srte_rro_info->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
	                        pccd_core_construct_sr_ro_info(route_info, sizeof(route_info), srte_rro_info);
	                    } else {
	                        pccd_core_construct_srv6_ro_info(route_info, sizeof(route_info), srte_rro_info);
                        }
                        strncat(multi_route_info, route_info, ROUTE_INFO_STRING_MAX_SIZE);
                        if (multipath_enabled) {
                            snprintf(
                              attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE,
                              "[Type: %s, path_id: %u, Weight: %u, state: %s]\n",
                              (srte_rro_info->resel_path_flags & LSP_PATH_TYPE_PRIMARY)?"Primary": "Secondary",
                              srte_rro_info->rsel_path_id, srte_rro_info->rsel_weight,
                              tag_extctrl_lsp_state_get_string(srte_rro_info->rsel_op_state));
                            strncat(multi_route_info, attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE);
                        }
                        srte_rro_info = (rpd_sr_ero_list_t *)
                                            &(srte_rro_info->rsel_ero[srte_rro_info->rsel_n_eros]);
                        counter++;
                    }
                }
	            XML_ELT(mgmt_sock, ODCI_LSP_RRO, "%s", strlen(multi_route_info) ? multi_route_info : "NULL");

                multi_route_info[0] = '\0';
                if (lsp->pce_proposed_ero_info) {
                    pce_srte_ero_list = (rpd_sr_ero_list_t*) (lsp->pce_proposed_ero_info);
                    counter = 0;
                    while (counter < lsp->pce_proposed_ero_info_total) {
                        if (!pce_srte_ero_list) {
                            break;
                        }
                        route_info[0] = '\0';
                        if (pce_srte_ero_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
                            pccd_core_construct_sr_ro_info(route_info, sizeof(route_info), pce_srte_ero_list);
                        } else {
                            pccd_core_construct_srv6_ro_info(route_info, sizeof(route_info),
                                                             pce_srte_ero_list);
                        }
                        strncat(multi_route_info, route_info, ROUTE_INFO_STRING_MAX_SIZE);
                        if (multipath_enabled) {
                            /*
                             * Since, this is proposed ERO, the LSP state
                             * is displayed as DOWN
                             */
                            snprintf(
                              attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE,
                              "[Type: %s, path_id: %u, Weight: %u, state: %s]\n",
                              (pce_srte_ero_list->resel_path_flags & LSP_PATH_TYPE_PRIMARY) ? 
                                                                        "Primary": "Secondary",
                              pce_srte_ero_list->rsel_path_id, pce_srte_ero_list->rsel_weight,
                              "Down");
                            strncat(multi_route_info, attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE);
                        }
                        pce_srte_ero_list = (rpd_sr_ero_list_t *)
                                                &(pce_srte_ero_list->rsel_ero[pce_srte_ero_list->rsel_n_eros]);
                        counter++;
                    }
                }
                XML_ELT(mgmt_sock, ODCI_LSP_PCE_ERO, "%s",
                        strlen(multi_route_info) ? multi_route_info : "NULL");

                multi_route_info[0] = '\0';
                if (lsp->srte_total_ero_count) {
                    srte_ero_info = (rpd_sr_ero_list_t *) lsp->srte_ero_info;
                    counter = 0;
                    while (counter < lsp->srte_total_ero_count) {
                        if (!srte_ero_info) {
                            break;
                        }
                        route_info[0] = '\0';
                        if (srte_ero_info->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
                            pccd_core_construct_sr_ro_info(route_info, sizeof(route_info), srte_ero_info);
                        } else {
                            pccd_core_construct_srv6_ro_info(route_info, sizeof(route_info), srte_ero_info);
                        }
                        strncat(multi_route_info, route_info, ROUTE_INFO_STRING_MAX_SIZE);
                        if (multipath_enabled) {
                            snprintf(
                                attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE,
                                "[Type: %s, path_id: %u, Weight: %u, state: %s]\n",
                                (srte_ero_info->resel_path_flags & LSP_PATH_TYPE_PRIMARY) ? 
                                    "Primary": "Secondary",
                                srte_ero_info->rsel_path_id, srte_ero_info->rsel_weight,
                                tag_extctrl_lsp_state_get_string(srte_ero_info->rsel_op_state));
                            strncat(multi_route_info, attrbs_info, PATH_ATTRIBUTES_INFO_STRING_MAX_SIZE);
                        }
                        srte_ero_info =(rpd_sr_ero_list_t *)
                                &(srte_ero_info->rsel_ero[srte_ero_info->rsel_n_eros]);
                        counter++;
                    }
                }
	            XML_ELT(mgmt_sock, ODCI_LSP_RPD_ERO, "%s",
                        strlen(multi_route_info) ? multi_route_info : "NULL");

                /* Configured ERO display is not supported as RPD doesn't send
                 * configured ERO separately. It sends only one ERO information.
                 * Plan is to add this support with the support of IRO
                 */
	            XML_ELT(mgmt_sock, ODCI_LSP_CONF_ERO, "Not Supported");
	        }

            if ((LSP_TYPE_EXTERNALLY_PROVISIONED == lsp->type) 
                || (LSP_TYPE_EXTERNALLY_CONTROLLED == lsp->type)) {
                intended_bw = ((lsp->intended_attrs.bw_valid) ? lsp->intended_attrs.bw : 0);
            } else {
                intended_bw = lsp->configured_bandwidth;
            }

            memset(buff_bw, '\0', 26);
            pccd_core_get_bandwidth_str(intended_bw, buff_bw, sizeof(buff_bw));
            XML_ELT(mgmt_sock, ODCI_LSP_INTENDED_BW, "%s", buff_bw);
            memset(buff_bw, '\0', 26);
            pccd_core_get_bandwidth_str(lsp->bandwidth, buff_bw, sizeof(buff_bw));
            XML_ELT(mgmt_sock, ODCI_LSP_ACTUAL_BW, "%s", buff_bw);

            struct lsp_metric_s *intended_metric_itr = NULL, *intended_metric_tmp;
            struct lsp_metric_s *actual_metric_itr = NULL, *actual_metric_tmp;

            struct metric_display {
                u_int8_t metric_type;
                u_int32_t bounded_metric_val;
                bool optimization_metric;
            };
            struct metric_display display_metric_list[512];
            int metric_itr = 0;
            //Copy intended metric list to an array
            SLIST_FOREACH_SAFE(intended_metric_itr, &lsp->intended_attrs.intended_metric_head,
                    metric_next, intended_metric_tmp) {
                display_metric_list[metric_itr].metric_type = intended_metric_itr->metric_info.metric_type;
                if (intended_metric_itr->metric_info.bound_flag) {
                    //Don't display LSP MSD if LSP MSD is greater than PCEP global MSD
                    if ((SEGMENT_ID_DEPTH == intended_metric_itr->metric_info.metric_type) &&
                            ((intended_metric_itr->metric_info.metric > maximum_srmpls_segment_list_depth) ||
                            (false == propagate_lsp_max_segmentlist_depth))) {
                        TRACE_UI("Skipped displaying MSD metric value:%u for lsp:%s",
                                intended_metric_itr->metric_info.metric,
                                lsp_full_name);
                        continue;
                    }
                    display_metric_list[metric_itr].bounded_metric_val = intended_metric_itr->metric_info.metric;
                } else {
                    display_metric_list[metric_itr].bounded_metric_val = 0;
                }
                if ((0 == intended_metric_itr->metric_info.bound_flag) &&
                        (0 == intended_metric_itr->metric_info.computed_flag)) {
                    display_metric_list[metric_itr].optimization_metric = true;
                } else {
                    display_metric_list[metric_itr].optimization_metric = false;
                }
                metric_itr++;
            }

            for(int i=0;i<metric_itr;i++){
               for(int j = i+1; j < metric_itr; j++){
                  if(display_metric_list[i].metric_type == display_metric_list[j].metric_type){
                      if (display_metric_list[j].optimization_metric) {
                          display_metric_list[i].optimization_metric = true;
                      }
                      if (display_metric_list[j].bounded_metric_val > display_metric_list[i].bounded_metric_val) {
                          display_metric_list[i].bounded_metric_val = display_metric_list[j].bounded_metric_val;
                      }
                     for(int k = j; k <metric_itr; k++){
                         display_metric_list[k].metric_type = display_metric_list[k+1].metric_type;
                         display_metric_list[k].bounded_metric_val = display_metric_list[k+1].bounded_metric_val;
                         display_metric_list[k].optimization_metric = display_metric_list[k+1].optimization_metric;
                     }
                     j--;
                     metric_itr--;
                  }
               }
            }

            for (int i=0; i < metric_itr; i++) {
                char metric_type_buffer[21] = {0};
                pccd_ui_get_metric_type_string(metric_type_buffer, sizeof(metric_type_buffer),
                                                display_metric_list[i].metric_type);

                XML_OPEN(mgmt_sock, ODCI_LSP_INTENDED_METRIC_ENTRY);
                XML_ELT(mgmt_sock, ODCI_METRIC_TYPE, "%s", metric_type_buffer);
                XML_ELT(mgmt_sock, ODCI_METRIC_BOUND, "%u", display_metric_list[i].bounded_metric_val);
                XML_ELT(mgmt_sock, ODCI_METRIC_OPTIMIZATION, "%s",
                        (display_metric_list[i].optimization_metric) ? "TRUE" : "FALSE");
                XML_CLOSE(mgmt_sock, ODCI_LSP_INTENDED_METRIC_ENTRY);
            }

            SLIST_FOREACH_SAFE(actual_metric_itr, &lsp->actual_metric_head,
                    metric_next, actual_metric_tmp) {
                char metric_type_buffer[21] = {0};
                pccd_ui_get_metric_type_string(metric_type_buffer, sizeof(metric_type_buffer),
                        actual_metric_itr->metric_info.metric_type);

                XML_OPEN(mgmt_sock, ODCI_LSP_ACTUAL_METRIC_ENTRY);
                XML_ELT(mgmt_sock, ODCI_METRIC_TYPE, "%s", metric_type_buffer);
                XML_ELT(mgmt_sock, ODCI_METRIC_COMPUTED_VALUE, "%u", actual_metric_itr->metric_info.metric);
                XML_CLOSE(mgmt_sock, ODCI_LSP_ACTUAL_METRIC_ENTRY);
            }

            XML_ELT(mgmt_sock, ODCI_LSP_ROUTE_METRIC, "%u", lsp->metric);

            if (lsp_vec && lsp_vec->lv_type == LSP_VECTOR_P2P) {
                pccd_core_get_lsp_mapped_fs_str(lsp_vec, mapped_fs_str, sizeof(mapped_fs_str));
            }
            XML_ELT(mgmt_sock, ODCI_LSP_MAPPED_FLOWSPEC, "%s",
                            strlen(mapped_fs_str) ? mapped_fs_str : "-");

            XML_OPEN(mgmt_sock, ODCI_LSP_ADMIN_GROUPS);
            XML_ELT(mgmt_sock, ODCI_LSP_EXCLUDE_ANY, "%d", lsp->prli_admin_grp_exclude_any);
            XML_ELT(mgmt_sock, ODCI_LSP_INCLUDE_ANY, "%d", lsp->prli_admin_grp_include_any);
            XML_ELT(mgmt_sock, ODCI_LSP_INCLUDE_ALL, "%d", lsp->prli_admin_grp_include_all);
            XML_CLOSE(mgmt_sock, ODCI_LSP_ADMIN_GROUPS);

            XML_OPEN(mgmt_sock, ODCI_LSP_PRIORITY);
            XML_ELT(mgmt_sock, ODCI_LSP_SETUP_PRIO, "%d", lsp->setup_prio);
            XML_ELT(mgmt_sock, ODCI_LSP_HOLD_PRIO, "%d", lsp->hold_prio);
            XML_CLOSE(mgmt_sock, ODCI_LSP_PRIORITY);

            if (BIT_TEST(lsp->path_flags, LSP_PATH_LOCAL_PROTECTION_DESIRED)) {           
                XML_ELT(mgmt_sock, ODCI_LSP_LOCAL_PROTECTION, "TRUE");
            } else {
                XML_ELT(mgmt_sock, ODCI_LSP_LOCAL_PROTECTION, "FALSE");
            }

            for (uint8_t assoc_itr = 0; assoc_itr < lsp->num_assoc_info; assoc_itr++) {
                if (strncmp(pccd_ui_get_assoc_type_string((uint8_t)lsp->assoc_info[assoc_itr].assoc_type),
                    "INVALID", 64) == 0) {
                    continue;
                }
                XML_OPEN(mgmt_sock, ODCI_LSP_ASSOCIATION_ENTRY);
                XML_ELT(mgmt_sock, ODCI_ASSOCIATION_TYPE, "%s",
                    pccd_ui_get_assoc_type_string(lsp->assoc_info[assoc_itr].assoc_type));
                XML_ELT(mgmt_sock, ODCI_ASSOCIATION_ID, "%d", lsp->assoc_info[assoc_itr].assoc_grp_id);


                if (!lsp->assoc_info[assoc_itr].is_assoc_src_ipv6) {
                    addr.s_addr = lsp->assoc_info[assoc_itr].assoc_source_u.v4;
                    XML_ELT(mgmt_sock, ODCI_ASSOCIATION_SOURCE, "%s", inet_ntoa(addr));
                } else {
                    char assoc_ip_str[INET6_ADDRSTRLEN];
                    struct in6_addr assoc_ipv6_addr;
                    memset(assoc_ip_str, 0, INET6_ADDRSTRLEN);
                    memcpy(&assoc_ipv6_addr,
                            lsp->assoc_info[assoc_itr].assoc_source_u.v6, 16);
                    inet_ntop(AF_INET6, &assoc_ipv6_addr, assoc_ip_str, sizeof(assoc_ip_str));
                    XML_ELT(mgmt_sock, ODCI_ASSOCIATION_SOURCE, "%s", assoc_ip_str);
                }
                
                if (LSP_ASSOCIATION_TYPE_SRPAG == lsp->assoc_info[assoc_itr].assoc_type) {
                    XML_OPEN(mgmt_sock, ODCI_SRPAG_ASSOCIATION_ENTRY);
                    XML_ELT(mgmt_sock, ODCI_SR_COLOR, "%u",
                        lsp->assoc_info[assoc_itr].sr_srpag_t.color);

                    if (!lsp->assoc_info[assoc_itr].sr_srpag_t.is_srpag_endpoint_ipv6) {
                        addr.s_addr = lsp->assoc_info[assoc_itr].sr_srpag_t.srpag_endpoint_addr_u.v4;
                        XML_ELT(mgmt_sock, ODCI_SR_ENDPOINT, "%s", inet_ntoa(addr));
                    } else {
                        char endpoint_str[INET6_ADDRSTRLEN];
                        struct in6_addr endpointv6_addr;
                        memset(endpoint_str, 0, INET6_ADDRSTRLEN);
                        memcpy(&endpointv6_addr,
                                lsp->assoc_info[assoc_itr].sr_srpag_t.srpag_endpoint_addr_u.v6, 16);
                        inet_ntop(AF_INET6, &endpointv6_addr, endpoint_str, sizeof(endpoint_str));
                        XML_ELT(mgmt_sock, ODCI_SR_ENDPOINT, "%s", endpoint_str);
                    }

                    XML_ELT(mgmt_sock, ODCI_SR_PROTO_ORIGIN, "%s", 
                        pccd_ui_get_sr_proto_origin_string(
                        lsp->assoc_info[assoc_itr].sr_srpag_t.sr_proto_origin));
                    XML_ELT(mgmt_sock, ODCI_SR_ORIGINATOR_ASN, "%u",
                        lsp->assoc_info[assoc_itr].sr_srpag_t.originator_asn);

                    if (!lsp->assoc_info[assoc_itr].sr_srpag_t.is_srpag_originator_ipv6) {
                        addr.s_addr = lsp->assoc_info[assoc_itr].sr_srpag_t.originator_addr_u.v4;
                        XML_ELT(mgmt_sock, ODCI_SR_ORIGINATOR_IP, "%s", inet_ntoa(addr));
                    } else {
                        char originator_str[INET6_ADDRSTRLEN];
                        struct in6_addr originatorv6_addr;
                        memset(originator_str, 0, INET6_ADDRSTRLEN);
                        memcpy(&originatorv6_addr,
                                lsp->assoc_info[assoc_itr].sr_srpag_t.originator_addr_u.v6, 16);
                        inet_ntop(AF_INET6, &originatorv6_addr, originator_str, sizeof(originator_str));
                        XML_ELT(mgmt_sock, ODCI_SR_ORIGINATOR_IP, "%s", originator_str);
                    }

                    XML_ELT(mgmt_sock, ODCI_SR_DISCRIMINATOR, "%u",
                        lsp->assoc_info[assoc_itr].sr_srpag_t.discriminator);
                    if (lsp->assoc_info[assoc_itr].sr_srpag_t.preference_valid) {
                        XML_ELT(mgmt_sock, ODCI_SR_PREFERENCE, "%u",
                            lsp->assoc_info[assoc_itr].sr_srpag_t.preference);
                    }
                    XML_CLOSE(mgmt_sock, ODCI_SRPAG_ASSOCIATION_ENTRY);
                }
                XML_CLOSE(mgmt_sock, ODCI_LSP_ASSOCIATION_ENTRY);
            }
            while (dag_i<lsp->div_assoc_info_count) {
                XML_OPEN(mgmt_sock, ODCI_LSP_ASSOCIATION_ENTRY);
                XML_ELT(mgmt_sock, ODCI_ASSOCIATION_TYPE, "DISJOINT");
                XML_ELT(mgmt_sock, ODCI_ASSOCIATION_ID, "%d",
                        lsp->div_assoc_info[dag_i].assoc_grp_id);
                if (!lsp->div_assoc_info[dag_i].is_assoc_src_ipv6) {
                    addr.s_addr = lsp->div_assoc_info[dag_i].assoc_source_u.v4;
                    XML_ELT(mgmt_sock, ODCI_ASSOCIATION_SOURCE, "%s", inet_ntoa(addr));
                } else {
                    char assoc_ip_str[INET6_ADDRSTRLEN];
                    struct in6_addr assoc_ipv6_addr;
                    memset(assoc_ip_str, 0, INET6_ADDRSTRLEN);
                    memcpy(&assoc_ipv6_addr,
                           lsp->div_assoc_info[dag_i].assoc_source_u.v6, 16);
                    inet_ntop(AF_INET6, &assoc_ipv6_addr, assoc_ip_str,
                              sizeof(assoc_ip_str));
                    XML_ELT(mgmt_sock, ODCI_ASSOCIATION_SOURCE, "%s", assoc_ip_str);
                }
                XML_OPEN(mgmt_sock, ODCI_DAG_ASSOCIATION_ENTRY);
                if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info_valid) {
                    if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.srlg_diverse) {
                        if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.link_diverse) {
                            strncpy(div_type, "SRLG_LINK_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.node_diverse) {
                            strncpy(div_type, "SRLG_NODE_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else {
                            strncpy(div_type, "SRLG_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        }
                    } else {
                        if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.link_diverse) {
                            strncpy(div_type, "LINK_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.node_diverse) {
                            strncpy(div_type, "NODE_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else {
                            strncpy(div_type, "UNKNOWN", DIVERSITY_TYPE_STR_MAX);
                        }
                    }
                    XML_ELT(mgmt_sock, ODCI_CONFIG_DISJOINT_TYPE, "%s", div_type);
                    XML_ELT(mgmt_sock, ODCI_CONFIG_STRICT,
                             (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.strictness?"Yes":"No"));
                    XML_ELT(mgmt_sock, ODCI_CONFIG_SHORTEST_PATH,
                             (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_conf_info.shortest_first?"Yes":"No"));
                }
                if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info_valid) {
                    if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.srlg_diverse) {
                        if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.link_diverse) {
                            strncpy(div_type, "SRLG_LINK_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.node_diverse) {
                            strncpy(div_type, "SRLG_NODE_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else {
                            strncpy(div_type, "SRLG_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        }
                    } else {
                        if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.link_diverse) {
                            strncpy(div_type, "LINK_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else if (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.node_diverse) {
                            strncpy(div_type, "NODE_DIVERSE", DIVERSITY_TYPE_STR_MAX);
                        } else {
                            strncpy(div_type, "UNKNOWN", DIVERSITY_TYPE_STR_MAX);
                        }
                    }
                    XML_ELT(mgmt_sock, ODCI_STATUS_DISJOINT_TYPE, "%s", div_type);
                    XML_ELT(mgmt_sock, ODCI_STATUS_STRICT,
                             (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.strictness?"Yes":"No"));
                    XML_ELT(mgmt_sock, ODCI_STATUS_SHORTEST_PATH,
                             (lsp->div_assoc_info[dag_i].disjoint_assoc_list.assoc_status_info.shortest_first?"Yes":"No"));
                }
                XML_CLOSE(mgmt_sock, ODCI_DAG_ASSOCIATION_ENTRY);
                dag_i++;
                XML_CLOSE(mgmt_sock, ODCI_LSP_ASSOCIATION_ENTRY);
            }

            memset(buff, '\0', 16);
            strftime (buff, 16, "%H:%M:%S.000", localtime (&lsp->last_pc_req_rpt));
            XML_ELT(mgmt_sock, ODCI_LSP_LAST_RECV, "%s", buff);

            memset(buff, '\0', 16);
            strftime (buff, 16, "%H:%M:%S.000", localtime (&lsp->last_pcupd_sent));
            XML_ELT(mgmt_sock, ODCI_LSP_LAST_SENT, "%s", buff);

            memset(buff, '\0', 16);
            strftime (buff, 16, "%H:%M:%S.000", localtime (&lsp->last_pc_upd_crt));
            XML_ELT(mgmt_sock, ODCI_LSP_PCU_RECV, "%s", buff);

            memset(buff, '\0', 16);
            strftime (buff, 16, "%H:%M:%S.000", localtime (&lsp->last_pcerr_sent));
            XML_ELT(mgmt_sock, ODCI_LSP_LAST_ERR, "%s", buff);

            XML_ELT(mgmt_sock, ODCI_LSP_LAST_ERR_REASON, "%s, %s, %s, %s, %s", 
                lsp->rpt_reason[0], lsp->rpt_reason[1], lsp->rpt_reason[2], lsp->rpt_reason[3], lsp->rpt_reason[4]);

            if (lsp_vec && lsp_vec->lv_type != LSP_VECTOR_P2P) {
                if (SLIST_FIRST(&lsp_vec->lv_flowspec_info_head)) {
                    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_EXT_FS);
                    SLIST_FOREACH_SAFE(fs_info, &lsp_vec->lv_flowspec_info_head,
                                       fs_info_next, fs_info_tmp) {
                        show_pccd_flowspec_info(mgmt_sock, fs_info, false);
                    }
                    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_EXT_FS);
                }
            }

            XML_CLOSE(mgmt_sock, ODCI_PCC_LSP_EXT_ENTRY);
        }
    } else {
        if( pccd_core_foreach_lsp_do(mgmt_sock, pccd_lsp_show_extensive_cb, 0)) {
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
            TRACE_FUNCTION_EXIT();
        }
    }
    
    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_ui_show_pccd_lsp_extensive (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status,
                       char *unparsed)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_EXTENSIVE);

    pccd_ui_show_pccd_lsp_extensive_display (mgmt_sock, status, unparsed);

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_EXTENSIVE);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * "show pccd lsp" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_lsp_display (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
		       char *unparsed)
{
    char*				print_one_lsp = NULL;
    const struct pccd_rpd_lsp_info*	lsp;
    struct lsp_vector *lsp_vec = NULL;
    struct pce_cfg_core *pce = NULL;
    TRACE_FUNCTION_ENTRY();

    if (unparsed && strstr(unparsed, "name")) {
        print_one_lsp = unparsed + strlen("name ");
        /*
         * even when name is not the cli option, the ms_parse_substring()seem
         * to pass on the the unparsed varaibale with "name". anyway let us be
         * safe and handle this case. this is the reason why anywhere you check
         * for validity of print_one_lsp, you have to check if the strlen is
         * also valid for a lsp name.
         */
    }

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP);

    if (print_one_lsp && strlen(print_one_lsp)) {
        lsp = pccd_rpd_get_lsp_by_name(print_one_lsp);
        if (lsp) {
            lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(lsp->id);
            if ((lsp_vec) && (lsp_vec->lv_ack_delegated == true)) {
                pce = lsp_vec->lv_pce;
            }

            (void)pccd_lsp_show_cb(mgmt_sock, pce, lsp, LSP_DISPLAY_FLAG_DEFULT);
        }
    } else {
        if( pccd_core_foreach_lsp_do(mgmt_sock, pccd_lsp_show_cb, LSP_DISPLAY_FLAG_DEFULT)) {
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
            TRACE_FUNCTION_EXIT();
        }
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP);

    TRACE_FUNCTION_RETURN(0);
}
/* show p2mp lsp */
static int
pccd_show_pccd_lsp_p2mp (mgmt_sock_t *mgmt_sock, struct pccd_p2mp_lsp_info *p2mp_lsp)
{
    struct pccd_rpd_lsp_info *rpd_lsp= NULL;
    struct pccd_rpd_lsp_info *tmp = NULL;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCC_P2MP_LSP_SECTION);
    XML_ELT(mgmt_sock, ODCI_P2MP_NAME, "%s", p2mp_lsp->p2mp_name);

    SLIST_FOREACH_SAFE(rpd_lsp, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, tmp) {
        struct lsp_vector *lsp_vec = pccd_core_get_lsp_vec_by_lsp_id(rpd_lsp->id);
        struct pce_cfg_core *pce = NULL;
        if (lsp_vec->lv_ack_delegated == true) {
            pce = lsp_vec->lv_pce;
        }
        
        XML_OPEN(mgmt_sock, ODCI_PCC_P2MP_LSP);
        (void)pccd_lsp_show_cb(mgmt_sock, pce, rpd_lsp, LSP_DISPLAY_FLAG_P2MP);
        XML_CLOSE(mgmt_sock, ODCI_PCC_P2MP_LSP);
    }
    
    XML_CLOSE(mgmt_sock, ODCI_PCC_P2MP_LSP_SECTION);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * "show pccd lsp p2mp" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_lsp_p2mp (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED, char *unparsed)
{
    char*               print_one_lsp;
    struct pccd_p2mp_lsp_info *p2mp_lsp = NULL;
    TRACE_FUNCTION_ENTRY();

    print_one_lsp = NULL;
    if (unparsed && strstr(unparsed, "name")) {
        print_one_lsp = unparsed + strlen("name ");
        /*
         * even when name is not the cli option, the ms_parse_substring()seem
         * to pass on the the unparsed varaibale with "name". anyway let us be
         * safe and handle this case. this is the reason why anywhere you check
         * for validity of print_one_lsp, you have to check if the strlen is
         * also valid for a lsp name.
         */
    }

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_P2MP);

    if (print_one_lsp && strlen(print_one_lsp)) {
        p2mp_lsp = pccd_get_p2mp_lsp_by_name(print_one_lsp);
        if (p2mp_lsp) {
            (void)pccd_show_pccd_lsp_p2mp(mgmt_sock, p2mp_lsp);
        }
    } else {
        void* next_node = NULL;
        p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
        while(NULL != p2mp_lsp){
            (void)pccd_show_pccd_lsp_p2mp(mgmt_sock, p2mp_lsp);
            p2mp_lsp = pccd_get_p2mp_lsp_next(&next_node);
        }
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_P2MP);

    TRACE_FUNCTION_RETURN(0);
}


/* show path-computation-client status callback */
static int
pccd_status_show_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce,
                         struct pce_lsp_statistic *pce_lsp_stats UNUSED, bool is_extensive UNUSED)
{
    time_t time_now;
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_SESSIONS_ENTRY);
    XML_ELT(mgmt_sock, ODCI_SESSION_NAME, "%s", pccd_core_pce_get_id(pce));
    XML_ELT(mgmt_sock, ODCI_SESSION_TYPE, "%s",
            pccd_core_get_pce_type_name_cli(pce));
    XML_ELT(mgmt_sock, ODCI_SESSION_PROVISIONING, "%s",
            pccd_core_pce_lsp_provisioning(pce) ? "On" : "Off");
    XML_ELT(mgmt_sock, ODCI_SESSION_STATUS, "%s",
            pccd_core_get_pce_state_name_cli(pce));
    time_now = time(NULL);
    XML_ELT(mgmt_sock, ODCI_SESSION_UP, "%d",
        (PCE_STATE_UP == pce->pc_state)?(time_now - pce->pc_statistics.pcep_connection_active):0);
    XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_SESSIONS_ENTRY);

    TRACE_FUNCTION_RETURN(0);
}

static int
pccd_status_pce_show_cb (mgmt_sock_t *mgmt_sock, struct pce_cfg_core *pce,
                         struct pce_lsp_statistic *pce_lsp_stats, bool is_extensive)
{
    char *key = NULL;

    TRACE_FUNCTION_ENTRY();

    if (false == is_extensive) {
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_PCE_ENTRY);
        XML_ELT(mgmt_sock, ODCI_PCE_NAME, "%s%s", pccd_core_pce_get_id(pce),
                pccd_core_pce_ismain(pce) ? " (main)" : "");
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED, "%lu", pce_lsp_stats->delegated);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED, "%lu", pce_lsp_stats->provisioned);
        key = pccd_core_pce_get_auth_key(pce);
        if (key[0] != 0) {
            XML_ELT(mgmt_sock, ODCI_PCE_AUTH_KEY, "%s", "configured" /*key*/);
        } else {
            key = pccd_core_pce_get_auth_keychain(pce);
            if (key[0] != 0) {
                XML_ELT(mgmt_sock, ODCI_PCE_AUTH_KEYCHAIN, "%s", key);
            }
            key = pccd_core_pce_get_auth_algorithm(pce);
            if (key[0] != 0) {
                XML_ELT(mgmt_sock, ODCI_PCE_AUTH_ALGORITHM, "%s", key);
            }
        }
        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_PCE_ENTRY);
    } else {
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_PCE_ENTRY_EXT);
        XML_ELT(mgmt_sock, ODCI_PCE_NAME_EXT, "%s%s", pccd_core_pce_get_id(pce),
                pccd_core_pce_ismain(pce) ? " (main)" : "");
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_EXT, "%lu", pce_lsp_stats->delegated);
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_P2P_EXT, "%lu", pce_lsp_stats->delegated_p2p);
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_P2P_PRIMARY_EXT, "%lu", 
                (pce_lsp_stats->delegated_p2p - pce_lsp_stats->delegated_p2p_bypass));
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_P2P_BYPASS_EXT, "%lu", 
                pce_lsp_stats->delegated_p2p_bypass);
        
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_P2MP_EXT, "%lu", pce_lsp_stats->delegated_p2mp);
        XML_ELT(mgmt_sock, ODCI_PCE_DELEGATED_P2MP_TREES_EXT, "%lu", 
                pce_lsp_stats->delegated_p2mp_trees);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_EXT, "%lu", pce_lsp_stats->provisioned);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_P2P_EXT, "%lu", pce_lsp_stats->provisioned_p2p);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_P2P_PRIMARY_EXT, "%lu", 
                (pce_lsp_stats->provisioned_p2p - pce_lsp_stats->provisioned_p2p_bypass));
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_P2P_BYPASS_EXT, "%lu", 
                pce_lsp_stats->provisioned_p2p_bypass);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_P2MP_EXT, "%lu", pce_lsp_stats->provisioned_p2mp);
        XML_ELT(mgmt_sock, ODCI_PCE_PROVISIONED_P2MP_TREES_EXT, "%lu", 
                pce_lsp_stats->provisioned_p2mp_trees);
        key = pccd_core_pce_get_auth_key(pce);
        if (key[0] != 0) {
            XML_ELT(mgmt_sock, ODCI_PCE_AUTH_KEY_EXT, "%s", "configured" /*key*/);
        } else {
            key = pccd_core_pce_get_auth_keychain(pce);
            if (key[0] != 0) {
                XML_ELT(mgmt_sock, ODCI_PCE_AUTH_KEYCHAIN_EXT, "%s", key);
            }
            key = pccd_core_pce_get_auth_algorithm(pce);
            if (key[0] != 0) {
                XML_ELT(mgmt_sock, ODCI_PCE_AUTH_ALGORITHM_EXT, "%s", key);
            }
        }
        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_PCE_ENTRY_EXT);
    }
    
    TRACE_FUNCTION_RETURN(0);
}

static void
pccd_status_add_sessions (mgmt_sock_t *mgmt_sock)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_SESSIONS);

    if( pccd_core_status_foreach_pce_do(mgmt_sock, pccd_status_show_cb,
                                        false, false)) {
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
        TRACE_FUNCTION_EXIT();
    }

    XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_SESSIONS);

    TRACE_FUNCTION_EXIT();
}

static void
pccd_status_add_lsp_summary (mgmt_sock_t *mgmt_sock, bool is_extensive)
{
    struct lsp_statistic stats;

    TRACE_FUNCTION_ENTRY();

    if (pccd_core_get_lsp_statistic(&stats))
    {
        TRACE_FUNCTION_EXIT();
        return;    
    }
    if (false == is_extensive) {
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_LSP);

        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_LSP_ENTRY);
        XML_ELT(mgmt_sock, ODCI_LSP_TOTAL, "%lu", stats.total);
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC, "%lu", stats.static_lsp);
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL, "%lu", stats.external);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER, "%lu", stats.provisioned_counter);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_LIMIT, "%lu", stats.provisioned_limit);
        XML_ELT(mgmt_sock, ODCI_LSP_ORPHAN, "%lu", stats.orphan);
        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_LSP_ENTRY);

        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_LSP);
    } else {
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_LSP_EXTENSIVE);

        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_LSP_ENTRY_EXT);
        XML_ELT(mgmt_sock, ODCI_LSP_TOTAL_EXT, "%lu", stats.total);
        
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_EXT, "%lu", stats.static_lsp);
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_P2P_EXT, "%lu", stats.static_lsp_p2p);
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_P2P_PRIMARY_EXT, "%lu", 
                (stats.static_lsp_p2p - stats.static_lsp_p2p_bypass));
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_P2P_BYPASS_EXT, "%lu", stats.static_lsp_p2p_bypass);
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_P2MP_EXT, "%lu", stats.static_lsp_p2mp);
        XML_ELT(mgmt_sock, ODCI_LSP_STATIC_P2MP_TREES_EXT, "%lu", stats.static_lsp_p2mp_trees);
        
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_EXT, "%lu", stats.external);
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_P2P_EXT, "%lu", stats.external_p2p);
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_P2P_PRIMARY_EXT, "%lu", 
                (stats.external_p2p - stats.external_p2p_bypass));
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_P2P_BYPASS_EXT, "%lu", stats.external_p2p_bypass);
        
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_P2MP_EXT, "%lu", stats.external_p2mp);
        XML_ELT(mgmt_sock, ODCI_LSP_EXTERNAL_P2MP_TREES_EXT, "%lu", stats.external_p2mp_trees);

        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_EXT, "%lu", stats.provisioned_counter);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_LIMIT_EXT, "%lu", stats.provisioned_limit);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_P2P_EXT, "%lu", stats.provisioned_counter_p2p);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_P2P_PRIMARY_EXT, "%lu", 
                (stats.provisioned_counter_p2p - stats.provisioned_counter_p2p_bypass));
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_P2P_BYPASS_EXT, "%lu", 
                stats.provisioned_counter_p2p_bypass);
        
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_P2MP_EXT, "%lu", stats.provisioned_counter_p2mp);
        XML_ELT(mgmt_sock, ODCI_LSP_PROVISIONED_COUNTER_P2MP_TREES_EXT, "%lu", stats.provisioned_counter_p2mp_trees);

        XML_ELT(mgmt_sock, ODCI_LSP_ORPHAN_EXT, "%lu", stats.orphan);
        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_LSP_ENTRY_EXT);        

        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_LSP_EXTENSIVE);
    }
    
    TRACE_FUNCTION_EXIT();
}

static void
pccd_status_add_pce_summary (mgmt_sock_t *mgmt_sock, bool is_extensive)
{
    TRACE_FUNCTION_ENTRY();

    if (false == is_extensive){
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_PCE);

        if( pccd_core_status_foreach_pce_do(mgmt_sock, pccd_status_pce_show_cb,
                                     true, false)) {
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
            TRACE_FUNCTION_EXIT();
        }

        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_PCE);
    } else {
        XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_PCE_EXTENSIVE);

        if( pccd_core_status_foreach_pce_do(mgmt_sock, pccd_status_pce_show_cb,
                                     true, true)) {
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
            TRACE_FUNCTION_EXIT();
        }

        XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_PCE_EXTENSIVE);
    }
    
    TRACE_FUNCTION_EXIT();
}

/**
 * "show pccd status" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_status (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
                              char *unparsed UNUSED)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATUS);

    pccd_status_add_sessions(mgmt_sock);
    pccd_status_add_lsp_summary(mgmt_sock, false);
    pccd_status_add_pce_summary(mgmt_sock, false);

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATUS);

    TRACE_FUNCTION_RETURN(0);
}

/* NSR Begin */
/* fills NSR Summary section in "show path-computation-client status extensive" */
static void
pccd_status_add_nsr_summary (mgmt_sock_t *mgmt_sock)
{
    TRACE_FUNCTION_ENTRY();
    boolean re_mode = pccd_nsr_master();
    boolean mirror_conn_status = pccd_mirror_is_connected();
    const char *repl_state = pccd_repl_state_to_string(pccd_repl_get_state());
    
    XML_OPEN(mgmt_sock, ODCI_PCC_STATUS_NSR_EXTENSIVE);
    
    XML_ELT(mgmt_sock, ODCI_RE_MODE, "%s", (re_mode ? "master" : "backup"));
    XML_ELT(mgmt_sock, ODCI_CONN_STATUS, "%s", (mirror_conn_status ? "up" : "down"));
    XML_ELT(mgmt_sock, ODCI_REPL_STATUS, "%s", repl_state);

    XML_CLOSE(mgmt_sock, ODCI_PCC_STATUS_NSR_EXTENSIVE);

    TRACE_FUNCTION_EXIT();
}
/* NSR End */

/**
 * "show pccd status extensive" cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_status_ext (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
                              char *unparsed UNUSED)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATUS_EXTENSIVE);

    pccd_status_add_sessions(mgmt_sock);
    pccd_status_add_lsp_summary(mgmt_sock, true);
    pccd_status_add_pce_summary(mgmt_sock, true);
	/* NSR Begin */
    pccd_status_add_nsr_summary(mgmt_sock);
	/* NSR End */

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATUS_EXTENSIVE);

    TRACE_FUNCTION_RETURN(0);
}


/*
 * "show pccd debug-information" cli handler.
 * @return 0 if success
 */
static int
pccd_ui_show_pccd_debug_info (mgmt_sock_t *mgmt_sock,
                              parse_status_t *status UNUSED,
                              char *unparsed UNUSED)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_DEBUG_INFO);

    XML_ELT(mgmt_sock, ODCI_PCCD_RPD_CONNECTION_STATUS, pccd_rpd_is_up() ? "Up" : "Down");

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_DEBUG_INFO);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * "clear pccd statistics ..." cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_clear_pccd_statistics (mgmt_sock_t *mgmt_sock,
                               parse_status_t *status UNUSED, char *unparsed)
{
    struct pce_cfg_core *pce = NULL;

    TRACE_FUNCTION_ENTRY();

    if (NULL == unparsed || strstr(unparsed, "all")) {
        if( pccd_core_foreach_pce_do(mgmt_sock, pccd_statistics_clear_cb,
                                     false)) {
            XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Clear failed.");
            XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

            TRACE_FUNCTION_RETURN(-1);
        }
    } else {
        pce = pccd_core_get_pce_by_id(unparsed);

        if (NULL == pce) {
            TRACE_CORE("Clear failed: no PCe with name \'%s\'", unparsed);
            XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
            PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "PCE \'%s\' not found.",
                                     unparsed);
            XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

            TRACE_FUNCTION_RETURN(-1);
        }

        TRACE_CORE("Clear statistics of PCE with name \'%s\'",
                   pccd_core_pce_get_id(pce));
        pccd_core_clear_statistics(pce);
    }

    XML_SEND_SUCCESS_TAG(mgmt_sock);

    TRACE_FUNCTION_RETURN(0);
}

/**
 * "requiest pccd active-pce ..." cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_request_pccd_active_pce (mgmt_sock_t *mgmt_sock,
                                 parse_status_t *status UNUSED, char *unparsed)
{
    struct pce_cfg_core *requested_active_pce = NULL;

    TRACE_FUNCTION_ENTRY();

    requested_active_pce = pccd_core_get_pce_by_id(unparsed);
    if (NULL == requested_active_pce) {
        XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "PCE \'%s\' not found.", unparsed);
        XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

        TRACE_FUNCTION_RETURN(-1);
    }

    if (false == pccd_core_set_new_main_pce(requested_active_pce)) {
        XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Failed to change active PCE.");
        XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

        TRACE_FUNCTION_RETURN(-1);
    }
    XML_SEND_SUCCESS_TAG(mgmt_sock);

    TRACE_FUNCTION_RETURN(-1);
}
/**
 * "requiest pccd active-pce ..." cli handler.
 *
 * @return 0 if success
 */
static int
pccd_ui_request_pccd_retry_delegation (mgmt_sock_t *mgmt_sock,
                                 parse_status_t *status UNUSED, char *unparsed)
{
    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);
    pccd_core_delegation_retry_by_lsp_name(unparsed);
    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_STATISTICS);

    XML_SEND_SUCCESS_TAG(mgmt_sock);

    TRACE_FUNCTION_RETURN(0);
}

/* "show path-computation-client object-class" */
static int
pccd_ui_show_pccd_object_class (mgmt_sock_t *mgmt_sock, parse_status_t *status UNUSED,
                                char *unparsed UNUSED)
{
    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_OBJECT_CLASS);
    XML_OPEN(mgmt_sock, ODCI_PCC_OBJECT_CLASS_ENTRY);

    XML_ELT(mgmt_sock, ODCI_OPEN_OBJECT, "%u", PCEP_OBJCLASS_OPEN);
    XML_ELT(mgmt_sock, ODCI_RP_OBJECT, "%u", PCEP_OBJCLASS_RP);
    XML_ELT(mgmt_sock, ODCI_NOPATH_OBJECT, "%u", PCEP_OBJCLASS_NOPATH);
    XML_ELT(mgmt_sock, ODCI_ENDPOINTS_OBJECT, "%u", PCEP_OBJCLASS_ENDPOINTS);
    XML_ELT(mgmt_sock, ODCI_BANDWIDTH_OBJECT, "%u", PCEP_OBJCLASS_BANDWIDTH);
    XML_ELT(mgmt_sock, ODCI_METRIC_OBJECT, "%u", PCEP_OBJCLASS_METRIC);
    XML_ELT(mgmt_sock, ODCI_ERO_OBJECT, "%u", PCEP_OBJCLASS_ERO);
    XML_ELT(mgmt_sock, ODCI_RRO_OBJECT, "%u", PCEP_OBJCLASS_RRO);
    XML_ELT(mgmt_sock, ODCI_LSPA_OBJECT, "%u", PCEP_OBJCLASS_LSPA);
    XML_ELT(mgmt_sock, ODCI_IRO_OBJECT, "%u", PCEP_OBJCLASS_IRO);
    XML_ELT(mgmt_sock, ODCI_SVEC_OBJECT, "%u", PCEP_OBJCLASS_SVEC);
    XML_ELT(mgmt_sock, ODCI_NOTIFICATION_OBJECT, "%u", PCEP_OBJCLASS_NOTIFICATION);
    XML_ELT(mgmt_sock, ODCI_PCEPERROR_OBJECT, "%u", PCEP_OBJCLASS_PCEPERROR);
    XML_ELT(mgmt_sock, ODCI_LOADBALANCING_OBJECT, "%u", PCEP_OBJCLASS_LOADBALANCING);
    XML_ELT(mgmt_sock, ODCI_CLOSE_OBJECT, "%u", PCEP_OBJCLASS_CLOSE);
    XML_ELT(mgmt_sock, ODCI_PATHKEY_OBJECT, "%u", PCEP_OBJCLASS_PATHKEY);
    XML_ELT(mgmt_sock, ODCI_LSP_OBJECT, "%u", PCEP_OBJCLASS_LSP);
    XML_ELT(mgmt_sock, ODCI_SRP_OBJECT, "%u", PCEP_OBJCLASS_SRP);
    XML_ELT(mgmt_sock, ODCI_VENDOR_OBJECT, "%u", PCEP_OBJCLASS_VENDOR);

    //Change values accordingly
    XML_ELT(mgmt_sock, ODCI_S2LS_OBJECT, "%u", PCEP_OBJCLASS_S2LS_VAL);
    XML_ELT(mgmt_sock, ODCI_ASSOCIATION_OBJECT, "%u", 
        (assoc_obj_complaince != ASSOC_OBJ_OLD_OBJ_CLASS_OLD_FORMAT) ?
         PCEP_OBJCLASS_ASSOCIATION : PCEP_OBJCLASS_ASSOCIATION_nonIANA);

    XML_ELT(mgmt_sock, ODCI_FLOWSPEC_OBJECT, "%u", PCEP_OBJCLASS_FLOWSPEC);
    XML_ELT(mgmt_sock, ODCI_PATHATTRIBUTE_OBJECT, "%u", PCEP_OBJ_PATH_ATTRIBUTE);

    XML_CLOSE(mgmt_sock, ODCI_PCC_OBJECT_CLASS_ENTRY);
    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_OBJECT_CLASS);
    return 0;
}

/* "show path-computation-client tlv-types" */
static int
pccd_ui_show_pccd_tlv_types (mgmt_sock_t *mgmt_sock, parse_status_t *status UNUSED,
                             char *unparsed UNUSED)
{
    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_TLV_TYPES);
    XML_OPEN(mgmt_sock, ODCI_PCC_TLV_TYPES_ENTRY);

    XML_ELT(mgmt_sock, ODCI_TLV_NO_PATH_VECTOR, "%u", TLV_NO_PATH_VECTOR);
    XML_ELT(mgmt_sock, ODCI_TLV_OVERLOADED_DURATION, "%u", TLV_OVERLOADED_DURATION);
    XML_ELT(mgmt_sock, ODCI_TLV_REQ_MISSING, "%u", TLV_REQ_MISSING);
    XML_ELT(mgmt_sock, ODCI_TLV_STATEFUL_PCE_CAPABILITY, "%u", TLV_STATEFUL_PCE_CAPABILITY);
    XML_ELT(mgmt_sock, ODCI_TLV_LSP_SYMBOLIC_NAME, "%u", TLV_LSP_SYMBOLIC_NAME);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV4_LSP_IDENTIFIERS, "%u", TLV_IPV4_LSP_IDENTIFIERS);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV6_LSP_IDENTIFIERS, "%u", TLV_IPV6_LSP_IDENTIFIERS);
    XML_ELT(mgmt_sock, ODCI_TLV_LSP_UPDATE_ERROR_CODE, "%u", TLV_LSP_UPDATE_ERROR_CODE);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV4_RSVP_ERROR_SPEC, "%u", TLV_IPV4_RSVP_ERROR_SPEC);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV6_RSVP_ERROR_SPEC, "%u", TLV_IPV6_RSVP_ERROR_SPEC);
    XML_ELT(mgmt_sock, ODCI_TLV_LSP_DB_VERSION, "%u", TLV_LSP_DB_VERSION);
    XML_ELT(mgmt_sock, ODCI_TLV_NODE_IDENTIFIER, "%u", TLV_NODE_IDENTIFIER);
    XML_ELT(mgmt_sock, ODCI_TLV_SR_PCE_CAPABILITY, "%u", TLV_SR_PCE_CAPABILITY);
    XML_ELT(mgmt_sock, ODCI_TLV_PATH_SETUP_TYPE, "%u", TLV_PATH_SETUP_TYPE);
    XML_ELT(mgmt_sock, ODCI_TLV_TE_PATH_BINDING, "%u", TLV_TE_PATH_BINDING);
    XML_ELT(mgmt_sock, ODCI_TLV_VENDOR_LSP_QUALIFIER, "%u", TLV_VENDOR_LSP_QUALIFIER);
    XML_ELT(mgmt_sock, ODCI_TLV_VENDOR_LSP_BW, "%u", TLV_VENDOR_LSP_BW);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV4_P2MP_LSP_IDENTIFIERS, "%u", TLV_IPV4_P2MP_LSP_IDENTIFIERS);
    XML_ELT(mgmt_sock, ODCI_TLV_IPV6_P2MP_LSP_IDENTIFIERS, "%u", TLV_IPV6_P2MP_LSP_IDENTIFIERS);
    XML_ELT(mgmt_sock, ODCI_TLV_VENDOR_P2MP_TREE_NAME, "%u", TLV_VENDOR_P2MP_TREE_NAME);
//    XML_ELT(mgmt_sock, ODCI_TLV_LSP_CLEANUP, "%u", TLV_LSP_CLEANUP);      //TODO: Is it okay to remove a xml tag
    XML_ELT(mgmt_sock, ODCI_TLV_VENDOR_LOCAL_CSPF, "%u", TLV_VENDOR_LOCAL_CSPF);
    XML_ELT(mgmt_sock, ODCI_TLV_SR_CANDIDATE_PATH_IDENTIFIER, "%u", TLV_SR_CANDIDATE_PATH_IDENTIFIER);
    XML_ELT(mgmt_sock, ODCI_TLV_SR_PREFERENCE, "%u", TLV_SR_PREFERENCE);
    XML_ELT(mgmt_sock, ODCI_TLV_MULTIPATH_CAPABILITY, "%u", TLV_MULTIPATH_CAPABILITY);
    XML_ELT(mgmt_sock, ODCI_TLV_PATH_ATTRIBUTE_WEIGHT, "%u", TLV_MULTIPATH_WEIGHT);
    XML_ELT(mgmt_sock, ODCI_TLV_PATH_ATTRIBUTE_BACKUP, "%u", TLV_MULTIPATH_BACKUP);
    XML_ELT(mgmt_sock, ODCI_TLV_PCE_FLOWSPEC_CAPABILITY, "%u", TLV_PCE_FLOWSPEC_CAPABILITY);
    XML_ELT(mgmt_sock, ODCI_TLV_FLOWSPEC_FLOWFILTER, "%u", TLV_FLOWSPEC_FLOWFILTER);
    XML_ELT(mgmt_sock, ODCI_TLV_PATH_ATTRIBUTE_COLOR, "%u", pathattribute_color_tlv_type);
    XML_ELT(mgmt_sock, ODCI_TLV_VENDOR_ROUTE_METRIC, "%u", TLV_VENDOR_LSP_ROUTE_PREFERENCE);
    XML_ELT(mgmt_sock, ODCI_TLV_DISJOINT_CONFIGURATION, "%u", TLV_DISJOINT_CONFIGURATION);
    XML_ELT(mgmt_sock, ODCI_TLV_DISJOINT_STATUS, "%u", TLV_DISJOINT_STATUS);

    XML_CLOSE(mgmt_sock, ODCI_PCC_TLV_TYPES_ENTRY);
    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_TLV_TYPES);
    return 0;
}

/* "show path-computation-client rfc-8231-compliance" */
static int
pccd_ui_show_pccd_rfc_8231_compliance (mgmt_sock_t *mgmt_sock UNUSED,
                                       parse_status_t *status UNUSED,
                                       char *unparsed UNUSED)
{
    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_RFC_8231_COMPLIANCE);

    if (!rfc8231_compliant) {
        XML_ELT(mgmt_sock, ODCI_RFC_STATUS, "No");
    } else {
        XML_ELT(mgmt_sock, ODCI_RFC_STATUS, "Yes");
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_RFC_8231_COMPLIANCE);
    return 0;
}


static int
pccd_show_lsp_flowspec_cb (mgmt_sock_t *mgmt_sock,
                           struct pce_cfg_core* pce, bool detailed UNUSED)
{
    int buff_len = 256, len, total_len;
    char buff[buff_len], int_num[10];

    struct pccd_p2mp_lsp_info *p2mp_lsp;
    struct lsp_vector *lsp_vec, *lsp_vec_tmp;
    struct pccd_flowspec_info_s *fs_info, *fs_info_tmp;
    struct pccd_rpd_lsp_info *p2mp_br, *p2mp_tmp;
    struct pccd_rpd_lsp_info *rpd_lsp = NULL;

    SLIST_FOREACH_SAFE(lsp_vec, &pce->pc_lsps, lv_pce_lsps, lsp_vec_tmp) {
        char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];

        p2mp_lsp = pccd_rpd_get_p2mp_lsp_by_id(lsp_vec->lv_lsp_id);
        total_len = 0;

        if (!p2mp_lsp) {
            rpd_lsp = pccd_rpd_get_lsp_by_id(lsp_vec->lv_lsp_id);
            if (!rpd_lsp) {
                continue;
            }
        }

        memset(buff, '\0', buff_len);
        SLIST_FOREACH_SAFE(fs_info, &lsp_vec->lv_flowspec_info_head, fs_info_next, fs_info_tmp) {
            if (fs_info_tmp) {
                len = snprintf(int_num, sizeof(int_num), "%u, ", fs_info->fs_id);
            } else { 
                len = snprintf(int_num, sizeof(int_num), "%u", fs_info->fs_id);
            }
            total_len += len;
            if (total_len < buff_len) {
                strncat(buff, int_num, len);
            }
        }

        /* 
         * If their is no FlowSpec associated with
         * LSP, then do not print anything
         */
         if (total_len == 0) {
             continue;
         }

         if (p2mp_lsp) {
             SLIST_FOREACH_SAFE(p2mp_br, &p2mp_lsp->p2mp_branch_lsps, lv_p2mp_lsps, p2mp_tmp) {
                 pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                     p2mp_br->lsp_name, p2mp_br->path_name);

                 XML_OPEN(mgmt_sock, ODCI_PCC_LSP_TRAFFIC_STEERING_ENTRY);

                 XML_ELT(mgmt_sock, ODCI_LSP_NAME, "%s", lsp_full_name);
                 XML_ELT(mgmt_sock, ODCI_LSP_P2MP, "%s", p2mp_lsp->p2mp_name);
                 XML_ELT(mgmt_sock, ODCI_LSP_PLSP_ID, "%u", p2mp_lsp->plsp_id);
                 XML_ELT(mgmt_sock, ODCI_PCE_ID, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
                 XML_ELT(mgmt_sock, ODCI_LSP_FS_ID, "%s", buff);

                 XML_CLOSE(mgmt_sock, ODCI_PCC_LSP_TRAFFIC_STEERING_ENTRY);
             }
         } else {
             pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name),
                rpd_lsp->lsp_name, rpd_lsp->path_name);

             XML_OPEN(mgmt_sock, ODCI_PCC_LSP_TRAFFIC_STEERING_ENTRY);

             XML_ELT(mgmt_sock, ODCI_LSP_NAME, "%s", lsp_full_name);
             XML_ELT(mgmt_sock, ODCI_LSP_PLSP_ID, "%u", rpd_lsp->id);
             XML_ELT(mgmt_sock, ODCI_PCE_ID, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
             XML_ELT(mgmt_sock, ODCI_LSP_FS_ID, "%s", buff);

             XML_CLOSE(mgmt_sock, ODCI_PCC_LSP_TRAFFIC_STEERING_ENTRY);
         }
    }
    return 0;
}

/*
 * show path-computation-client lsp traffic steering
 */
static int
pccd_ui_show_pccd_lsp_flowspec (mgmt_sock_t *mgmt_sock,
                                parse_status_t *status UNUSED, char *unparsed UNUSED)
{
    int res;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_TRAFFIC_STEERING);

    res  = pccd_core_foreach_pce_do(mgmt_sock, pccd_show_lsp_flowspec_cb, false);
    if (res) {
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
        XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_TRAFFIC_STEERING);
        TRACE_FUNCTION_RETURN(-1);
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_LSP_TRAFFIC_STEERING);

    TRACE_FUNCTION_RETURN(0);
}

static int
show_pccd_flowspec_cb (mgmt_sock_t *mgmt_sock,
                       struct pce_cfg_core* pce, bool detailed UNUSED)
{
    struct pccd_flowspec_info_s *fs_info, *fs_info_next;

    XML_OPEN(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_SECTION);
    XML_ELT(mgmt_sock, ODCI_PCE_ID, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
    XML_OPEN(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING);

    fs_info = pccd_core_get_first_flowspec_info(pce);
    while (fs_info) {
        fs_info_next = pccd_core_get_next_flowspec_info(pce, &fs_info->fs_patricia_node);
        show_pccd_flowspec_info(mgmt_sock, fs_info, true);
        fs_info = fs_info_next;
    }
    XML_CLOSE(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING);
    XML_CLOSE(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_SECTION);

    return PCCD_RET_SUCCESS;
}

static int
show_pccd_flowspec_one_pce (mgmt_sock_t *mgmt_sock,
                            struct pce_cfg_core* pce, uint32_t fs_id)
{
    struct pccd_flowspec_info_s *fs_info, *fs_info_next;

    XML_OPEN(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_SECTION);
    XML_ELT(mgmt_sock, ODCI_PCE_ID, "%s", pce ? pccd_core_pce_get_id(pce) : "-");
    XML_OPEN(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING);

    if (fs_id) {
        fs_info = pccd_core_get_pce_fs_by_id(pce, fs_id);
        if (fs_info) {
            show_pccd_flowspec_info(mgmt_sock, fs_info, true);
        }
    } else {
        fs_info = pccd_core_get_first_flowspec_info(pce);
        while (fs_info) {
            fs_info_next = pccd_core_get_next_flowspec_info(pce, &fs_info->fs_patricia_node);
            show_pccd_flowspec_info(mgmt_sock, fs_info, true);
            fs_info = fs_info_next;
        }
    }

    XML_CLOSE(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING);
    XML_CLOSE(mgmt_sock, ODCI_PCC_TRAFFIC_STEERING_SECTION);

    return PCCD_RET_SUCCESS;
}


/*
 * show path-computation-client traffic steering
 * show path-computation-client traffic steering pce <pce-id>
 */
static int
pccd_ui_show_pccd_flowspec (mgmt_sock_t *mgmt_sock, parse_status_t *status UNUSED,
                            char *unparsed)
{
    int res, i;
    uint32_t fs_id;
    struct pce_cfg_core *pce;
    char work[100];
    char p[3][30], *tok;

    TRACE_FUNCTION_ENTRY();

    XML_OPEN(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_TRAFFIC_STEERING);

    fs_id = 0;
    res = -1;
    if (unparsed) {
        i = 0;
        strncpy(work, unparsed, 100 - 1);

        tok = strtok(work, " ");
        while (tok) {
            strncpy(p[i], tok, 30 - 1);
            i++;
            tok = strtok(NULL, " ");
        }
        pce = pccd_core_get_pce_cfg_core(p[0]);
        if (pce) {
            if (i > 2) {
                fs_id = strtoul(p[2], NULL, 10);
            }
            res = show_pccd_flowspec_one_pce(mgmt_sock, pce, fs_id);
        }
    } else {
        res  = pccd_core_foreach_pce_do(mgmt_sock, show_pccd_flowspec_cb, false);
    }

    if (res) {
        PCCD_SEND_ERROR_RESPONSE(mgmt_sock, "Show failed.");
        XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_TRAFFIC_STEERING);
        TRACE_FUNCTION_RETURN(-1);
    }

    XML_CLOSE(mgmt_sock, ODCI_PATH_COMPUTATION_CLIENT_TRAFFIC_STEERING);

    TRACE_FUNCTION_RETURN(0);
}

/*
 * show_version
 *
 * Return the version string
 *
 */
static int
show_version (mgmt_sock_t *msp, parse_status_t *csb,
              char *unparsed __unused)
{
    int level = csb->subcode;

    if (level == LEVEL_BRIEF) {
        xml_show_version(msp, NULL, FALSE);
    } else if (level == LEVEL_DETAIL ||
               level == LEVEL_EXTENSIVE ||
               level == LEVEL_SESSION_TRACE) {
        xml_show_version(msp, NULL, TRUE);
    }

    return 0;
}

///////////////////////////////////////////////////////////////////////////////
// parsers lvl4
static const parse_menu_t pccd_ui_show_pccd_traffic_steering_pce[] = {
    {"fs-id", "show extensive label switched path", 0, NULL, pccd_ui_show_pccd_flowspec},
    {NULL, "Show Traffic Steering (FLowSpec) information", 0, NULL, pccd_ui_show_pccd_flowspec},
    {NULL, NULL, 0, NULL, NULL}
};

///////////////////////////////////////////////////////////////////////////////
// parsers lvl3
static const parse_menu_t pccd_menu_show_status[] = {
        {"extensive",  "show path-computation-client status extensive", 0, NULL, pccd_ui_show_pccd_status_ext},
        {NULL, "show path-computation-client status", 0, NULL, pccd_ui_show_pccd_status},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_ui_show_pccd_lsp[] = {
    {"extensive", "show extensive label switched path", 0, NULL, pccd_ui_show_pccd_lsp_extensive},
    {"p2mp",  "show p2mp label switched path", 0, NULL, pccd_ui_show_pccd_lsp_p2mp},
    {"traffic-steering", "show lsp's traffic steering", 0, NULL, pccd_ui_show_pccd_lsp_flowspec},
    {NULL, "show label switched path database", 0, NULL, pccd_ui_show_pccd_lsp_display},
    {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_ui_show_pccd_traffic_steering[] = {
    {"pce", "show extensive label switched path", 0, pccd_ui_show_pccd_traffic_steering_pce, NULL},
    {NULL, "Show Traffic Steering (FLowSpec) information", 0, NULL, pccd_ui_show_pccd_flowspec},
    {NULL, NULL, 0, NULL, NULL}
};

///////////////////////////////////////////////////////////////////////////////
// parsers lvl2
static const parse_menu_t pccd_menu_show_statistics[] = {
        {"statistics", "show path-computation-client statistics", 0, NULL, pccd_ui_show_pccd_statistics},
        {"active-pce", "show active PCE statistics", 0, NULL, pccd_ui_show_pccd_active_pce},
        {"lsp", "show label switched path database", 0, pccd_ui_show_pccd_lsp, NULL},
        {"status", "show path-computation-client status", 0, pccd_menu_show_status, NULL},
        {"debug-information", "show path-computation-client debug-information", 0, NULL, pccd_ui_show_pccd_debug_info},
        {"lsp-retry-pending", "show LSPs for which the retry delegation is pending", 0, NULL, pccd_ui_show_pccd_lsp_retry_pending},
        {"object-class", "show object class values", 0, NULL, pccd_ui_show_pccd_object_class},
        {"tlv-types", "show tlv type values", 0, NULL, pccd_ui_show_pccd_tlv_types},
        {"rfc-8231-compliance", "show RFC 8231 compliance", 0, NULL, pccd_ui_show_pccd_rfc_8231_compliance},
        {"traffic-steering", "Show Traffic Steering (FLowSpec) information", 0, pccd_ui_show_pccd_traffic_steering, NULL},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_menu_clear_statistics[] = {
        {"statistics", "clear path-computation-client statistics", 0, NULL, pccd_ui_clear_pccd_statistics},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_menu_request_active_pce[] = {
        {"active-pce", "set active PCE", 0, NULL, pccd_ui_request_pccd_active_pce},
        {"retry-delegation", "retry delegation of LSP", 0, NULL, pccd_ui_request_pccd_retry_delegation},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_show_version_menu[] = {
        { "brief", NULL, LEVEL_BRIEF, NULL, show_version},
        { "detail", NULL, LEVEL_DETAIL, NULL, show_version },
        { "extensive", NULL, LEVEL_EXTENSIVE, NULL, show_version },
        { "trace-info", NULL, LEVEL_SESSION_TRACE, NULL, show_version },
        { NULL, NULL, 0, NULL, NULL }
};

///////////////////////////////////////////////////////////////////////////////
// parsers lvl1
static const parse_menu_t pccd_menu_show[] = {
        {"path-computation-client", NULL, 0, pccd_menu_show_statistics, NULL},
        {"version", NULL, 0, pccd_show_version_menu, NULL},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_menu_clear[] = {
        {"path-computation-client", NULL, 0, pccd_menu_clear_statistics, NULL},
        {NULL, NULL, 0, NULL, NULL}
};

static const parse_menu_t pccd_menu_request[] = {
        {"path-computation-client", NULL, 0, pccd_menu_request_active_pce, NULL},
        {NULL, NULL, 0, NULL, NULL}
};

///////////////////////////////////////////////////////////////////////////////
// parsers lvl0
const parse_menu_t pccd_master_menu[] = {
        {"show", NULL, 0, pccd_menu_show, NULL},
        {"clear", NULL, 0, pccd_menu_clear, NULL},
        {"request", NULL, 0, pccd_menu_request, NULL},
        {NULL, NULL, 0, NULL, NULL}
};

///////////////////////////////////////////////////////////////////////////////
// init
int
pccd_ui_init(evContext ctx)
{
    TRACE_UI("Initializing pccd ui");

    xml_set_send_method((xml_send_method_t) ms_peer_send_line);
    xml_set_get_method((xml_get_method_t) mgmt_sock_get_xml);
    xml_set_eof_method((xml_eof_method_t) mgmt_sock_eof);
    ms_init(ctx, DNAME_PCCD, pccd_master_menu, NULL);

    return 0;
}
