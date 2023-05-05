/*
 * $Id: pccd_core.h 1325062 2023-03-29 15:13:08Z gchandraseka $
 *
 * pccd_core.h
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */

#ifndef PCCD_CORE_H_
#define PCCD_CORE_H_

#include <netinet/in.h>
#include <isc/eventlib.h>
#include <helpers/trace_util.h>
#include <sys/queue.h>
#include <jnx/patricia.h>
#include <jnx/libpcep.h>
#include "pccd_stats.h"
#include "pccd_radix.h"

#define PCCD_AUTH_KEYCHAIN_MAX 128
#define PCCD_AUTH_ALGORITHM_MAX 32
#define PCCD_AUTH_KEY_MAX 128
#define PCCD_PCE_ID_MAX 64

#define PCEP_ERR_TYPE_INTERNAL_ERROR 24
#define PCEP_ERR_VALUE_INTERNAL_ERROR 1

#define PCE_ENTITY_CONN_KEY_SIZE 4
#define PCE_PEER_CONN_KEY_SIZE 12
#define PCE_SESS_CONN_KEY_SIZE 16

#define PCCD_PCC_FS_ID_MAX                 0xffffffff

extern bool rfc8231_compliant;
extern bool multipath_enabled;
extern bool disjoint_association_enabled;

struct pccd_rpd_lsp_info;
struct lsp_intended_attr_s;

#define pccd_core_incr_lv_mapped_flows_cnt(lsp_vec) lsp_vec->lv_mapped_flows_count++
#define pccd_core_decr_lv_mapped_flows_cnt(lsp_vec) lsp_vec->lv_mapped_flows_count--

typedef enum {
    PCE_TYPE_NONE,
    PCE_TYPE_STATELESS,
    PCE_TYPE_STATEFUL,
    PCE_TYPE_STATEFULACTIVE
} pce_type_t;

struct pce_local_timers {
    unsigned char plt_min_keepalive;
    unsigned char plt_max_keepalive;
    unsigned char plt_max_deadtimer;
};

struct pce_remote_timers {
    unsigned char prt_min_keepalive;
    unsigned char prt_max_keepalive;
};

/*PCEP MIB entity table*/
typedef struct pcePcepEntityTable_data {
    patnode_t node;
    u_int8_t key[PCE_ENTITY_CONN_KEY_SIZE];
    uint32_t pcePcepEntityIndex;
} pcePcepEntityTable_data_t;

/*PCEP MIB Peer table*/
typedef struct pcePcepPeerTable_data {
    patnode_t node;
    u_int8_t key[PCE_PEER_CONN_KEY_SIZE];
    union {
        struct in_addr   v4;
        struct in6_addr  v6;
    } pcePcepPeerAddr;
    int pcePcepPeerAddrType;
    int pcePcepPeerRole;
    boolean pcePcepPeerInitiateSession;
    boolean pcePcepPeerSessionExists;
    uint32_t pcePcepPeerNumSessSetupOK;
    uint32_t pcePcepPeerNumSessSetupFail;
    int32_t pcePcepPeerSessionUpTime;
    int32_t pcePcepPeerSessionFailTime;
    int32_t pcePcepPeerSessionFailUpTime;
    uint32_t pcePcepPeerNumPCErrSent;
    uint32_t pcePcepPeerNumPCErrRcvd;
    uint32_t pcePcepPeerNumKeepaliveSent;
    uint32_t pcePcepPeerNumKeepaliveRcvd;
    uint32_t pcePcepPeerNumUnknownRcvd;
    uint32_t pcePcepPeerNumCorruptRcvd;

    struct pce_cfg_core *pce_core;
} pcePcepPeerTable_data_t;

/*PCEP MIB Session Table*/
typedef struct pcePcepSessTable_data {
    patnode_t node;
    u_int8_t key[PCE_SESS_CONN_KEY_SIZE];
    struct pcep_conn *pc_conn;
    uint32_t pcePcepSessConnectRetry;
    int32_t pcePcepSessStateLastChange;
    uint32_t pcePcepSessState;
    int32_t pcePcepSessInitiator;
    int32_t pcePcepSessDiscontinuityTime;

    uint32_t pcePcepSessLocalID;
    uint32_t pcePcepSessRemoteID;
    uint32_t pcePcepSessKeepaliveTimer;
    uint32_t pcePcepSessPeerKeepaliveTimer;
    uint32_t pcePcepSessDeadTimer;
    uint32_t pcePcepSessPeerDeadTimer;
    uint32_t pcePcepSessNumPCErrSent;
    uint32_t pcePcepSessNumPCErrRcvd;
    uint32_t pcePcepSessNumKeepaliveSent;
    uint32_t pcePcepSessNumKeepaliveRcvd;
    uint32_t pcePcepSessNumUnknownRcvd;
    uint32_t pcePcepSessNumCorruptRcvd;
} pcePcepSessTable_data_t;

/*
 * config against each pce on how to treat the empty-ero received in pcupdate.
 */
typedef
struct pce_cfg_empty_ero_action_s {
    bool			pceea_send_err;
    bool			pceea_path_tear_down;
    bool			pceea_routing_decision; /* the default */
} pce_cfg_empty_ero_action_t;

struct pce_common_opts {
    pce_type_t                  pco_pce_type;
    char                        pco_auth_keychain[PCCD_AUTH_KEYCHAIN_MAX];
    char                        pco_auth_algorithm[PCCD_AUTH_ALGORITHM_MAX];
    char                        pco_auth_key[PCCD_AUTH_KEY_MAX];
    struct pce_local_timers     pco_local_timers;
    struct pce_remote_timers    pco_remote_timers;
    unsigned short              pco_request_timer;
    unsigned                    pco_max_unknown_requests;
    unsigned                    pco_max_unknown_messages;
    bool                        pco_no_advertise_pcc_owned_lsps;
    unsigned int                pco_delegation_cleanup_timeout;
    unsigned short              pco_delegation_setup_timeout;
    unsigned short              pco_delegation_retry_timeout;
    bool                        pco_lsp_retry_delegation;
    bool                        pco_changed;
    bool                        pco_lsp_provisioning;
    bool                        pco_p2mp_lsp_report_capability;
    bool                        pco_p2mp_lsp_update_capability;
    bool                        pco_p2mp_lsp_init_capability;
	bool						pco_spring_capability;
    bool                        pco_srv6_capability;
    unsigned int                pco_lsp_cleanup_timer;
    daemon_trace_file_options_t pco_traceoptions;
    pce_cfg_empty_ero_action_t  pco_empty_ero_action;
    bool                        pco_disable_tlv_path_binding;
    bool                        pco_flowspec_capability;
    bool                        pco_multipath_capability;
    uint16_t                    pco_num_multipaths;
    bool                        pco_tls_enabled;
    uint8_t                     pco_tls_wait_timer;
    bool                        pco_disjoint_assoc_capability;
};
#define pco_empty_ero_send_err            pco_empty_ero_action.pceea_send_err
#define pco_empty_ero_path_tear_down      pco_empty_ero_action.pceea_path_tear_down
#define pco_empty_ero_routing_decision    pco_empty_ero_action.pceea_routing_decision

typedef enum pce_state {
    PCE_STATE_DELETED,
    PCE_STATE_NEW,
    PCE_STATE_RECONNECT,
    PCE_STATE_CONNECTING,
    PCE_STATE_CONNECTED,
    PCE_STATE_SYNC,
    PCE_STATE_UP,
} pce_state_t;

struct pce_cfg {
    char                     pce_id[PCCD_PCE_ID_MAX];
    struct pce_common_opts   pce_opts;
    struct pce_group_cfg    *pce_pce_group;
    union {
        struct in_addr       v4;
        struct in6_addr      v6;
    } pce_local_addr;
    union {
        struct in_addr       v4;
        struct in6_addr      v6;
    } pce_dest_addr;
    bool                     is_ipv6_session;
    bool                     is_local_v6_configured;
    uint16_t                 pce_dest_port;
    unsigned short           pce_delegation_prio;
    unsigned short           pce_request_prio;
    unsigned short           pce_deleg_setup_timeout;
    unsigned int             pce_deleg_cleanup_timeout;
    bool                     pce_lsp_provisioning;
    bool                     pce_p2mp_lsp_report_capability;
    bool                     pce_p2mp_lsp_update_capability;
    bool                     pce_p2mp_lsp_init_capability;
	bool					 pce_spring_capability;
    bool                     pce_srv6_capability;
    unsigned int             pce_lsp_cleanup_timer;
    int                      pce_index;
	bool      		         pce_session_critical_config_modify;
    bool                     pce_flowspec_capability;           /* FlowSpec Capability */
    bool                     pce_multipath_capability;
    uint16_t                 pce_num_multipaths;
    bool                     pce_tls_enabled;
    bool                     pce_disjoint_assoc_capability;
    /* tracing TBD */

    pcePcepEntityTable_data_t *entity_table;
    pcePcepPeerTable_data_t *peer_table;
    pcePcepSessTable_data_t *sess_table;

};

/*
 * LSP Vector type
 */

#define LSP_VECTOR_P2P                                              1
#define LSP_VECTOR_P2MP_CLI_REGULAR              2
#define LSP_VECTOR_P2MP_EXTERNALLY_PROV   3

struct pccd_flowspec_info_s;
SLIST_HEAD(pccd_flowspec_info_head, pccd_flowspec_info_s);

struct lsp_vector {
    patnode_t                      lv_patricia_id;
    uint32_t                       lv_lsp_id;
    uint32_t                       srp_id; // SRP ID for pce initiated lsp
    bool			   ack; //acknowledgement flag for PCReport
    struct pce_cfg_core            *lv_pce;
    bool                           lv_want_to_delegate; // request for delegation made
    bool                           lv_ack_delegated;    // lsp delegation was accepted
    uint8_t                        lv_type;    // lsp is p2p, p2mp local or p2mp exteranally provisoned
    bool                           lv_retry_delegation; // re-try delegation of LSP 
    uint8_t                        lv_delegation_failed;// delegation failure counter
    evTimerID                      lv_delegation_setup_tid;   // timer for LSP delegation retry
    evTimerID                      lv_lsp_cleanup_tid;  // timer for LSP cleanup
    evTimerID                      lv_lsp_delegation_retry_tid; // timer for LSP delegation after re-delegation
    SLIST_ENTRY(lsp_vector)        lv_pce_lsps;         /*< SLIST node in pce_cfg_core list of LSPs */
    struct pccd_flowspec_info_head  lv_flowspec_info_head;   /*< SLIST head of flowspec's>*/
    bool                           fs_rpd_pend_upd; /*< RPD update is pending */

    /**
     * To directly refer to the current pcc created fs id in use to map new
     * locally configured prefixes
     */
    uint32_t                       lv_curr_pcc_fs_id_in_use;

    /* To know the count of flowspecs mapped to this lsp vector */
    int8_t                         lv_mapped_flows_count;

    /**
     * To know whether pccd need to create fs for prefixes or not in
     * Cases:
     * 1. Always for local lsp if not created already
     * 2. After pccd restart for externally controlled/provisioned lsp
     */
    uint8_t                        lv_need_to_create_fs;
};
SLIST_HEAD(lsp_vector_head, lsp_vector);

PATNODE_TO_STRUCT(pccd_lsp_id_patnode_to_lv, struct lsp_vector, lv_patricia_id);

#define PCCD_ALL_LSP_VECTOR(lv)     \
  {struct lsp_vector * __next = 0;	\
  for( lv = (struct lsp_vector *)patricia_lookup_least( pccd_lsp_vector_root_id ) ;\
       lv; lv = __next ){ \
         __next = (struct lsp_vector  *)patricia_get_next(pccd_lsp_vector_root_id, \
                                               &lv->lv_patricia_id);

#define PCCD_ALL_LSP_VECTOR_END(lv) } }


/* Extending configuration's pce_cfg */
struct pce_cfg_core {
    struct pce_cfg                   pc_pce;
    struct pcep_connect_parameters   pc_params;
    /* Local attributes */
    pce_state_t                      pc_state;
    struct pcep_conn                *pc_conn;
    evTimerID                        pc_reconnect_timer;
    evTimerID                        pc_delegation_cleanup_tid; /*< Delegation cleanup timeout timer */
    evTimerID                        pc_set_new_main_pce_tid; /*< Set new main pce timer */
    unsigned short                   pc_reconnect_sec; /*< How much seconds to wait for new PCE reconnect attempt */
    unsigned short                   pc_reconnects; /*< How many times this PCE tried to reconnect. Does not roll */
#define    PCE_CFG_LOW_RECONNECT_SEC 2 /* Lowest reconnection timer in seconds */
#define    PCE_CFG_MAX_RECONNECT_SEC 16    /* The maximum time in seconds to wait between reconnects to PCE */
    SLIST_ENTRY(pce_cfg_core)        pc_next; /*< Node in pce_cfg_head list */
    struct lsp_vector_head           pc_lsps;
    unsigned int                     pc_lsps_count;
    bool                             pc_main; /*< This PCE selected as main ? */
    struct pce_statistics            pc_statistics; /*< counters for this PCE */
    int objects_stack;
    int objects_lsps_stack;
    struct pcep_object *objs_stack;
    patroot                          *pccd_flowspec_info_root;
};

typedef struct pccd_pce_err_type_val_s {
    uint8_t	pce_err_type;
    uint8_t	pce_err_val;
}pccd_pce_err_type_val_t;

void
pccd_core_update_pce_list (struct pce_cfg *pec);
int
pccd_core_created_pce(struct pce_cfg *pec);
int
pccd_core_deleted_pce(struct pce_cfg *pec);
void
pccd_core_reload_pce(struct pce_cfg *pec);
void
pccd_core_reload_all_sr_pces(void);
void
pccd_core_reload_all_srmpls_pces(void);
void
pccd_core_reload_all_srv6_pces(void);
void
pccd_core_delete_all_pces(void);
void
pccd_core_delete_all_provisioned_lsps(void);

bool
pccd_core_get_pce_type (struct pce_cfg *pec);

struct pce_cfg*
pccd_core_alloc_pce_cfg(const char pce_id[PCCD_PCE_ID_MAX]);
struct pce_cfg*
pccd_core_get_pce_cfg(const char *pce_id);

struct pce_cfg_core *
pccd_core_get_pce_cfg_core(const char *pce_id);

void
pccd_core_pce_cfg_pce_id(struct pce_cfg *pce, const char pce_id[PCCD_PCE_ID_MAX]);

void
pccd_core_pce_cfg_statefullness(struct pce_cfg *pce, pce_type_t pce_type);

void
pccd_core_pce_cfg_lsp_provisioning(struct pce_cfg *pce, bool lsp_provisioning);

void
pccd_core_pce_cfg_p2mp_lsp_report_capability(struct pce_cfg *pce, bool p2mp_lsp_report_capability);

void
pccd_core_pce_cfg_spring_capability(struct pce_cfg *pce, bool spring_capability);

void
pccd_core_pce_cfg_srv6_capability(struct pce_cfg *pce, bool srv6_capability);

void
pccd_core_pce_cfg_disable_tlv_path_binding(struct pce_cfg *pce, bool disable_tlv_path_bind);

void
pccd_core_pce_cfg_p2mp_lsp_update_capability(struct pce_cfg *pce, bool p2mp_lsp_update_capability);

void
pccd_core_pce_cfg_p2mp_lsp_init_capability(struct pce_cfg *pce, bool p2mp_lsp_init_capability);

void
pccd_core_pce_cfg_lsp_cleanup_timer(struct pce_cfg *pce, u_int lct);

void
pccd_core_auth_keychain(struct pce_cfg *pce,
                        const char auth_keychain[PCCD_AUTH_KEYCHAIN_MAX]);
void
pccd_core_auth_algorithm(struct pce_cfg *pce,
                         const char auth_algorithm[PCCD_AUTH_ALGORITHM_MAX]);
void
pccd_core_auth_key(struct pce_cfg *pce, const char auth_key[PCCD_AUTH_KEY_MAX]);

void
pccd_core_pce_cfg_local_timers(struct pce_cfg *pce,
                               const struct pce_local_timers *timers);

void
pccd_core_pce_cfg_remote_timers(struct pce_cfg *pce,
                                const struct pce_remote_timers *timers);

void
pccd_core_pce_cfg_request_timer(struct pce_cfg *pce, u_short rt);

void
pccd_core_pce_cfg_max_unknown_requests(struct pce_cfg *pce, unsigned rqsts);

void
pccd_core_pce_cfg_max_unknown_mesgs(struct pce_cfg *pce, unsigned msgs);

void
pccd_core_pce_cfg_no_advertise_own_lsps(struct pce_cfg *pce, bool no_advertise);

void
pccd_core_pce_cfg_delegation_cleanup_timeout(struct pce_cfg *pce, u_int secs);
void
pccd_core_pce_cfg_lsp_retry_delegation(struct pce_cfg *pce, bool retry_delegation);
void
pccd_core_pce_cfg_delegation_retry_timeout(struct pce_cfg *pce, u_short secs);
void
pccd_core_pce_cfg_delegation_setup_timeout(struct pce_cfg *pce, u_short secs);

void
pccd_core_pce_cfg_local_addr(struct pce_cfg *pce, struct in_addr *addr);

void
pccd_core_pce_cfg_local_v6_addr(struct pce_cfg *pce, struct in6_addr *addr);

void
pccd_core_pce_cfg_dest_addr(struct pce_cfg *pce, struct in_addr *addr);

void
pccd_core_pce_cfg_dest_v6_addr(struct pce_cfg *pce, struct in6_addr *addr);

void
pccd_core_pce_cfg_tcp_port(struct pce_cfg *pce, uint16_t port);

void
pccd_core_pce_cfg_delegation_priority(struct pce_cfg *pce, u_short prio);

void
pccd_core_pce_cfg_request_priority(struct pce_cfg *pce, u_short prio);

void
pccd_core_pce_cfg_trace_protocol(struct pce_cfg *pce, daemon_trace_file_options_t *dtfo);

void
pccd_alloc_msg_rate_buffer(unsigned limit);

void
pccd_alloc_upd_rate_buffer(unsigned limit);

void
pccd_set_max_provisioned_lsps(unsigned limit);

int
pccd_core_init(evContext ctx);

struct pce_cfg_core;

bool
pccd_core_clear_statistics(struct pce_cfg_core *pce);

bool
is_bit_set(unsigned value, unsigned bit_index);

bool
pccd_core_del_lspvec_senderr (uint32_t lsp_id, bool delete,
                              bool send_err,
			      pccd_pce_err_type_val_t err);

void
pccd_core_delete_lsp(struct lsp_vector *lsp);

void
pccd_core_disconnect_all_pces(void);

void
pccd_core_move_all_pces_to_up(void);

int
pccd_core_delegation_retry_by_lsp_name(char* lsp_name);

void
pccd_core_construct_ero_info(char *hops, uint32_t buffer_size,void *r_info);

void
pccd_core_construct_rro_info(char *hops, uint32_t buffer_size, void *r_info);

void
pccd_core_construct_sr_ro_info(char *hops, uint32_t buffer_size, void *r_info);

void
pccd_core_construct_srv6_ro_info(char *hops, uint32_t buffer_size, void *r_info);

struct lsp_vector *
pccd_core_get_lsp_vec_by_lsp_id(uint32_t lsp_id);

const char *
pccd_core_get_pcupdate_empty_ero_action_str(struct pce_cfg_core *);

void
pccd_pce_entity_table_create (struct pce_cfg *pce);

void
pccd_core_set_rfc8231_compliance (bool val);

void
pccd_set_multipath_capability(bool value);

void
pccd_set_disjoint_assoc_capability(bool value);

void
pccd_set_maxsegment_list_propagation(bool value);

void
pccd_set_tls_enable (bool value);

void
pccd_core_pce_cfg_tls_wait_timer(struct pce_cfg *pce, uint8_t timer_val);

int
pccd_core_report_deleted_lsp(struct pce_cfg_core *pce,
    const struct pccd_rpd_lsp_info *rpd_lsp, uint32_t srp_id);

bool
pccd_core_has_any_spring_pce(void);

bool
pccd_core_has_any_srv6_pce(void);

void
pccd_core_get_bandwidth_str(uint64_t bits, char* bw_str, uint32_t buffer_size);

void
pccd_core_pce_set_delegation_cleanup_timer(struct pce_cfg_core *pce);

/* NSR Begin */
void
pccd_core_connect_all_pces(void);

void
pccd_core_provisioned_lsps_increase_counter(void);

void
pccd_core_provisioned_lsps_decrease_counter(void);

void
pccd_core_store_lsp(struct pce_cfg_core *pce, uint32_t lsp_id, uint32_t srp_id, 
                    bool created, uint8_t vec_type);

void
pccd_core_update_lsp_delegation (struct pccd_rpd_lsp_info *rpd_lsp);

void
pccd_core_return_control(const struct pccd_rpd_lsp_info *rpd_lsp);

void
pccd_core_copy_intended_attributes (struct lsp_intended_attr_s *intended_attrs,
                                    const struct pccd_rpd_lsp_info *rpd_lsp);
/* NSR End */

uint32_t
pccd_core_pcc_fs_id_alloc(struct pce_cfg_core* pce);

void
pccd_core_tmp_prefix_data_cleanup(struct pccd_flowspec_info_head  *tmp_lv_fs_info_head,
                               radix_root_t *tmp_lsp_prefix_tree_root);

void
pccd_core_update_flowspec_prefix(const struct pccd_rpd_lsp_info *rpd_lsp,
              struct lsp_vector* lsp_vec, boolean* is_notify);

void
pccd_core_lsp_transfer(struct pce_cfg_core *src, struct pce_cfg_core *dst,
                       struct lsp_vector *vec);

bool
pccd_core_validate_p2mp_symbolic_name (char *received_name, char* p2mp_name);


#endif /* PCCD_CORE_H_ */
