/*
 * $Id: pccd_rpd_ipc.c 1332071 2023-04-25 18:01:55Z gchandraseka $
 *
 * Contains encoding/decoding of messages to/from rpd.
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */
#include <unistd.h>
#include <sys/errno.h>

#include <jnx/aux_types.h>
#include <jnx/jsockaddr.h>
#include <jnx/librpd/shared.h>
#include <jnx/librpd/lspinfo.h>
#include <jnx/librpd/librpd.h>
#include <jnx/librpd/ipc_rpd.h>
#include <jnx/getput.h>
#include <jnx/ppm/rpc_proto.h>

#include "pccd_xmalloc.h"
#include "pccd_log.h"
#include "pccd_trace.h"
#include "pccd_rpd_ipc.h"
#include "pccd_ret_code.h"
#include "pccd_rpd.h"

#define PCCD_RPD_CLIENT_ID "pccd"

#define MAX_AVAILABLE_ERO_IN_TX_BUFFER 10
#define MAX_MSG_HEADER_SIZE 1024
#define TX_BUFFER_LEN 65535
u_int8_t tx_buffer_ptr[TX_BUFFER_LEN];

/* Buffer location to store received fragmented data */
static uint8_t *frag_recv_buf = NULL, *current_frag_buf_ptr = NULL;
static uint32_t message_id_counter = 1, current_message_id = 0, recent_frag_id = 0;

static void
print_assoc_info(lsp_association_info *info,
                        u_int32_t num_assoc_info)
{
    char assoc_src_str[INET6_ADDRSTRLEN], endpoint_str[INET6_ADDRSTRLEN], originator_str[INET6_ADDRSTRLEN];
    u_int32_t count = 0;
    while (count < num_assoc_info) {
        memset(assoc_src_str, 0, INET6_ADDRSTRLEN);
        memset(endpoint_str, 0, INET6_ADDRSTRLEN);
        memset(originator_str, 0, INET6_ADDRSTRLEN);

        if (!info->is_assoc_src_ipv6) {
            struct in_addr assoc_src_addr, endpoint_addr, originator_addr;
            assoc_src_addr.s_addr = (in_addr_t) info->assoc_source_u.v4;
            endpoint_addr.s_addr = (in_addr_t) info[count].sr_srpag_t.srpag_endpoint_addr_u.v4;
            originator_addr.s_addr = (in_addr_t) info[count].sr_srpag_t.originator_addr_u.v4;
            memcpy(assoc_src_str, inet_ntoa(assoc_src_addr), 20);
            memcpy(endpoint_str, inet_ntoa(endpoint_addr), 20);
            memcpy(originator_str, inet_ntoa(originator_addr), 20);
        } else {
            struct in6_addr assoc_srcv6_addr, endpointv6_addr, originatorv6_addr;
            memcpy(&assoc_srcv6_addr, info->assoc_source_u.v6, 16);
            memcpy(&endpointv6_addr, info[count].sr_srpag_t.srpag_endpoint_addr_u.v6, 16);
            memcpy(&originatorv6_addr, info[count].sr_srpag_t.originator_addr_u.v6, 16);
            inet_ntop(AF_INET6, &assoc_srcv6_addr, assoc_src_str, sizeof(assoc_src_str));
            inet_ntop(AF_INET6, &endpointv6_addr, endpoint_str, sizeof(endpoint_str));
            inet_ntop(AF_INET6, &originatorv6_addr, originator_str, sizeof(originator_str));
        }

        TRACE_RPD(" grp_id  %u type %u is assoc source ipv6 %d assoc_source %s",
            info[count].assoc_grp_id,
            info[count].assoc_type,
            info[count].is_assoc_src_ipv6,
            assoc_src_str);

        TRACE_RPD("Total: %u , count: %u grp_id  %u",
            num_assoc_info, count, info[count].assoc_grp_id);
        if (info[count].assoc_flags & LSP_PATH_TYPE_PRIMARY) {
            TRACE_RPD("Primary Path ");
        }
        if (info[count].assoc_flags & LSP_PATH_TYPE_SECONDARY) {
            TRACE_RPD("Secondary Path ");
        }

        if ( info[count].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG ) {
            TRACE_RPD(" color %u is endpoint ipv6 %d endpoint %s "
                "sr_proto_origin %u originator asn %u is originator addr ipv6 %d "
                "originator ip %s discriminator %u ",
            info[count].sr_srpag_t.color,
            info[count].sr_srpag_t.is_srpag_endpoint_ipv6,
            endpoint_str,
            info[count].sr_srpag_t.sr_proto_origin,
            info[count].sr_srpag_t.originator_asn,
            info[count].sr_srpag_t.is_srpag_originator_ipv6,
            originator_str,
            info[count].sr_srpag_t.discriminator );

            if (info[count].sr_srpag_t.preference_valid) {
                TRACE_RPD(" preference %u", info[count].sr_srpag_t.preference);
            }
        }
        count++;
    }
}

static void
print_div_assoc_info(lsp_association_info *info,
                        u_int32_t num_div_assoc_info)
{
    char assoc_src_str[INET6_ADDRSTRLEN], endpoint_str[INET6_ADDRSTRLEN], originator_str[INET6_ADDRSTRLEN];
    u_int32_t count = 0;
    while (count < num_div_assoc_info) {
        memset(assoc_src_str, 0, INET6_ADDRSTRLEN);
        memset(endpoint_str, 0, INET6_ADDRSTRLEN);
        memset(originator_str, 0, INET6_ADDRSTRLEN);

        if (!info->is_assoc_src_ipv6) {
            struct in_addr assoc_src_addr, endpoint_addr, originator_addr;
            assoc_src_addr.s_addr = (in_addr_t) info->assoc_source_u.v4;
            endpoint_addr.s_addr = (in_addr_t) info[count].sr_srpag_t.srpag_endpoint_addr_u.v4;
            originator_addr.s_addr = (in_addr_t) info[count].sr_srpag_t.originator_addr_u.v4;
            memcpy(assoc_src_str, inet_ntoa(assoc_src_addr), 20);
            memcpy(endpoint_str, inet_ntoa(endpoint_addr), 20);
            memcpy(originator_str, inet_ntoa(originator_addr), 20);
        } else {
            struct in6_addr assoc_srcv6_addr, endpointv6_addr, originatorv6_addr;
            memcpy(&assoc_srcv6_addr, info->assoc_source_u.v6, 16);
            memcpy(&endpointv6_addr, info[count].sr_srpag_t.srpag_endpoint_addr_u.v6, 16);
            memcpy(&originatorv6_addr, info[count].sr_srpag_t.originator_addr_u.v6, 16);
            inet_ntop(AF_INET6, &assoc_srcv6_addr, assoc_src_str, sizeof(assoc_src_str));
            inet_ntop(AF_INET6, &endpointv6_addr, endpoint_str, sizeof(endpoint_str));
            inet_ntop(AF_INET6, &originatorv6_addr, originator_str, sizeof(originator_str));
        }

        TRACE_RPD(" grp_id  %u type %u is assoc source ipv6 %d assoc_source %s",
            info[count].assoc_grp_id,
            info[count].assoc_type,
            info[count].is_assoc_src_ipv6,
            assoc_src_str);

        if (info->disjoint_assoc_list.assoc_conf_info_valid) {
            TRACE_RPD(" CONF-Flags-%u %u %u %u %u", info->disjoint_assoc_list.assoc_conf_info.link_diverse,
                      info->disjoint_assoc_list.assoc_conf_info.node_diverse,
                      info->disjoint_assoc_list.assoc_conf_info.srlg_diverse,
                      info->disjoint_assoc_list.assoc_conf_info.strictness,
                      info->disjoint_assoc_list.assoc_conf_info.shortest_first);
        }
        if (info->disjoint_assoc_list.assoc_status_info_valid) {
            TRACE_RPD(" STATUS-Flags-%u %u %u %u %u", info->disjoint_assoc_list.assoc_status_info.link_diverse,
                      info->disjoint_assoc_list.assoc_status_info.node_diverse,
                      info->disjoint_assoc_list.assoc_status_info.srlg_diverse,
                      info->disjoint_assoc_list.assoc_status_info.strictness,
                      info->disjoint_assoc_list.assoc_status_info.shortest_first);
        }
        count++;
    }
}


/**
 * pccd_rpd_is_update_received_for_existing_lsp
 *
 * To find if update recived from RPD corresponds to the same LSP or not
 *
 * @param[in] existing_setup_type    :   
 *            existing_sub_type      :
 *            existing_is_p2mp       :
 *            recv_setup_type        : 
 *            recv_sub_type          :
 *            recv_is_p2mp           :
 *
 * @return  Returns true, if update is received for existing LSP.
 *          Returns false, if new LSP is received
 */
static bool
pccd_rpd_is_update_received_for_existing_lsp(uint8_t existing_setup_type,
    uint8_t existing_sub_type, bool existing_is_p2mp, uint8_t recv_setup_type, 
    uint8_t recv_sub_type, bool recv_is_p2mp)
{
    bool is_existing_lsp = true;
    if((existing_setup_type != recv_setup_type) || 
        (existing_sub_type != recv_sub_type) ||
        (existing_is_p2mp != recv_is_p2mp)) {
        is_existing_lsp = false;
    }
    return is_existing_lsp;
}


/**
 * Decode a pcrequest message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] pcrequest_msg Decoded pcrequest message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
static boolean
pccd_rpd_decode_pcrequest(u_int8_t *msg_data, u_int32_t msg_length,
                          rpd_msg_pcrequest_status_t *pcrequest_msg)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int8_t *tlv_8bit_data;
    u_int32_t bwh, bwl;
    u_int tlv_len;
    rpd_extctrl_lsp_config_status_info_t *lcs;
    lsp_type_info_t *lsp_type_info;

    if (!pcrequest_msg) {
        TRACE_RPD("pccd_rpd_decode_pcrequest: message is empty");
        return FALSE;
    }

    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));
    lcs = &pcrequest_msg->lsp_config_status;
    lsp_type_info = &lcs->lsp_type_info;

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest: EXTCTRL_TLV_MAX");
        return FALSE;
    }

    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest: TLV EXTCTRL_TLV_CONTEXT absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:TLV EXTCTRL_TLV_CONTEXT tlv length: %d", tlv_len);
        return FALSE;
    }
    pcrequest_msg->context = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_RETURN_CODE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest: EXTCTRL_TLV_RETURN_CODE absent ");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_RETURN_CODE tlv length: %d", tlv_len);
        return FALSE;
    }
    pcrequest_msg->return_code = get_short(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_NAME absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lcs->name)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_NAME tlv length: %d", tlv_len);
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    strncpy(lcs->name, tlv_var_data, sizeof(lcs->name));
    lcs->name[sizeof(lcs->name) - 1] = '\0';

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->path_name)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_PATH_NAME tlv length: %d", tlv_len);
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lcs->path_name, tlv_var_data, sizeof(lcs->path_name));
        lcs->path_name[sizeof(lcs->path_name) - 1] = '\0';
    } else {
        bzero(lcs->path_name, sizeof(lcs->path_name));
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_ACTIVE_PATH_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->active_path_name)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_ACTIVE_PATH_NAME tlv length: %d", tlv_len);
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lcs->active_path_name, tlv_var_data, sizeof(lcs->active_path_name));
        lcs->active_path_name[sizeof(lcs->active_path_name) - 1] = '\0';
    } else {
        bzero(lcs->active_path_name, sizeof(lcs->active_path_name));
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_TEMPLATE_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->template_name)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_PATH_TEMPLATE_NAME tlv length: %d", tlv_len);
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lcs->template_name, tlv_var_data, sizeof(lcs->template_name));
        lcs->template_name[sizeof(lcs->template_name) - 1] = '\0';
    } else {
        bzero(lcs->template_name, sizeof(lcs->template_name));
    }

    tlv = tlv_array[EXTCTRL_TLV_MSG_TRIGGER_REASON];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_MSG_TRIGGER_REASON absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_MSG_TRIGGER_REASON tlv length: %d", tlv_len);
        return FALSE;
    }
    lcs->msg_trigger_reason = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_LSP_TYPE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_TYPE absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_TYPE tlv length: %d", tlv_len);
        return FALSE;
    }
    lcs->type = get_short(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_LSP_STATE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_STATE absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_LSP_STATE tlv length: %d", tlv_len);
        return FALSE;
    }
    lcs->state = get_short(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_CONTROL_STATUS];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:001");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:002");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->control_status = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_LSP_FLAGS];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:003");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:004");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->lsp_flags = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    lcs->relcsi_admin_grp_exclude_any = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    lcs->relcsi_admin_grp_include_any = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    lcs->relcsi_admin_grp_include_all = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_CONF_SETUP_PRIO];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:005");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:006");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->configured_setup_prio = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_CONF_HOLD_PRIO];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:007");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:008");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->configured_hold_prio = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_SETUP_PRIO];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:009");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0010");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->setup_prio = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_HOLD_PRIO];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0011");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0012");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->hold_prio = *tlv_8bit_data;

    tlv = tlv_array[EXTCTRL_TLV_BANDWIDTH];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0013");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int64_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0014");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bwh = get_long(tlv_var_data);
    bwl = get_long(tlv_var_data + 4);
    lcs->bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;

    tlv = tlv_array[EXTCTRL_TLV_LSP_ID];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->lsp_id)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:0015");
            return FALSE;
        }
        lcs->lsp_id = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_TUNNEL_ID];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->tunnel_id)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:0016");
            return FALSE;
        }
        lcs->tunnel_id = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_CONF_BANDWIDTH];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0017");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int64_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0018");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bwh = get_long(tlv_var_data);
    bwl = get_long(tlv_var_data + 4);
    lcs->configured_bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;


    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0019");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0020 tlv len: %d", tlv_len);
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lsp_type_info->setup_type = *tlv_8bit_data;
    TRACE_RPD("pccd_rpd_decode_pcrequest: setup_type: %d", lsp_type_info->setup_type);

    tlv = tlv_array[EXTCTRL_TLV_SRC_DEST_ADDR_TYPE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0019.1");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:0019.1 tlv len: %d", tlv_len);
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    if (*tlv_8bit_data) {
        lcs->is_lsp_src_dst_addr_type_ipv6 = true;
    } else {
        lcs->is_lsp_src_dst_addr_type_ipv6 = false;
    }
    TRACE_RPD("pccd_rpd_decode_pcrequest: src_dest_ip_type_ipv6: %d", lcs->is_lsp_src_dst_addr_type_ipv6);

    tlv = tlv_array[EXTCTRL_TLV_DEST_ADDR];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_DEST_ADDR absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    tlv_var_data = rpc_proto_tlv_data(tlv);
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_DEST_ADDR tlv length: %d", tlv_len);
            return FALSE;
        }
        bcopy(tlv_var_data, &lcs->dstaddr_u.v4, tlv_len);
    } else {
        if (tlv_len != 16) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_IPV6_DEST_ADDR tlv length: %d", tlv_len);
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->dstaddr_u.v6, tlv_len);
    }

    tlv = tlv_array[EXTCTRL_TLV_SRC_ADDR];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_SRC_ADDR absent");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    tlv_var_data = rpc_proto_tlv_data(tlv);
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_SRC_ADDR tlv length: %d", tlv_len);
            return FALSE;
        }
        bcopy(tlv_var_data, &lcs->srcaddr_u.v4, tlv_len);
    } else {
        if (tlv_len != 16) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:EXTCTRL_TLV_IPV6_SRC_ADDR tlv length: %d", tlv_len);
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->srcaddr_u.v6, tlv_len);
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
    tlv = tlv_array[EXTCTRL_TLV_ERO_INFO];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->ero_info  = xmalloc(tlv_len);
        if (!lcs->ero_info) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:021");
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->ero_info, tlv_len);
        lcs->ero_len = tlv_len;
    }
    } else if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
            (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest: %d", lsp_type_info->setup_type);
        tlv = tlv_array[EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT];
        if (tlv) {
            tlv_8bit_data = rpc_proto_tlv_data(tlv);
            lcs->srte_total_ero_count = *tlv_8bit_data;
        } else {
            lcs->srte_total_ero_count = 0;
        }
        tlv = tlv_array[EXTCTRL_TLV_SRTE_MAX_SEGMENT_LIST_INFO];
        if (tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            if (tlv_len != sizeof(lcs->max_segment_list)) {
                TRACE_RPD("Invalid max computed segment list size");
                return FALSE;
            }
            lcs->max_segment_list = get_short(rpc_proto_tlv_data(tlv));
        } else {
            lcs->max_segment_list = 0;
        }
        tlv = tlv_array[EXTCTRL_TLV_SRTE_ERO_INFO];
        if (tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            tlv_var_data = rpc_proto_tlv_data(tlv);
            lcs->srte_ero_info  = xmalloc(tlv_len);
            if (!lcs->srte_ero_info) {
                TRACE_RPD("pccd_rpd_decode_pcrequest: memory allocation dailed for srte ero info");
                return FALSE;
            }
            lcs->srte_ero_len = tlv_len;
            bcopy(tlv_var_data, lcs->srte_ero_info, tlv_len);
        } else {
            lcs->srte_ero_info = NULL;
        }
        TRACE_RPD(" rpd->pccd decode operation. Lsp %s - "
                  "Total eros: %u max_segment_list: %u ero_validity: %s",
                  lcs->name, lcs->srte_total_ero_count,
                  lcs->max_segment_list, lcs->srte_ero_info ? "Valid": "Invalid");
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
    TRACE_RPD("pccd_rpd_decode_pcrequest: setup type: %u", lsp_type_info->setup_type);
    tlv = tlv_array[EXTCTRL_TLV_RRO_INFO];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->rro_info  = xmalloc(tlv_len);
        if (!lcs->rro_info) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:023");
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->rro_info, tlv_len);
        lcs->rro_len = tlv_len;
    }
    } else if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
               (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        tlv = tlv_array[EXTCTRL_TLV_SRTE_TOTAL_RRO_COUNT];
        if (tlv) {
            tlv_8bit_data = rpc_proto_tlv_data(tlv);
            lcs->srte_total_rro_count = *tlv_8bit_data;
        } else {
            lcs->srte_total_rro_count = 0;
        }
        tlv = tlv_array[EXTCTRL_TLV_SRTE_RRO_INFO];
        if (tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            tlv_var_data = rpc_proto_tlv_data(tlv);
            lcs->srte_rro_info  = xmalloc(tlv_len);
            if (!lcs->srte_rro_info) {
                TRACE_RPD("pccd_rpd_decode_pcrequest: memory allocation failed for srte rro info");
                return FALSE;
            }
            lcs->srte_rro_len = tlv_len;
            bcopy(tlv_var_data, lcs->srte_rro_info, tlv_len);
        } else {
            lcs->srte_rro_info = NULL;
        }
        TRACE_RPD(" rpd->pccd decode operation. Lsp %s - "
                  "Total rros: %u rro_validity: %s",
                  lcs->name, lcs->srte_total_rro_count,
                  lcs->srte_rro_info ? "Valid": "Invalid");
    }

    tlv = tlv_array[EXTCTRL_TLV_ERRORSPECOBJ];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
	if (tlv_len) {
	    lcs->error_spec_obj  = xmalloc(tlv_len);
	    memcpy(lcs->error_spec_obj, tlv_var_data, tlv_len);
	    lcs->error_spec_obj_len = tlv_len;
	}
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_FLAG];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:025");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest:026");
        return FALSE;
    }
    lcs->path_flags = get_short(rpc_proto_tlv_data(tlv));
    TRACE_RPD("received path_flags: 0x%x", lcs->path_flags);

    tlv = tlv_array[EXTCTRL_TLV_NUM_ASSOCIATION_INFO];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->num_assoc_info)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:027");
            return FALSE;
        }
        lcs->num_assoc_info = get_short(rpc_proto_tlv_data(tlv));
    }

    if (lcs->num_assoc_info) {
        tlv = tlv_array[EXTCTRL_TLV_ASSOCIATION_INFO];
        if (tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            if (tlv_len > sizeof(lcs->assoc_info)) {
                return FALSE;
            }
            tlv_var_data = rpc_proto_tlv_data(tlv);
            memcpy(lcs->assoc_info, tlv_var_data, tlv_len);
            print_assoc_info(lcs->assoc_info, lcs->num_assoc_info);
        }
    }

    tlv = tlv_array[EXTCTRL_TLV_DISJOINT_ASSOC_INFO_COUNT];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->div_assoc_info_count)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:div_assoc_info");
            return FALSE;
        }
        lcs->div_assoc_info_count = get_long(rpc_proto_tlv_data(tlv));
    }
    TRACE_RPD("DAG: RPD->PCCD: Number of div assoc info count %s %u",
              lcs->name, lcs->div_assoc_info_count);
    if (lcs->div_assoc_info_count > MAX_DISJOINT_ASSOC_INFO) {
        TRACE_RPD("DAG: RPD->PCCD: received more than 8 diversity assoc group."
                  "Ignoring the message from RPD");
        return FALSE;
    }
    if (lcs->div_assoc_info_count) {
        tlv = tlv_array[EXTCTRL_TLV_DISJOINT_ASSOC_INFO];
        if (tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            if (tlv_len > (sizeof(lsp_association_info) * lcs->div_assoc_info_count)) {
                TRACE_RPD("DAG: RPD->PCCD: unexpected size of tlv data");
                return FALSE;
            }
            tlv_var_data = rpc_proto_tlv_data(tlv);
            lcs->div_assoc_info = xmalloc(sizeof(lsp_association_info) * lcs->div_assoc_info_count);
            memcpy(lcs->div_assoc_info, tlv_var_data, tlv_len);
            print_div_assoc_info(lcs->div_assoc_info, lcs->div_assoc_info_count);
        }
    }

    tlv = tlv_array[EXTCTRL_TLV_PATH_PRIORITY];
    if( tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:028");
            return FALSE;
        }
        lcs->path_priority = get_long(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_PATH_AUTO_BANDWIDTH];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int64_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:029");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bwh = get_long(tlv_var_data);
        bwl = get_long(tlv_var_data + 4);
        lcs->auto_bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;
    }

    lcs->metric_valid = FALSE;
    tlv = tlv_array[EXTCTRL_TLV_LSP_METRIC];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            return FALSE;
        }
        lcs->metric = get_long(rpc_proto_tlv_data(tlv));
        lcs->metric_valid = TRUE;
    }

    /*P2mp*/

    lcs->p2mp_mbb_flag = 0;
    tlv = tlv_array[EXTCTRL_TLV_P2MP_MBB_FLAG];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->num_paths)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:032");
            return FALSE;
        }
        lcs->p2mp_mbb_flag = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_P2MP_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->p2mp_name)) {
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lcs->p2mp_name, tlv_var_data, sizeof(lcs->p2mp_name));
        lcs->p2mp_name[sizeof(lcs->p2mp_name) - 1] = '\0';
    } else {
        bzero(lcs->p2mp_name, sizeof(lcs->p2mp_name));
    }

    tlv = tlv_array[EXTCTRL_TLV_P2MP_ID];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            return FALSE;
        }
        lcs->p2mp_id = get_long(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_NUM_PATHS];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->num_paths)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:032");
            return FALSE;
        }
        lcs->num_paths = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_TE_PATH_BINDING_TYPE];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int16_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:033");
            return FALSE;
        }
        lcs->lsp_binding_sid.binding_type = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_TE_PATH_BINDING_VAL];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("pccd_rpd_decode_pcrequest:034");
            return FALSE;
        }
        lcs->lsp_binding_sid.binding_value = get_long(rpc_proto_tlv_data(tlv));
    }

    /* PCE Initiated Bypass : begin */ 
    tlv = tlv_array[EXTCTRL_TLV_BYP_PRIMARY_NHOP];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("Invalid TLV length %u for EXTCTRL_TLV_BYP_PRIMARY_NHOP", 
                      tlv_len);
            return FALSE;
        }
        lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr = get_long(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_PROT_TYPE];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("Invalid TLV length %u for EXTCTRL_TLV_BYP_PROT_TYPE", 
                      tlv_len);
            return FALSE;
        }
        lcs->rbyp_params.rbp_prot_type = get_long(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_SUBSCR];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("Invalid TLV length %u for EXTCTRL_TLV_BYP_SUBSCR", 
                      tlv_len);
            return FALSE;
        }
        lcs->rbyp_params.rbp_subscr = get_long(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_IN_USE];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("Invalid TLV length %u for EXTCTRL_TLV_BYP_IN_USE", 
                      tlv_len);
            return FALSE;
        }
        lcs->rbyp_state.rbs_in_use = get_long(rpc_proto_tlv_data(tlv));
    }    
    /* PCE Initiated Bypass : end */
    if((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
       (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
        if(tlv) {
            tlv_len = rpc_proto_tlv_data_length(tlv);
            if (tlv_len != sizeof(u_int8_t)) {
                TRACE_RPD("pccd_rpd_decode_pcrequest:sub_type tlv len: %d", tlv_len);
                return FALSE;
            }
            tlv_8bit_data = rpc_proto_tlv_data(tlv);
            lsp_type_info->sub_type = *tlv_8bit_data;
            TRACE_RPD("pccd_rpd_decode_pcrequest: sub_type: %d", lsp_type_info->sub_type);
        }
    }

    tlv = tlv_array[EXTCTRL_TLV_INSTALL_PFX];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->install_prefix_info = xmalloc(tlv_len);
        if (!lcs->install_prefix_info) {
             TRACE_RPD("pccd_rpd_decode_pcrequest: Memory allocation failure for %u",
                            EXTCTRL_TLV_INSTALL_PFX);
             return FALSE;
        }
        bcopy(tlv_var_data, lcs->install_prefix_info, tlv_len);
    } else {
        lcs->install_prefix_info = NULL;
    }

    tlv = tlv_array[EXTCTRL_TLV_OPTIMIZATION_METRIC];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->optimization_metric_list = xmalloc(tlv_len);
        if (!lcs->optimization_metric_list) {
             TRACE_RPD("pccd_rpd_decode_pcrequest: Memory allocation failure for %u",
                     EXTCTRL_TLV_OPTIMIZATION_METRIC);
             return FALSE;
        }
        bcopy(tlv_var_data, lcs->optimization_metric_list, tlv_len);
    } else {
        lcs->optimization_metric_list = NULL;
    }

    tlv = tlv_array[EXTCTRL_TLV_BOUND_METRIC];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->bound_metric_list = xmalloc(tlv_len);
        if (!lcs->bound_metric_list) {
             TRACE_RPD("pccd_rpd_decode_pcrequest: Memory allocation failure for %u",
                     EXTCTRL_TLV_BOUND_METRIC);
             return FALSE;
        }
        bcopy(tlv_var_data, lcs->bound_metric_list, tlv_len);
    } else {
        lcs->bound_metric_list = NULL;
    }

    tlv = tlv_array[EXTCTRL_TLV_ACTUAL_METRIC];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        lcs->actual_metric_list = xmalloc(tlv_len);
        if (!lcs->actual_metric_list) {
             TRACE_RPD("pccd_rpd_decode_pcrequest: Memory allocation failure for %u",
                     EXTCTRL_TLV_ACTUAL_METRIC);
             return FALSE;
        }
        bcopy(tlv_var_data, lcs->actual_metric_list, tlv_len);
    } else {
        lcs->actual_metric_list = NULL;
    }

    TRACE_RPD("PCCD decoded RPD_MSG_PCREQUEST_N_LSPSTATUS message successfully");
    return TRUE;
}

/**
 * Decode a lsperror message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] lsperr_msg Decoded rpd error message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
static boolean
pccd_rpd_decode_lsp_error(u_int8_t *msg_data, u_int16_t msg_length,
                            rpd_msg_extctrl_lsp_error_t *lsperr_msg)
{
    rpc_tlv *tlv = NULL;
    const char *err_msg = NULL;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data = NULL;
	u_int16_t ele_path_flags = 0;
    u_int8_t *tlv_8bit_data;
    u_int tlv_len = 0;
    lsp_type_info_t *lsp_type_info;

    if (!lsperr_msg) {
        return FALSE;
    }

    lsp_type_info = &lsperr_msg->lsp_type_info;
    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        return FALSE;
    }

    /* Get the Context */
    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    lsperr_msg->context = get_long(rpc_proto_tlv_data(tlv));

    /* Get the client/controller id */
    tlv = tlv_array[EXTCTRL_TLV_CLIENT_ID];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lsperr_msg->lsp_controller.name)) {
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, lsperr_msg->lsp_controller.name, tlv_len);

    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lsp_type_info->setup_type = *tlv_8bit_data;

    if((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
       (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
        if (!tlv) {
            return FALSE;
        }
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int8_t)) {
            return FALSE;
        }
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        lsp_type_info->sub_type = *tlv_8bit_data;
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_FLAG];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int16_t)) {
            return FALSE;
        }
        ele_path_flags = get_short(rpc_proto_tlv_data(tlv));
        lsperr_msg->flags = ele_path_flags;
    } else {
        lsperr_msg->flags = 0;
    }

    /* Get the Error LSP name */
    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lsperr_msg->lsp_name)) {
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    strncpy(lsperr_msg->lsp_name, tlv_var_data, tlv_len);

    /* Get the Error Code */
    tlv = tlv_array[EXTCTRL_TLV_RETURN_CODE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(u_int16_t)) {
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    lsperr_msg->error = get_short(rpc_proto_tlv_data(tlv));

    return TRUE;
}

/**
 * Decode a lsprequest message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] lsprequest_msg Decoded pcrequest message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
static boolean
pccd_rpd_decode_lsp_request(u_int8_t *msg_data, u_int16_t msg_length,
                            rpd_msg_extctrl_lsp_request_t *lspreq_msg)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int8_t *tlv_8bit_data;
	u_int16_t path_flags = 0;
    u_int tlv_len;
    lsp_type_info_t *lsp_type_info;
    if (!lspreq_msg) {
        return FALSE;
    }

    lsp_type_info = &lspreq_msg->lsp_type_info;
    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        return FALSE;
    }

    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    lspreq_msg->context = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lspreq_msg->name)) {
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    strncpy(lspreq_msg->name, tlv_var_data, sizeof(lspreq_msg->name));
    lspreq_msg->name[sizeof(lspreq_msg->name) - 1] = '\0';

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lspreq_msg->path_name)) {
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lspreq_msg->path_name, tlv_var_data, sizeof(lspreq_msg->path_name));
        lspreq_msg->path_name[sizeof(lspreq_msg->path_name) - 1] = '\0';
    } else {
        bzero(lspreq_msg->path_name, sizeof(lspreq_msg->path_name));
    }

    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lsp_type_info->setup_type = *tlv_8bit_data;
    
    if((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
       (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
        if (!tlv) {
            return FALSE;
        }
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int8_t)) {
            return FALSE;
        }
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        lsp_type_info->sub_type = *tlv_8bit_data;
    }

    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_FLAG];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int16_t)) {
            return FALSE;
        }
        path_flags = get_short(rpc_proto_tlv_data(tlv));
        lspreq_msg->is_p2mp_lsp = (path_flags & LSP_PATH_TYPE_P2MP);
    } else {
        lspreq_msg->is_p2mp_lsp = 0;
    }

    tlv = tlv_array[EXTCTRL_TLV_CLIENT_ID];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lspreq_msg->lsp_controller.name)) {
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, lspreq_msg->lsp_controller.name, tlv_len);

    return TRUE;
}

static void
pccd_rpd_encode_pcupdate_bypass_params(struct rsvp_byp_params_s *byp_params,
                                       rpc_tlv **cur_tlv, u_int *bytes_left, 
                                       u_int *length)
{
    TRACE_FUNCTION_ENTRY();

    /* PCE Initiated Bypass : begin */ 
    if (byp_params->rbp_nhaddr.rbn_ipv4_addr != 0) {
        if (!rpc_proto_build_complete_tlv(cur_tlv, RPC_TLV_DATA_32_BIT,
                          bytes_left, length,
                          EXTCTRL_TLV_BYP_PROT_TYPE,
                          &byp_params->rbp_prot_type,
                          sizeof(u_int32_t))) {
            TRACE_RPD("Not able to encode lsp_params->rbyp_params.rbp_prot_type: %d", 
                      byp_params->rbp_prot_type);
            return;
        }
        if (!rpc_proto_build_complete_tlv(cur_tlv, RPC_TLV_DATA_32_BIT,
                          bytes_left, length,
                          EXTCTRL_TLV_BYP_SUBSCR,
                          &byp_params->rbp_subscr,
                          sizeof(u_int32_t))) {
            TRACE_RPD("Not able to encode lsp_params->rbyp_params.rbp_subscr: %d", 
                      byp_params->rbp_subscr);
            return;
        }
                
        if (!rpc_proto_build_complete_tlv(cur_tlv, RPC_TLV_DATA_32_BIT,
                          bytes_left, length,
                          EXTCTRL_TLV_BYP_PRIMARY_NHOP,
                          &byp_params->rbp_nhaddr.rbn_ipv4_addr,
                          sizeof(u_int32_t))) {
            TRACE_RPD("Not able to encode lsp_params->rbyp_params.rbp_nhaddr.rbn_ipv4_addr: 0x%x", 
                      byp_params->rbp_nhaddr.rbn_ipv4_addr);
            return;
        }

		TRACE_RPD("PCCD_RPD encode bypass params:"
				"Nexthop: 0x%x, Protection Type: %u, Subscription: %u ", 
				byp_params->rbp_nhaddr.rbn_ipv4_addr,
				byp_params->rbp_prot_type, byp_params->rbp_subscr);
    }
    /* PCE Initiated Bypass : end */ 

    TRACE_FUNCTION_EXIT();
}

/**
 * calculate Encoded pcupdate message length.
 *
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static uint32_t
pccd_rpd_calculate_pcupdate_length (rpd_msg_pcupdate_t *msg)
{
    uint32_t                              length = 0;
    rpd_extctrl_lsp_config_status_info_t *lsp_params;
    lsp_type_info_t                      *lsp_type_info;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(msg != NULL);

    lsp_params = &msg->pupd_lsp_params;
    lsp_type_info = &lsp_params->lsp_type_info;

    /* EXTCTRL_TLV_CLIENT_ID */
    length += sizeof(rpc_tlv) + sizeof(msg->lsp_controller.name);

    /* EXTCTRL_TLV_SRC_DEST_ADDR_TYPE */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* EXTCTRL_TLV_SRC_ADDR */
    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    } else {
        length += sizeof(rpc_tlv) + 16;
    }

    /* EXTCTRL_TLV_DEST_ADDR */
    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    } else {
        length += sizeof(rpc_tlv) + 16;
    }

    /* EXTCTRL_TLV_CONTEXT */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /* EXTCTRL_TLV_LSP_TYPE */
    length += sizeof(rpc_tlv) + sizeof(lsp_params->type);

    /* EXTCTRL_TLV_LSP_STATE */
    length += sizeof(rpc_tlv) + sizeof(lsp_params->state);

    /* EXTCTRL_TLV_LSP_FLAGS */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* EXTCTRL_TLV_LSP_PATH_FLAG */
    length += sizeof(rpc_tlv) + sizeof(lsp_params->path_flags);

    /* EXTCTRL_TLV_LSP_NAME */
    length += sizeof(rpc_tlv) + sizeof(lsp_params->name);

    /* EXTCTRL_TLV_P2MP_NAME, EXTCTRL_TLV_P2MP_MBB_FLAG tlvs required only for p2mp lsps */

    /* EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /* EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /* EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /* EXTCTRL_TLV_SETUP_PRIO */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* EXTCTRL_TLV_HOLD_PRIO */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* EXTCTRL_TLV_BANDWIDTH */
    if (BIT_ISSET(lsp_params->lcs_params_flags, TAG_EXTCTRL_PARAMS_BANDWIDTH)) {
        length += sizeof(rpc_tlv) + sizeof(u_int64_t);
    }

    /* EXTCTRL_TLV_SETUP_TYPE */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* EXTCTRL_TLV_ERO_INFO */
    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
        length += sizeof(rpc_tlv) + lsp_params->ero_len;
    }

    /* EXTCTRL_TLV_SUB_TYPE */
    if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
        (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {
        length += sizeof(rpc_tlv) + sizeof(u_int8_t);
    }

    /* EXTCTRL_TLV_LSP_PATH_NAME */
    if(strlen(lsp_params->path_name)) {
        length += sizeof(rpc_tlv) + sizeof(lsp_params->path_name);
    }

    /* EXTCTRL_TLV_PATH_PRIORITY */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /* EXTCTRL_TLV_NUM_ASSOCIATION_INFO */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /* EXTCTRL_TLV_ASSOCIATION_INFO */
    if (lsp_params->num_assoc_info) {
        length += sizeof(rpc_tlv) + sizeof(lsp_association_info);
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
        (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        if (lsp_params->srte_ero_info) {
            /* EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT */
            length += sizeof(rpc_tlv) + sizeof(u_int8_t);

            uint32_t count = 0, total_ero_len = 0, ero_tlv_len = 0;
            if (lsp_params->srte_total_ero_count) {
                rpd_sr_ero_list_t *srte_ero_list = NULL;
                srte_ero_list =  (rpd_sr_ero_list_t *) lsp_params->srte_ero_info;
                while (count < lsp_params->srte_total_ero_count) {
                    total_ero_len = total_ero_len + srte_ero_list->rsel_n_eros;
                    srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
                    count++;
                }
                ero_tlv_len = (lsp_params->srte_total_ero_count * sizeof(rpd_sr_ero_list_t)) +
                              (total_ero_len * sizeof(rpd_sr_ero_t));
                /* EXTCTRL_TLV_SRTE_ERO_INFO */
                length += sizeof(rpc_tlv) + ero_tlv_len;
            }
        }
        /* EXTCTRL_TLV_SRTE_MAX_SEGMENT_LIST_INFO */
        length += sizeof(rpc_tlv) + sizeof(lsp_params->max_segment_list);
    }

    if (lsp_params->metric_valid) {
        /* EXTCTRL_TLV_LSP_METRIC */
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    }

    /* EXTCTRL_TLV_LOCAL_CSPF */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    TRACE_FUNCTION_RETURN(length);
}

/**
 * Encode a pcupdate message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static int
pccd_rpd_encode_pcupdate(u_int8_t *buf, u_int bytes_left,
                         rpd_msg_pcupdate_t *msg)
{
    rpc_tlv *cur_tlv;
    u_int length;

    rpd_extctrl_lsp_config_status_info_t *lsp_params;
    lsp_type_info_t *lsp_type_info;
    u_int8_t bw[sizeof(u_int64_t)];

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(buf != NULL);
    INSIST_ERR(msg != NULL);

    cur_tlv = (rpc_tlv *)(void *)buf;
    length = 0;
    lsp_params = &msg->pupd_lsp_params;
    lsp_type_info = &lsp_params->lsp_type_info;

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      sizeof(msg->lsp_controller.name))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SRC_DEST_ADDR_TYPE,
                                      &lsp_params->is_lsp_src_dst_addr_type_ipv6,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SRC_ADDR,
                                      &lsp_params->srcaddr_u.v4,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
        }
    } else {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SRC_ADDR,
                                      lsp_params->srcaddr_u.v6,
                                      16)) {
        TRACE_FUNCTION_RETURN(0);
        }
    }

    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_DEST_ADDR,
                                      &lsp_params->dstaddr_u.v4,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
        }
    } else {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_DEST_ADDR,
                                      lsp_params->dstaddr_u.v6,
                                      16)) {
        TRACE_FUNCTION_RETURN(0);
        }
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_TYPE,
                                      &lsp_params->type,
                                      sizeof(lsp_params->type))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_STATE,
                                      &lsp_params->state,
                                      sizeof(lsp_params->state))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_FLAGS,
                                      &lsp_params->lsp_flags,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_PATH_FLAG,
                                      &lsp_params->path_flags,
                                      sizeof(lsp_params->path_flags))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      lsp_params->name,
                                      sizeof(lsp_params->name))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (lsp_params->path_flags & LSP_PATH_TYPE_P2MP) {
        /*
        * Encode lsp p2mp tree name
        */
        if(strlen(lsp_params->p2mp_name)) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                                &bytes_left, &length,
                                                EXTCTRL_TLV_P2MP_NAME,
                                                lsp_params->p2mp_name,
                                                strlen(lsp_params->p2mp_name))) {
                TRACE_FUNCTION_RETURN(0);
            }
        }

        if (lsp_params->p2mp_mbb_flag) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                              &bytes_left, &length,
                                              EXTCTRL_TLV_P2MP_MBB_FLAG,
                                              &lsp_params->p2mp_mbb_flag,
                                              sizeof(lsp_params->p2mp_mbb_flag))) {
                TRACE_FUNCTION_RETURN(0);
            }
        }
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY,
                                      &lsp_params->relcsi_admin_grp_exclude_any,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY,
                                      &lsp_params->relcsi_admin_grp_include_any,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL,
                                      &lsp_params->relcsi_admin_grp_include_all,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_PRIO,
                                      &lsp_params->setup_prio,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_HOLD_PRIO,
                                      &lsp_params->hold_prio,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    /*
     * Set bandwidth only if the PCCreate or PCUpd has BANDWIDTH TLV.
     */
    if (BIT_ISSET(lsp_params->lcs_params_flags, TAG_EXTCTRL_PARAMS_BANDWIDTH)) {
        put_long(&bw[0], (lsp_params->bandwidth & 0xffffffff00000000ULL) >> 32);
        put_long(&bw[4], lsp_params->bandwidth & 0xffffffff);
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_BANDWIDTH,
                                          bw,
                                          sizeof(u_int64_t))) {
            TRACE_FUNCTION_RETURN(0);
        }
    }
        
    TRACE_RPD("lsp_params->setup_type: %d", lsp_type_info->setup_type);
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_TYPE,
                                      &lsp_type_info->setup_type,
                                      sizeof(u_int8_t))) {
        TRACE_RPD("Not able to encode lsp_params->setup_type: %d", lsp_type_info->setup_type);
        TRACE_FUNCTION_RETURN(0);
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
        if (lsp_params->ero_info) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_ERO_INFO,
                                          lsp_params->ero_info,
                                          lsp_params->ero_len)) {
            TRACE_RPD("Not able to encode lsp_params->ero_info: %p", lsp_params->ero_info);
            TRACE_FUNCTION_RETURN(0);
            }
        }
    }

    if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
        (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {
        TRACE_RPD("lsp_params->sub_type: %d", lsp_type_info->sub_type);
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(u_int8_t))) {
            TRACE_RPD("Not able to encode lsp_params->sub_type: %d", lsp_type_info->sub_type);
            TRACE_FUNCTION_RETURN(0);
        }
    }

    if(strlen(lsp_params->path_name)) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					  &bytes_left, &length,
					  EXTCTRL_TLV_LSP_PATH_NAME,
					  lsp_params->path_name,
					  sizeof(lsp_params->path_name))) {
	    TRACE_FUNCTION_RETURN(0);
	}
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_PATH_PRIORITY,
                                      &lsp_params->path_priority,
                                      sizeof(u_int16_t))) {
        return 0;
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_NUM_ASSOCIATION_INFO,
                                      &lsp_params->num_assoc_info,
                                      sizeof(u_int16_t))) {
        return 0;
    }
    if (lsp_params->num_assoc_info) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_ASSOCIATION_INFO,
                                          lsp_params->assoc_info,
                                          lsp_params->num_assoc_info *
                                          sizeof(lsp_association_info))) {
            return 0;
        }
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
        (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
        if (lsp_params->srte_ero_info) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                              &bytes_left, &length,
                                              EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT,
                                              &lsp_params->srte_total_ero_count,
                                              sizeof(u_int8_t))) {
                return 0;
            }
            uint32_t count = 0, total_ero_len = 0, ero_tlv_len = 0;
            if (lsp_params->srte_total_ero_count) {
                rpd_sr_ero_list_t *srte_ero_list = NULL;
                srte_ero_list =  (rpd_sr_ero_list_t *) lsp_params->srte_ero_info;
                while (count < lsp_params->srte_total_ero_count) {
                    total_ero_len = total_ero_len + srte_ero_list->rsel_n_eros;
                    srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
                    count++;
                }
                ero_tlv_len = (lsp_params->srte_total_ero_count * sizeof(rpd_sr_ero_list_t)) +
                              (total_ero_len * sizeof(rpd_sr_ero_t));
                if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                                  &bytes_left, &length,
                                                  EXTCTRL_TLV_SRTE_ERO_INFO,
                                                  lsp_params->srte_ero_info,
                                                  ero_tlv_len)) {
                    TRACE_RPD("Not able to encode lsp_params->srte_ero_info: %p", lsp_params->srte_ero_info);
                    TRACE_FUNCTION_RETURN(0);
                }
            }
        }
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_MAX_SEGMENT_LIST_INFO,
                                          &lsp_params->max_segment_list,
                                          sizeof(lsp_params->max_segment_list))) {
            TRACE_FUNCTION_RETURN(0);
        }
    }

    if (lsp_params->metric_valid) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_METRIC,
                                          &lsp_params->metric,
                                          sizeof(u_int32_t))) {
            TRACE_FUNCTION_RETURN(0);
        }
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LOCAL_CSPF,
				      &lsp_params->relcsi_local_cspf,
				      sizeof(u_int8_t))) {
	TRACE_FUNCTION_RETURN(0);
    }

    /* PCE Initiated Bypass : begin */
    pccd_rpd_encode_pcupdate_bypass_params(&lsp_params->rbyp_params,
                                           &cur_tlv, &bytes_left, &length);
    /* PCE Initiated Bypass : end */

    /**
     * Encode install-prefix buff
     */
    if (lsp_params->install_prefix_info) {
        unsigned len = RPD_PREFIX_BUFF_LEN(lsp_params->install_prefix_info);
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                     &bytes_left, &length,
                     EXTCTRL_TLV_INSTALL_PFX,
                     lsp_params->install_prefix_info,
                     len)) {
            TRACE_RPD("Not able to encode lsp_params->install_prefix_info: %p",
                        lsp_params->install_prefix_info);
            TRACE_FUNCTION_RETURN(0);
        }
    }

    TRACE_FUNCTION_RETURN(length);
}

/**
 * Encode a pcupdate message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static int
pccd_rpd_encode_pcupdate_delete(u_int8_t *buf, u_int bytes_left,
                         rpd_msg_pcupdate_t *msg)
{
    rpc_tlv *cur_tlv;
    u_int length;

    rpd_extctrl_lsp_config_status_info_t *lsp_params;
    lsp_type_info_t *lsp_type_info;
    
    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(buf != NULL);
    INSIST_ERR(msg != NULL);

    cur_tlv = (rpc_tlv *)(void *)buf;
    length = 0;
    lsp_params = &msg->pupd_lsp_params;
    lsp_type_info = &lsp_params->lsp_type_info;

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      sizeof(msg->lsp_controller.name))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SRC_DEST_ADDR_TYPE,
                                      &lsp_params->is_lsp_src_dst_addr_type_ipv6,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
         if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTCTRL_TLV_SRC_ADDR,
                                       &lsp_params->srcaddr_u.v4,
                                       sizeof(u_int32_t))) {
         TRACE_FUNCTION_RETURN(0);
         }
     } else {
         if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTCTRL_TLV_SRC_ADDR,
                                       lsp_params->srcaddr_u.v6,
                                       16)) {
         TRACE_FUNCTION_RETURN(0);
         }
     }

    if (!lsp_params->is_lsp_src_dst_addr_type_ipv6) {
         if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTCTRL_TLV_DEST_ADDR,
                                       &lsp_params->dstaddr_u.v4,
                                       sizeof(u_int32_t))) {
         TRACE_FUNCTION_RETURN(0);
         }
     } else {
         if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTCTRL_TLV_DEST_ADDR,
                                       lsp_params->dstaddr_u.v6,
                                       16)) {
         TRACE_FUNCTION_RETURN(0);
         }
     }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_FLAGS,
                                      &lsp_params->lsp_flags,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_TYPE,
                                      &lsp_params->type,
                                      sizeof(lsp_params->type))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      lsp_params->name,
                                      sizeof(lsp_params->name))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if(strlen(lsp_params->path_name)) {

        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_NAME,
                                          lsp_params->path_name,
                                          sizeof(lsp_params->path_name))) {
            TRACE_FUNCTION_RETURN(0);
        }
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_PATH_FLAG,
                                      &lsp_params->path_flags,
                                      sizeof(lsp_params->path_flags))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_TYPE,
                                      &lsp_type_info->setup_type,
                                      sizeof(u_int8_t))) {
        TRACE_FUNCTION_RETURN(0);
    }
    
	if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
	   (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(u_int8_t))) {
            TRACE_FUNCTION_RETURN(0);
        }
	}

    /* PCE Initiated Bypass : begin */ 
    pccd_rpd_encode_pcupdate_bypass_params(&lsp_params->rbyp_params,
                                           &cur_tlv, &bytes_left, &length);    
    /* PCE Initiated Bypass : end */ 
        
    TRACE_FUNCTION_RETURN(length);
}

/**
 * Encode a lsp request message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static int
pccd_rpd_encode_lsp_request(u_int8_t *buf, u_int bytes_left,
                            rpd_msg_extctrl_lsp_request_t *msg)
{
    rpc_tlv *cur_tlv;
    u_int length;
    lsp_type_info_t *lsp_type_info;

    if (!msg) {
        return 0;
    }

    if (!buf) {
        return 0;
    }

    lsp_type_info = & msg->lsp_type_info;
    cur_tlv = (rpc_tlv *)(void *)buf;
    length = 0;

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        TRACE_RPD("not able to encode lsp_params->context: %d", msg->context);
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      msg->name,
                                      sizeof(msg->name))) {
        TRACE_RPD("not able to encode lsp_params->lsp_name: %d", msg->name);
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      sizeof(msg->lsp_controller.name))) {
        TRACE_RPD("not able to encode lsp_params->controller_name: %s", msg->lsp_controller.name);
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_TYPE,
                                      &lsp_type_info->setup_type,
                                      sizeof(u_int8_t))) {
        TRACE_RPD("Not able to encode lsp_params->setup_type: %d", lsp_type_info->setup_type);
        TRACE_FUNCTION_RETURN(0);
    }

    if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
       (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(u_int8_t))) {
            TRACE_RPD("Not able to encode lsp_params->sub_type: %d", lsp_type_info->sub_type);
            TRACE_FUNCTION_RETURN(0);
        }
        /* path_name is required only for SPRING_TE. RSVP acts on all paths of a tunnel,
        SPRING_TE acts only on the given path of a tunnel */
        if(strlen(msg->path_name)) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                              &bytes_left, &length,
                                              EXTCTRL_TLV_LSP_PATH_NAME,
                                              msg->path_name,
                                              sizeof(msg->path_name))) {
                TRACE_RPD("not able to encode lsp_params->path_name: %d", msg->name);
                TRACE_FUNCTION_RETURN(0);
            }
        }
    }
    return length;
}

/**
 * Encode a pcupdate fragment message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static uint32_t
pccd_rpd_encode_pcupdate_fragment (u_int8_t                *buf,
                                   u_int                    bytes_left,
                                   rpd_msg_frag_pcupdate_t *msg,
                                   uint8_t                 *data_buf)
{
    rpc_tlv                                   *cur_tlv;
    uint32_t                                   length = 0;
    rpd_extctrl_lsp_config_status_frag_info_t *lsp_params;

    TRACE_FUNCTION_ENTRY();
    INSIST_ERR(buf != NULL);
    INSIST_ERR(msg != NULL);

    cur_tlv = (rpc_tlv *)(void *) buf;
    lsp_params = &msg->pupd_frag_info;

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      sizeof(msg->lsp_controller.name))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_MSG_ID,
                                      &lsp_params->message_id,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_TOTAL_FRAGMENTS,
                                      &lsp_params->total_fragments,
                                      sizeof(uint32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CURRENT_FRAGMENT,
                                      &lsp_params->current_fragment,
                                      sizeof(uint32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_TOTAL_MESSAGE_SIZE,
                                      &lsp_params->total_msg_size,
                                      sizeof(uint32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE,
                                      &lsp_params->current_fragment_size,
                                      sizeof(uint32_t))) {
        TRACE_FUNCTION_RETURN(0);
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_FRAGMENT_DATA,
                                      (data_buf + 
                                        (MAX_FRAGMENT_DATA * (lsp_params->current_fragment-1))),
                                      lsp_params->current_fragment_size)) {
        TRACE_FUNCTION_RETURN(0);
    }
    return length;
}

int
pccd_rpd_pcupdate_send(struct pccd_rpd_lsp_info *rpd_lsp, rpd_session_handle handle,
                       const char *client_name,
                       const rpd_extctrl_lsp_config_status_info_t *params)
{
    ipc_msg_t hdr;
    rpd_msg_pcupdate_t msg;
    rpd_msg_frag_pcupdate_t frag_msg;
    u_int length, dyn_length = 0, frag_length = 0;
    int ret = 0, send_len = 0, counter = 0, current_fragment = 0;
    uint32_t curr_message_id = 0, msg_buffer_size = 0;;
    bool need_dyn_mem = false;
    uint8_t *dyn_tx_buffer_ptr = NULL, *frag_tx_ptr = NULL, *write_buf = NULL;

    TRACE_FUNCTION_ENTRY();

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_PCUPDATE;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;
    
    if(rpd_lsp){
        msg.context = rpd_lsp->context;
    } else {
        msg.context = 0;
    }

    if (!client_name || strlen(client_name) >= sizeof(msg.lsp_controller.name) ) {
        errno = EINVAL;
        TRACE_FUNCTION_RETURN(-1);
    }
    strncpy(msg.lsp_controller.name, client_name,
            sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';
    msg.pupd_lsp_params = *params;

    /*
     * Optimization
     * Send data length is calculated only when multiple EROs are present
     * and it is greater than 10 in the update message. Currently, SRv6 ERO
     * with 16 SIDs require approximately 1000 bytes in PCUpdate message.
     * The TX buffer currently has 65K bytes in size. So, for up to 10 EROs
     * we would require much less than 65K bytes. This value of 10 can be 
     * re-optimised later
     */
    if (params->srte_total_ero_count > MAX_AVAILABLE_ERO_IN_TX_BUFFER) {
        dyn_length = pccd_rpd_calculate_pcupdate_length(&msg);
        if (dyn_length > TX_BUFFER_LEN) {
            need_dyn_mem = true;
            dyn_tx_buffer_ptr = xmalloc(dyn_length);
            if (!dyn_tx_buffer_ptr) {
                TRACE_FUNCTION_RETURN(-1);
            }
        }
    }
    if (need_dyn_mem) {
        length = pccd_rpd_encode_pcupdate(dyn_tx_buffer_ptr, dyn_length, &msg);
    } else {
        length = pccd_rpd_encode_pcupdate(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    }
    if (!length) {
        TRACE_RPD("pccd_rpd_encode_pcupdate failed");
        if (dyn_tx_buffer_ptr) {
            free(dyn_tx_buffer_ptr);
        }
        TRACE_FUNCTION_RETURN(-1);
    }
    /*
     * Check for need for fragmentation
     */
    if (length > MAX_FRAGMENT_DATA) {
        if (need_dyn_mem) {
            frag_tx_ptr = dyn_tx_buffer_ptr;
            msg_buffer_size = dyn_length;
        } else {
            frag_tx_ptr = &tx_buffer_ptr[0];
            msg_buffer_size = TX_BUFFER_LEN;
        }
        TRACE_RPD(": PCCD -> RPD message requires fragmentation. "
                  "LSP: %s Current Message Length=%d", params->name, length);
        counter = length;
        if(rpd_lsp){
            frag_msg.context = rpd_lsp->context;
        } else {
            frag_msg.context = 0;
        }
        if (!client_name || strlen(client_name) >= sizeof(frag_msg.lsp_controller.name) ) {
            errno = EINVAL;
            if (dyn_tx_buffer_ptr) {
                free(dyn_tx_buffer_ptr);
            }
            TRACE_FUNCTION_RETURN(-1);
        }
        strlcpy(frag_msg.lsp_controller.name, client_name,
                sizeof(frag_msg.lsp_controller.name));
        curr_message_id = message_id_counter++;
        write_buf = (uint8_t *) xmalloc(MAX_FRAGMENT_DATA + MAX_MSG_HEADER_SIZE);
        while (counter > 0) {
            ipc_msg_t frag_hdr;
            rpd_extctrl_lsp_config_status_frag_info_t frag_det;

            /*
             * Fragment Metadata
             */
            frag_det.total_fragments = length / MAX_FRAGMENT_DATA;
            if (length % MAX_FRAGMENT_DATA != 0) {
                frag_det.total_fragments += 1; 
            }
            frag_det.current_fragment = current_fragment+1;
            current_fragment++;
            frag_det.total_msg_size = length;
            if (counter > MAX_FRAGMENT_DATA) {
                send_len = MAX_FRAGMENT_DATA;
            } else {
                send_len = counter;
            }
            frag_det.current_fragment_size = send_len;
            frag_det.message_id = curr_message_id;
            TRACE_RPD(": Message_id %u - LSP %s, total fragment:%d current_fragment:%d "
                      "total_fragment_size:%d current_fragment_size:%d",
                      frag_det.message_id, params->name,
                      frag_det.total_fragments, frag_det.current_fragment,
                      frag_det.total_msg_size, frag_det.current_fragment_size);
            memcpy(&frag_msg.pupd_frag_info, &frag_det, 
                   sizeof(rpd_extctrl_lsp_config_status_frag_info_t));
            frag_length = pccd_rpd_encode_pcupdate_fragment(
                            write_buf, msg_buffer_size, &frag_msg, frag_tx_ptr);
            if (!frag_length) {
                TRACE_RPD("pccd_rpd_encode_pcupdate_fragment failed");
                if (dyn_tx_buffer_ptr) {
                    free(dyn_tx_buffer_ptr);
                }
                if (write_buf) {
                    free(write_buf);
                }
                TRACE_FUNCTION_RETURN(-1);
            }
            /*
             * Fragment Header
             */
            frag_hdr.type = 0; 
            frag_hdr.subtype = RPD_MSG_EXTCTRL_SRTE_FRAG_PCUPDATE;
            frag_hdr.opcode = IPC_MSG_ACTION_NONE;
            frag_hdr.error = IPC_ERROR_OK;
            frag_hdr.length = (unsigned short) frag_length;
            ret = rpd_client_msg_write(handle, &frag_hdr, write_buf);
            if (ret) {
                LOGGING_ERR("rpd client message write failed: %d '%s'", errno,
                            strerror(errno));
                if (dyn_tx_buffer_ptr) {
                    free(dyn_tx_buffer_ptr);
                }
                if (write_buf) {
                    free(write_buf);
                }
                TRACE_FUNCTION_RETURN(-1);
            }
            counter -= send_len;
        }
        if (dyn_tx_buffer_ptr) {
            free(dyn_tx_buffer_ptr);
        }
        if (write_buf) {
            free(write_buf);
        }
        TRACE_FUNCTION_RETURN(ret);
    } else {
        TRACE_RPD(": LSP %s - Fragmentation is not required", params->name);
    }

    hdr.length = length;

    pccd_rpd_update_instance(rpd_lsp, LAST_PCUPD_SENT);

    TRACE_FUNCTION_RETURN(rpd_client_msg_write(handle, &hdr, tx_buffer_ptr));
}

int
pccd_rpd_pcupdate_send_delete(rpd_session_handle handle, const u_int32_t context,
                       const char *client_name,
                       const rpd_extctrl_lsp_config_status_info_t *params)
{
    ipc_msg_t hdr;
    rpd_msg_pcupdate_t msg;
    u_int length;

    TRACE_FUNCTION_ENTRY();

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_PCUPDATE;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    msg.context = context;
    if (!client_name || strlen(client_name) >= sizeof(msg.lsp_controller.name)) {
        errno = EINVAL;
        TRACE_FUNCTION_RETURN(-1);
    }
    strncpy(msg.lsp_controller.name, client_name,
            sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';
    msg.pupd_lsp_params = *params;

    length = pccd_rpd_encode_pcupdate_delete(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    if (!length) {
        TRACE_RPD("pccd_rpd_encode_pcupdate failed");
        TRACE_FUNCTION_RETURN(-1);
    }

    hdr.length = length;
    TRACE_FUNCTION_RETURN(rpd_client_msg_write(handle, &hdr, tx_buffer_ptr));
}


int
pccd_rpd_lsp_get_info_all_send(rpd_session_handle handle, boolean pce_only)
{
    ipc_msg_t hdr;
    rpd_msg_client_identification_t msg;

    strncpy(msg.name, PCCD_RPD_CLIENT_ID, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    hdr.type = 0;
    hdr.subtype = (pce_only == TRUE) ? RPD_MSG_EXTCTRL_GET_ALL_EXTCTRLLSPINFO :
            RPD_MSG_EXTCTRL_GET_ALL_LSPINFO;
    hdr.length = sizeof(msg);
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    return rpd_client_msg_write(handle, &hdr, &msg);
}

/**
 * send get specific lsp request.
 *
 * @param[in] handle - rpd session handle
 * @param[in] lsp_name - name of the requested lsp
 * @param[in] path_name - path name of the requested lsp
 * @param[in] setup_type - setup type of the requested lsp
 * @param[in] sub_type - sub setup type of the requested lsp
 * @param[in] context - context of requested lsp
 *
 * @return FALSE when the message cannot be sent
 * @return TRUE  when the message is successfully sent
 */
int
pccd_rpd_lsp_get_info_send(rpd_session_handle handle,
                              const char *lsp_name,
                              const char *path_name,
                              const uint8_t setup_type, 
                              const uint8_t sub_type,
                              const uint32_t context)
{
    ipc_msg_t hdr;
    rpd_msg_extctrl_lsp_request_t msg;
    u_int length;

    if (!lsp_name || strlen(lsp_name) >= sizeof(msg.name)) {
        errno = EINVAL;
        return -1;
    }
    strncpy(msg.name, lsp_name, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    if (path_name && strlen(path_name)) {
        strncpy(msg.path_name, path_name, sizeof(msg.path_name));
        msg.path_name[sizeof(msg.path_name) - 1] = '\0';
    } else {
        msg.path_name[0] = '\0';
    }

    strncpy(msg.lsp_controller.name, PCCD_RPD_CLIENT_ID,
            sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';

    msg.lsp_type_info.setup_type = setup_type;
    msg.lsp_type_info.sub_type = sub_type;
    msg.context = context;
    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_LSP_GET_INFO;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    length = pccd_rpd_encode_lsp_request(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    if (!length) {
        return -1;
    }
    hdr.length = (uint16_t)length;
    return rpd_client_msg_write(handle, &hdr, tx_buffer_ptr);
}

int
pccd_rpd_lsp_get_control_send(rpd_session_handle handle,
                                            const char *lsp_name,
                                            const char *path_name,
                                            const uint8_t setup_type, 
                                            const uint8_t sub_type,
                                            const uint32_t context)
{
    ipc_msg_t hdr;
    rpd_msg_extctrl_lsp_request_t msg;
    u_int length;

    if (!lsp_name || strlen(lsp_name) >= sizeof(msg.name)) {
        errno = EINVAL;
        return -1;
    }
    strncpy(msg.name, lsp_name, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    if (path_name && strlen(path_name)) {
        strncpy(msg.path_name, path_name, sizeof(msg.path_name));
        msg.path_name[sizeof(msg.path_name) - 1] = '\0';
    } else {
        msg.path_name[0] = '\0';
    }

    strncpy(msg.lsp_controller.name, PCCD_RPD_CLIENT_ID,
            sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';

    msg.lsp_type_info.setup_type = setup_type;
    msg.lsp_type_info.sub_type = sub_type;
    msg.context = context;
    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRLLSP_GET_CONTROL;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    length = pccd_rpd_encode_lsp_request(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    if (!length) {
        return -1;
    }
    hdr.length = length;
    return rpd_client_msg_write(handle, &hdr, tx_buffer_ptr);
}

int
pccd_rpd_lsp_return_control_send(rpd_session_handle handle,
                                 const char *lsp_name,
                                 const char *path_name,
                                 const uint8_t setup_type,
                                 const uint8_t sub_type,
                                 const u_int32_t context)
{
    ipc_msg_t hdr;
    rpd_msg_extctrl_lsp_request_t msg;
    u_int length;

    if (!lsp_name || strlen(lsp_name) >= sizeof(msg.name)) {
        errno = EINVAL;
        return -1;
    }
    strncpy(msg.name, lsp_name, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    if (path_name && strlen(path_name)) {
        strncpy(msg.path_name, path_name, sizeof(msg.path_name));
        msg.path_name[sizeof(msg.path_name) - 1] = '\0';
    } else {
        msg.path_name[0] = '\0';
    }

    strncpy(msg.lsp_controller.name, PCCD_RPD_CLIENT_ID,
            sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';

    msg.lsp_type_info.setup_type = setup_type;
    msg.lsp_type_info.sub_type = sub_type;
    msg.context = context;
    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRLLSP_RETURN_CONTROL;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    length = pccd_rpd_encode_lsp_request(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    if (!length) {
        return -1;
    }
    hdr.length = length;
    return rpd_client_msg_write(handle, &hdr, tx_buffer_ptr);
}

int
pccd_rpd_lsp_return_control_all_send(rpd_session_handle handle)
{
    ipc_msg_t hdr;
    rpd_msg_client_identification_t msg;

    strncpy(msg.name, PCCD_RPD_CLIENT_ID, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_RETURN_CTRL_FOR_ALL;
    hdr.length = sizeof(msg);
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    return rpd_client_msg_write(handle, &hdr, &msg);
}

int
pccd_rpd_lsp_get_controll_all_send(rpd_session_handle handle)
{
    ipc_msg_t hdr;
    rpd_msg_client_identification_t msg;

    strncpy(msg.name, PCCD_RPD_CLIENT_ID, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_TAKE_CTRL_FOR_ALL;
    hdr.length = sizeof(msg);
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    return rpd_client_msg_write(handle, &hdr, &msg);
}

int
pccd_rpd_lsp_retry_pcrequests_send(rpd_session_handle handle)
{
    ipc_msg_t hdr;
    rpd_msg_client_identification_t msg;

    strncpy(msg.name, PCCD_RPD_CLIENT_ID, sizeof(msg.name));
    msg.name[sizeof(msg.name) - 1] = '\0';

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_RETRY_PCREQUESTS;
    hdr.length = sizeof(msg);
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    return rpd_client_msg_write(handle, &hdr, &msg);
}

/**
    SR color and SRPAG endpoints can be changed from Junos CLI. Then LSP delete and add will not be sent by SRTE,
    existing LSP is updated with new color or end-point. For PCEP, as SRPAG identifiers should not change
    in lifetime of LSP, LSP delete and add should be sent
*/
bool
pccd_rpd_sr_color_endpoint_changed(rpd_session_handle handle,
                                  rpd_extctrl_lsp_config_status_info_t *lsp_config_status,
                                  struct pccd_rpd_lsp_info *rpd_lsp)
{
    uint8_t rpd_lsp_srpag_pos = LSP_ASSOCIATION_TYPE_MAX;
    uint8_t rcvd_lsp_srpag_pos = LSP_ASSOCIATION_TYPE_MAX;
    uint16_t num_assoc_info;
    bool isChanged = false;

    if ((LSP_TYPE_EXTERNALLY_PROVISIONED == lsp_config_status->type) ||
        ((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE != lsp_config_status->lsp_type_info.setup_type) &&
        (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE != lsp_config_status->lsp_type_info.setup_type)))
        return isChanged;

    num_assoc_info  = ( lsp_config_status->num_assoc_info > rpd_lsp->num_assoc_info ) ?
                            lsp_config_status->num_assoc_info : rpd_lsp->num_assoc_info;

    if ( num_assoc_info >= LSP_ASSOCIATION_TYPE_MAX ) {
        TRACE_RPD("ERROR: number of LSP associations >= Max association");
        return isChanged;
    }
    if ( num_assoc_info == 0 )
        return isChanged;

    for ( uint8_t count = 0; count < num_assoc_info; count++) {
        if(lsp_config_status->assoc_info[count].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG) {
            rcvd_lsp_srpag_pos = count;
        }
         if(rpd_lsp->assoc_info[count].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG) {
            rpd_lsp_srpag_pos = count;
        }
    }

    if ((rcvd_lsp_srpag_pos == LSP_ASSOCIATION_TYPE_MAX) &&
        (rpd_lsp_srpag_pos == LSP_ASSOCIATION_TYPE_MAX))
        return isChanged;

    if ((rcvd_lsp_srpag_pos != LSP_ASSOCIATION_TYPE_MAX) &&
        (rpd_lsp_srpag_pos == LSP_ASSOCIATION_TYPE_MAX) ) {

        TRACE_RPD(" Deleting existing uncolored SR LSP. New colored SR LSP will be created ");
        pccd_rpd_lsp_del(handle,lsp_config_status->name, lsp_config_status->path_name);
        isChanged = true;

    } else if ((rcvd_lsp_srpag_pos == LSP_ASSOCIATION_TYPE_MAX) &&
                (rpd_lsp_srpag_pos != LSP_ASSOCIATION_TYPE_MAX)) {

        TRACE_RPD(" Deleting existing colored SR LSP. New uncolored SR LSP will be created ");
        pccd_rpd_lsp_del(handle,lsp_config_status->name, lsp_config_status->path_name);
        isChanged = true;

    } else if (lsp_config_status->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.color !=
               rpd_lsp->assoc_info[rpd_lsp_srpag_pos].sr_srpag_t.color) {

        TRACE_RPD(" SR LSP color changed. Deleting existing LSP, New LSP will be created with rcvd color ");
        pccd_rpd_lsp_del(handle,lsp_config_status->name, lsp_config_status->path_name);
        isChanged = true;

    } else if (((!lsp_config_status->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.is_srpag_endpoint_ipv6) &&
                (lsp_config_status->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.srpag_endpoint_addr_u.v4 !=
                 rpd_lsp->assoc_info[rpd_lsp_srpag_pos].sr_srpag_t.srpag_endpoint_addr_u.v4)) ||
               ((lsp_config_status->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.is_srpag_endpoint_ipv6) &&
                 memcmp(lsp_config_status->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.srpag_endpoint_addr_u.v6,
                 rpd_lsp->assoc_info[rcvd_lsp_srpag_pos].sr_srpag_t.srpag_endpoint_addr_u.v6, 16))) {

        TRACE_RPD(" SR LSP SRPAG endpoint changed. Deleting existing LSP, New LSP will be \
            created with rcvd destination ");
        pccd_rpd_lsp_del(handle,lsp_config_status->name, lsp_config_status->path_name);
        isChanged = true;

    }

    return isChanged;
}

void
pccd_rpd_cleanup_frag_state (void)
{
    if (frag_recv_buf) {
        free(frag_recv_buf);
        frag_recv_buf = NULL;
    }
    current_frag_buf_ptr = NULL;
    message_id_counter = 1;
    current_message_id = 0;
    recent_frag_id = 0;
}

void
pccd_rpd_pcrequest_frag_recv (rpd_session_handle  handle,
                              u_int8_t           *msg,
                              u_int               msg_length)
{
    rpc_tlv                                   *tlv;
    const char                                *err_msg;
    rpc_tlv                                   *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t                                  *tlv_var_data;
    u_int                                      tlv_len;
    rpd_extctrl_lsp_config_status_frag_info_t  lcs;
    uint32_t                                   message_id = 0;


    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));

    if (rpc_proto_buffer_parse_tlvs(msg, (uint16_t)msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: EXTCTRL_TLV_MAX absent");
        return;
    }

    tlv = tlv_array[EXTCTRL_TLV_TOTAL_FRAGMENTS];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_TOTAL_FRAGMENTS absent");
        return;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_TOTAL_FRAGMENTS "
                  "tlv length: %d",tlv_len);
        return;
    }
    lcs.total_fragments = get_long(rpc_proto_tlv_data(tlv));
    
    tlv = tlv_array[EXTCTRL_TLV_CURRENT_FRAGMENT];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_CURRENT_FRAGMENT absent");
        return;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag:TLV EXTCTRL_TLV_CURRENT_FRAGMENT "
                  "tlv length: %d", tlv_len);
        return;
    }
    lcs.current_fragment = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_TOTAL_MESSAGE_SIZE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_TOTAL_FRAGMENT_SIZE absent");
        return;
    }     
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_TOTAL_FRAGMENT_SIZE "
                  "tlv length: %d", tlv_len);
        return;
    }
    lcs.total_msg_size = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE absent");
        return;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {     
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE "
                  "tlv length: %d", tlv_len);
        return;
    }
    lcs.current_fragment_size = get_long(rpc_proto_tlv_data(tlv));

    tlv = tlv_array[EXTCTRL_TLV_MSG_ID];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_MSG_ID absent");
        return;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_MSG_ID "
                  "tlv length: %d", tlv_len);
        return;
    }
    message_id = get_long(rpc_proto_tlv_data(tlv));
    if (!message_id) {
        TRACE_RPD(": Invalid message id %u found. Cleaning up fragment states",
                  message_id);
        pccd_rpd_cleanup_frag_state();
        return;
    }

    TRACE_RPD(": Message_id %u, Fragment received. RPD->PCCD - %d/%d   %d/%d",
              message_id,
              lcs.current_fragment, lcs.total_fragments,
              lcs.current_fragment_size, lcs.total_msg_size);
    if (lcs.current_fragment == 1) {
        frag_recv_buf = xmalloc(lcs.total_msg_size+1);
        if (!frag_recv_buf) {
            return;
        }
        current_frag_buf_ptr = frag_recv_buf;
        current_message_id = message_id;
    }
    if (message_id != current_message_id) {
        LOGGING_ERR(": Invalid message id %u found instead of %u. Cleaning up fragment states",
                    message_id, current_message_id);
        pccd_rpd_cleanup_frag_state();
        return;
    }

    tlv = tlv_array[EXTCTRL_TLV_FRAGMENT_DATA];
    if (!tlv) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_FRAGMENT_DATA absent");
        return;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != lcs.current_fragment_size) {
        TRACE_RPD("pccd_rpd_decode_pcrequest_frag: TLV EXTCTRL_TLV_FRAGMENT_DATA "
                  "tlv length: %d", tlv_len);
        return;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, current_frag_buf_ptr, tlv_len);
    current_frag_buf_ptr += lcs.current_fragment_size;
    if ((lcs.current_fragment - recent_frag_id) != 1) {
        TRACE_RPD(": Invalid frag id %u found instead of %u. Cleaning up fragment states",
                  lcs.current_fragment, recent_frag_id+1);
        LOGGING_ERR(": Invalid frag id %u found instead of %u. Cleaning up fragment states",
                    lcs.current_fragment, recent_frag_id+1);
        pccd_rpd_cleanup_frag_state();
        return;
    }
    recent_frag_id = lcs.current_fragment;

    if (lcs.current_fragment != lcs.total_fragments) {
        TRACE_RPD(": Enqueued fragmented data. Awaiting more fragmented data");
        return;
    }

    TRACE_RPD(": Starting encode for all merged fragments");
    pccd_rpd_pcrequest_recv(handle, frag_recv_buf, lcs.total_msg_size);
    pccd_rpd_cleanup_frag_state();
    return;
}

void
pccd_rpd_pcrequest_recv(rpd_session_handle handle,
                        u_int8_t *msg, u_int msg_length)
{
    rpd_msg_pcrequest_status_t *pccd_msg;
    rpd_msg_pcrequest_status_t pcrequest_msg;
    pccd_rpd_name_tree_key name_tree_key;
    rpd_extctrl_lsp_config_status_info_t *lsp_config_status;
    lsp_type_info_t *recv_lsp_type_info;
    struct pccd_rpd_lsp_info *rpd_lsp = NULL;
    struct pccd_rpd_lsp_info *curr_rpd_lsp = NULL;
    bool recv_is_p2mp_lsp;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];

    TRACE_FUNCTION_ENTRY();

    bzero(&pcrequest_msg, sizeof(pcrequest_msg));
    pccd_msg = &pcrequest_msg;
    if (!pccd_rpd_decode_pcrequest(msg, msg_length,
                                   &pcrequest_msg)) {
        LOGGING_ERR("Could not decode message from RPD");
        TRACE_RPD("Could not decode pcrequest");
        TRACE_FUNCTION_RETURN();
    }

    lsp_config_status = &pccd_msg->lsp_config_status;
    recv_lsp_type_info = &lsp_config_status->lsp_type_info;
    pccd_rpd_get_lsp_name(lsp_full_name, sizeof(lsp_full_name), 
        lsp_config_status->name, lsp_config_status->path_name);
    recv_is_p2mp_lsp = (lsp_config_status->path_flags & LSP_PATH_TYPE_P2MP);
    TRACE_RPD("Received LSP: '%s', with setup_type: %d, sub_type: %d, is_p2mp_lsp: %d", 
        lsp_full_name, recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type,
        recv_is_p2mp_lsp);
    name_tree_key = pccd_rpd_create_name_tree_key(recv_lsp_type_info->setup_type, 
        recv_lsp_type_info->sub_type, recv_is_p2mp_lsp);
    rpd_lsp = pccd_rpd_get_lsp_by_name_and_preference(lsp_full_name, name_tree_key.type, 
        name_tree_key.sub_type);

    pccd_rpd_update_instance(rpd_lsp, LAST_PC_REQ_RPT);

    if(rpd_lsp)
    {
        bool existing_is_p2mp = (rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP);
        bool lsp_setup_types_same = pccd_rpd_is_update_received_for_existing_lsp(rpd_lsp->setup_type, rpd_lsp->sub_type,
            existing_is_p2mp, recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type,
            recv_is_p2mp_lsp);

        /**
         * LSP is not same even if lsp type changes from Externally provisioned to
         * locally controlled or delegated
         */
        bool lsp_type_change_for_pce_init = (rpd_lsp->type == LSP_TYPE_EXTERNALLY_PROVISIONED) ?
            (lsp_config_status->type != LSP_TYPE_EXTERNALLY_PROVISIONED) : false;

        curr_rpd_lsp = rpd_lsp;

        if (lsp_setup_types_same && (!lsp_type_change_for_pce_init)) {

                TRACE_RPD("Received update to existing LSP");
                if (pccd_rpd_sr_color_endpoint_changed(handle, lsp_config_status, rpd_lsp)) {
                   curr_rpd_lsp = NULL;  //Existing SR LSP is deleted due to color/ end-point change
                }

            } else {
            TRACE_RPD("Received lsp with new setup_type/sub_type/p2mp status: recv_type is %d, \
                recv_sub_type is %d  and recv p2mp status is %d. Existing setup_type is %d, \
                existing sub_type is %d and existing p2mp status is %d", 
                recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, recv_is_p2mp_lsp,
                rpd_lsp->setup_type, rpd_lsp->sub_type, existing_is_p2mp);

            if((LSP_TYPE_EXTERNALLY_PROVISIONED != lsp_config_status->type) && 
                (LSP_TYPE_EXTERNALLY_PROVISIONED != rpd_lsp->type)) {
                if(pccd_rpd_compare_priority_of_lsps_with_same_name(rpd_lsp, 
                    recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type)) {
                    TRACE_RPD("Deleting existing LSP from local Cache and adding reveived lsp");
                    pccd_rpd_lsp_del(handle,lsp_config_status->name, 
                        lsp_config_status->path_name);
                    curr_rpd_lsp = NULL;
                } else {
                    TRACE_RPD("LSP in local Cache has higher priority than received LSP, \
                        ignoring received pcrequest message");
                    TRACE_FUNCTION_RETURN();
                    }
            } else if((LSP_TYPE_EXTERNALLY_PROVISIONED == lsp_config_status->type) && 
                (LSP_TYPE_EXTERNALLY_PROVISIONED != rpd_lsp->type)) {
                    TRACE_RPD("LSP in local Cache has higher priority than received \
                        externally provisioned LSP, ignoring received pcrequest message");
                    TRACE_FUNCTION_RETURN();
            } else {
                TRACE_RPD("Received locally created LSP is having same name as externally \
                    provisioned LSP in db");
                curr_rpd_lsp = NULL;
            }
        }
    } else {
        TRACE_RPD("New LSP request received");
    }

    pccd_rpd_pcreq_status(curr_rpd_lsp, handle, pccd_msg->context,
                          pccd_msg->return_code,
                          &pccd_msg->lsp_config_status);

    if (lsp_config_status->install_prefix_info) {
        free(lsp_config_status->install_prefix_info);
        lsp_config_status->install_prefix_info = NULL;
    }

    if (lsp_config_status->optimization_metric_list) {
        free(lsp_config_status->optimization_metric_list);
        lsp_config_status->optimization_metric_list = NULL;
    }

    if (lsp_config_status->bound_metric_list) {
        free(lsp_config_status->bound_metric_list);
        lsp_config_status->bound_metric_list = NULL;
    }

    if (lsp_config_status->actual_metric_list) {
        free(lsp_config_status->actual_metric_list);
        lsp_config_status->actual_metric_list = NULL;
    }

    TRACE_FUNCTION_EXIT();
}

void
pccd_rpd_lsp_del_recv(rpd_session_handle handle,
                      u_int8_t *msg, u_int msg_length)
{
    pccd_rpd_name_tree_key name_tree_key;
    rpd_msg_extctrl_lsp_request_t *del_msg;
    rpd_msg_extctrl_lsp_request_t delete_msg;
    lsp_type_info_t *recv_lsp_type_info;
    struct pccd_rpd_lsp_info *rpd_lsp = NULL;
    char lsp_full_name[RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)];

    TRACE_FUNCTION_ENTRY();

    bzero(lsp_full_name, (RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1)));

    bzero(&delete_msg, sizeof(delete_msg));
    del_msg = &delete_msg;
    recv_lsp_type_info = &del_msg->lsp_type_info;
    if (!pccd_rpd_decode_lsp_request(msg, msg_length,
                                     &delete_msg)) {
        TRACE_RPD("Could not decode lsp request in lsp_del message");
        TRACE_FUNCTION_RETURN();
    }

    TRACE_RPD("setup_type = %d , sub_type = %d, is_p2mp_lsp = %d", recv_lsp_type_info->setup_type,
        recv_lsp_type_info->sub_type,del_msg->is_p2mp_lsp);

    name_tree_key = pccd_rpd_create_name_tree_key(recv_lsp_type_info->setup_type, 
        recv_lsp_type_info->sub_type, del_msg->is_p2mp_lsp);

    pccd_rpd_get_lsp_name(lsp_full_name, RPD_LSP_NAME_PATH_NAME_COUNT*(RPD_LSP_NAME_SIZE +1), 
        del_msg->name, del_msg->path_name);

    rpd_lsp = pccd_rpd_get_lsp_by_name_and_preference(lsp_full_name, name_tree_key.type, 
        name_tree_key.sub_type);
    if(rpd_lsp) {
        bool existing_is_p2mp = (rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP);

        if(pccd_rpd_is_update_received_for_existing_lsp(rpd_lsp->setup_type, rpd_lsp->sub_type,
            existing_is_p2mp, recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type,
            del_msg->is_p2mp_lsp)) {
            TRACE_RPD("RPD's delete request processing for %s: recv_setup_type is %d, \
                recv_subtype is %d and recv_is_p2mp_lsp is %d", 
                lsp_full_name, 
                recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, del_msg->is_p2mp_lsp);
            } else {
            TRACE_RPD("RPD's delete request ignored for '%s' as received setup_type \
                 or sub_type or p2mp status doesnt match with existing lsp in database \
                 recv_setup_type is %d, recv_sub_type is %d and recv_p2mp_status is %d \
                Existing setup_type is %d, existing sub_type is %d, existing p2mp status is %d",
                lsp_full_name, 
                recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, del_msg->is_p2mp_lsp,
                rpd_lsp->setup_type, rpd_lsp->sub_type, existing_is_p2mp);
            TRACE_FUNCTION_RETURN();
        }
    } else {
        TRACE_RPD("RPD's delete request ignored as '%s' is not present in local LSP cache", 
            lsp_full_name);
        TRACE_FUNCTION_RETURN();
    }

    pccd_rpd_lsp_del(handle, del_msg->name, del_msg->path_name);
    TRACE_FUNCTION_EXIT();
}

void
pccd_rpd_lsp_err_recv(rpd_session_handle handle,
                      u_int8_t *msg, u_int msg_length)
{
    pccd_rpd_name_tree_key name_tree_key;
    rpd_msg_extctrl_lsp_error_t *err_msg;
    rpd_msg_extctrl_lsp_error_t error_msg;
    lsp_type_info_t *recv_lsp_type_info;
    bool is_p2mp_lsp;

    TRACE_FUNCTION_ENTRY();

    bzero(&error_msg, sizeof(error_msg));
    err_msg = &error_msg;
    recv_lsp_type_info = &err_msg->lsp_type_info;
    if (!pccd_rpd_decode_lsp_error(msg, msg_length,
                                     &error_msg)) {
        TRACE_RPD("Could not decode lsp error message");
        TRACE_FUNCTION_RETURN();
    }

    is_p2mp_lsp = (err_msg->flags & LSP_PATH_TYPE_P2MP);
    TRACE_RPD("Error message = %d, setup_type = %d , sub_type = %d, is_p2mp_lsp = %d",
        err_msg->error, recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, 
        is_p2mp_lsp);

    name_tree_key = pccd_rpd_create_name_tree_key(recv_lsp_type_info->setup_type, 
        recv_lsp_type_info->sub_type, is_p2mp_lsp);
    if(TAG_EXTCTRL_ERROR_P2MP_LSP_NAME_CONFLICT != err_msg->error) {
        struct pccd_rpd_lsp_info *rpd_lsp = pccd_rpd_get_lsp_by_name_and_preference(
            err_msg->lsp_name, name_tree_key.type, name_tree_key.sub_type);
        if(rpd_lsp) {
            bool existing_is_p2mp = (rpd_lsp->path_flags & LSP_PATH_TYPE_P2MP);

            if(pccd_rpd_is_update_received_for_existing_lsp(rpd_lsp->setup_type, 
                rpd_lsp->sub_type, existing_is_p2mp, recv_lsp_type_info->setup_type, 
                recv_lsp_type_info->sub_type, is_p2mp_lsp)) {
                TRACE_RPD("RPD's error request processing for %s: recv_setup_type is %d, \
                recv_subtype is %d and recv_is_p2mp_lsp is %d", 
                err_msg->lsp_name, recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, 
                is_p2mp_lsp);
            } else {
                TRACE_RPD("RPD's error request ignored for '%s' as received setup_type \
                 or sub_type or p2mp status doesnt match with existing lsp in database \
                 recv_setup_type is %d, recv_sub_type is %d and recv_p2mp_status is %d \
                Existing setup_type is %d, existing sub_type is %d, existing p2mp status is %d",
                err_msg->lsp_name, 
                recv_lsp_type_info->setup_type, recv_lsp_type_info->sub_type, is_p2mp_lsp,
                rpd_lsp->setup_type, rpd_lsp->sub_type, existing_is_p2mp);

                TRACE_FUNCTION_RETURN();
            }
        } else {
            TRACE_RPD("RPD's error request ignored as '%s' is not present in local LSP cache", 
                err_msg->lsp_name);
            TRACE_FUNCTION_RETURN();
        }

            pccd_rpd_lsp_err(handle, rpd_lsp, NULL, err_msg->error);
        } else {
            struct pccd_p2mp_lsp_info *p2mp_lsp = pccd_get_p2mp_lsp_by_name(
                err_msg->lsp_name);
            pccd_rpd_lsp_err(handle, NULL, p2mp_lsp, err_msg->error);
        }
    TRACE_FUNCTION_EXIT();
}

/**
 * Decode a external rpd flowspec cfg/rpt message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] update_msg Decoded rpd flowspec update message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
static boolean
pccd_rpd_ipc_extr_flowspec_decode_msg (u_int8_t *msg_data, u_int16_t msg_length,
                           rpd_msg_extr_flow_spec_update_t *update_msg)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTR_FLOW_SPEC_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int tlv_len;
    rpd_extr_flow_spec_info_t *rpd_fs_info;
    struct in_addr src_addr, grp_addr;

    if (!update_msg) {
        return FALSE;
    }

    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));
    rpd_fs_info = &update_msg->pupd_lsp_params;

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTR_FLOW_SPEC_TLV_MAX)) {
        return FALSE;
    }

    /*
     * Decode Client ID
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_CLIENT_ID];
    if (!tlv) {
        TRACE_RPD("Client identification tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > (RPD_LSP_NAME_SIZE + 1)) {
        TRACE_RPD("Client name too long in flowspec request");
        return FALSE;
    }
    if (tlv_len > sizeof(update_msg->lsp_controller.name)) {
        TRACE_RPD("Client identification tlv malformed in flowspec request");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, update_msg->lsp_controller.name, tlv_len);

    /* Decode per lsp context */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_CONTEXT];
    if (!tlv) {
        TRACE_RPD("LSP context tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("LSP context malformed in flowspec request");
        return FALSE;
    }
    update_msg->context = get_long(rpc_proto_tlv_data(tlv));

    /*
     * Decode FS ID
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_FS_ID];
    if (!tlv) {
        TRACE_RPD("LSP FS ID tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("LSP FS ID tlv malformed in flowspec request");
        return FALSE;
    }
    rpd_fs_info->fs_id = get_long(rpc_proto_tlv_data(tlv));
    TRACE_RPD(" FS ID %i", rpd_fs_info->fs_id);

    /* Decode lsp name */  
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_LSP_NAME];
    if (!tlv) {
        TRACE_RPD("LSP name tlv absent in flowspec report");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(rpd_fs_info->lsp_name)) {
        TRACE_RPD("LSP name tlv malformed in flowspec report");
        return FALSE;
    }
    if (tlv_len > (RPD_LSP_NAME_SIZE + 1)) {
        TRACE_RPD("LSP name too long in flowspec report");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, rpd_fs_info->lsp_name, tlv_len);
    TRACE_RPD("Received RPD Flowspec report for LSP %s", rpd_fs_info->lsp_name);

    /*
     * Decode address family
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_ADDR_FAMILY];
    if (!tlv) {
        TRACE_RPD("LSP address family tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("LSP address family tlv malformed in flowspec request");
        return FALSE;
    }
    rpd_fs_info->addr_family = get_long(rpc_proto_tlv_data(tlv));
    TRACE_RPD("  address family %i", rpd_fs_info->addr_family);

    /*
     * Decode ptnl flags
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_PTNL_FLAGS];
    if (!tlv) {
        TRACE_RPD("PTNL flags tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        TRACE_RPD("PTNL flags tlv malformed in flowspec request");
        return FALSE;
    }
    rpd_fs_info->ptnl_flags = get_long(rpc_proto_tlv_data(tlv));
    TRACE_RPD("  PTNL flags %s", rpd_extr_flowspec_flags_get_string(rpd_fs_info->ptnl_flags));

    if (rpd_fs_info->addr_family != MCAST_AF_IPV4) {
        TRACE_RPD("Address family %i not supported", rpd_fs_info->addr_family);
        return FALSE;
    }

    if ((rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_SRC_GRP) ||
        (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_WCSRC_GRP)){
        /*
         * Decode group prefix and length
         */
        tlv = tlv_array[EXTR_FLOW_SPEC_TLV_GRP_PREFIX];
        if (!tlv) {
            TRACE_RPD("LSP group prefix tlv absent in flowspec request");
            return FALSE;
        }
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(fs_prefix_info)) {
            TRACE_RPD("LSP group prefix tlv malformed in flowspec request");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        memcpy(&rpd_fs_info->mc_grp_prefix, tlv_var_data, tlv_len);
        grp_addr.s_addr = rpd_fs_info->mc_grp_prefix.ip_addr.ipv4;
        TRACE_RPD("  Group prefix %s/%i", inet_ntoa(grp_addr),
                    rpd_fs_info->mc_grp_prefix.ip_mask);
    }

    if (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_SRC_GRP) {
        /*
         * Decode source prefix and length
         */
        tlv = tlv_array[EXTR_FLOW_SPEC_TLV_SRC_PREFIX];
        if (!tlv) {
            TRACE_RPD("LSP source prefix tlv absent in flowspec request");
            return FALSE;
        }
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(fs_prefix_info)) {
            TRACE_RPD("LSP source prefix tlv malformed in flowspec request");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        memcpy(&rpd_fs_info->src_prefix, tlv_var_data, tlv_len);
        src_addr.s_addr = rpd_fs_info->src_prefix.ip_addr.ipv4;
        TRACE_RPD("  Source prefix %s/%i", inet_ntoa(src_addr),
                    rpd_fs_info->src_prefix.ip_mask);
    }

    /*
     * Decode route distinguisher upper and lower bytes
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_RD];
    if (!tlv) {
        TRACE_RPD("Route distinguisher tlv absent in flowspec request");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(fs_rd_info)) {
        TRACE_RPD("Route distinguisher tlv malformed in flowspec request");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    memcpy(&rpd_fs_info->rd, tlv_var_data, tlv_len);
    TRACE_RPD("  Route distinguisher upper bytes %u", rpd_fs_info->rd.rti_rd_upper);
    TRACE_RPD("  Route distinguisher lower bytes %u", rpd_fs_info->rd.rti_rd_lower);

    /*
     * Decode Error code
     */
    tlv = tlv_array[EXTR_FLOW_SPEC_TLV_ERR_CODE];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int32_t)) {
            TRACE_RPD("LSP Error code tlv malformed in flowspec request");
            return FALSE;
        }
        rpd_fs_info->error_code = get_long(rpc_proto_tlv_data(tlv));
        TRACE_RPD(" Error: %s",
                  rpd_extr_flowspec_error_get_string(rpd_fs_info->error_code));
    }

    return TRUE;
}

void
pccd_rpd_ipc_extr_flowspec_recv_cfg_upd (rpd_session_handle handle UNUSED,
                                     u_int8_t *msg_data, u_int msg_length)
{
    bool res;
    rpd_msg_extr_flow_spec_update_t cfg_upd_msg;
    rpd_msg_extr_flow_spec_update_t *update_msg;

    TRACE_FUNCTION_ENTRY();

    bzero(&cfg_upd_msg, sizeof(cfg_upd_msg));
    update_msg = &cfg_upd_msg;
    res = pccd_rpd_ipc_extr_flowspec_decode_msg(msg_data, (u_int16_t)msg_length, &cfg_upd_msg);
    if (!res) {
        LOGGING_ERR("Could not decode fs cfg update message from RPD");
        TRACE_RPD("Could not decode fs cfg update message");
        TRACE_FUNCTION_EXIT();
        return;
    }

    pccd_rpd_find_fs_req_msg(&update_msg->pupd_lsp_params);

    TRACE_FUNCTION_EXIT();
}

/**
 * Call back function when RPD send config report
 * of flowspec.
 *
 * @param[in] handle RPD session handle
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 */
void
pccd_rpd_ipc_extr_flowspec_recv_rpt (rpd_session_handle handle UNUSED,
                                 u_int8_t *msg_data, u_int msg_length)
{
    bool res;
    rpd_msg_extr_flow_spec_update_t rpt_msg;
    rpd_msg_extr_flow_spec_update_t *report_msg;

    TRACE_FUNCTION_ENTRY();

    bzero(&rpt_msg, sizeof(rpt_msg));
    report_msg = &rpt_msg;
    res = pccd_rpd_ipc_extr_flowspec_decode_msg(msg_data, (u_int16_t)msg_length, &rpt_msg);
    if (!res) {
        LOGGING_ERR("Could not decode fs report message from RPD");
        TRACE_RPD("Could not decode fs report message");
        TRACE_FUNCTION_RETURN();
    }

    pccd_rpd_handle_flowspec_report(&report_msg->pupd_lsp_params);
    TRACE_FUNCTION_EXIT();
}

/*
 * Helper function to display the decoded TLV from IPC msg
 * recevied from RPD for flow spec
 */
static void
pccd_rpd_ipc_extr_flowspec_display_tlv (u_int8_t *msg_data, u_int16_t msg_length)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTR_FLOW_SPEC_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int tlv_len;
    u_int32_t tlv_32bit_data;
    fs_threshold_info threshold;
    fs_rd_info rd;
    fs_prefix_info fs_ip_prefix;
    struct in_addr src_addr, grp_addr;

    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTR_FLOW_SPEC_TLV_MAX)) {
        return;
    }

    /*
     * Display lsp name
     */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_LSP_NAME];
     if (!tlv) {
         TRACE_RPD("LSP name tlv absent in flowspec update");
         return;
     }
     tlv_len = rpc_proto_tlv_data_length(tlv);
     if (tlv_len > (RPD_LSP_NAME_SIZE + 1)) {
         TRACE_RPD("LSP name too long in flowspec update");
         return;
     }
     tlv_var_data = rpc_proto_tlv_data(tlv);
     TRACE_RPD("Encoded flowspec Update for LSP %s", tlv_var_data);

     /*
      * Display address family
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_ADDR_FAMILY];
     if (!tlv) {
         TRACE_RPD("LSP address family tlv absent in flowspec update");
         return;
     }
     tlv_len = rpc_proto_tlv_data_length(tlv);
     if (tlv_len != sizeof(u_int32_t)) {
         TRACE_RPD("LSP address family tlv malformed in flowspec update");
         return;
     }
     tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
     TRACE_RPD("Encoded address family %i", tlv_32bit_data);
     
     /*
      * Display FS ID
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_FS_ID];
     if (tlv) {
         tlv_len = rpc_proto_tlv_data_length(tlv);
         if (tlv_len != sizeof(u_int32_t)) {
             TRACE_RPD("FS ID tlv malformed in flowspec update");
             return;
         }
         tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
         TRACE_RPD("Encoded FS ID %i", tlv_32bit_data);
     }

     /*
      * Display group prefix and length
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_GRP_PREFIX];
     if (tlv) {
         tlv_len = rpc_proto_tlv_data_length(tlv);
         if (tlv_len != sizeof(fs_prefix_info)) {
             TRACE_RPD("LSP group prefix tlv malformed in flowspec update");
             return;
         }
         tlv_var_data = rpc_proto_tlv_data(tlv);
         memcpy(&fs_ip_prefix, tlv_var_data, tlv_len);
         grp_addr.s_addr = fs_ip_prefix.ip_addr.ipv4;
         TRACE_RPD("Encoded  Group prefix %s/%i", inet_ntoa(grp_addr),
                     fs_ip_prefix.ip_mask);
     }

     /*
      * Display source prefix and length
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_SRC_PREFIX];
     if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(fs_prefix_info)) {
            TRACE_RPD("LSP source prefix tlv malformed in flowspec update");
            return;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        memcpy(&fs_ip_prefix, tlv_var_data, tlv_len);
        tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
        src_addr.s_addr = fs_ip_prefix.ip_addr.ipv4;
        TRACE_RPD("Encoded  Source prefix %s/%i", inet_ntoa(src_addr),
                    fs_ip_prefix.ip_mask);
      }

     /*
      * Display route distinguisher upper and lower bytes
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_RD];
     if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(fs_rd_info)) {
            TRACE_RPD("Route distinguisher tlv malformed in flowspec update");
            return;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        memcpy(&rd, tlv_var_data, tlv_len);
        TRACE_RPD("Encoded  Route distinguisher upper bytes %i", rd.rti_rd_upper);
        TRACE_RPD("Encoded  Route distinguisher lower bytes %i", rd.rti_rd_lower);
     }

     /*
      * Display segmentation threshold rate and fan out threshold
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_THRESHOLD];
     if (tlv) {
         tlv_len = rpc_proto_tlv_data_length(tlv);
         if (tlv_len != sizeof(fs_threshold_info)) {
             TRACE_RPD("Threshold tlv malformed in flowspec update");
             return;
         }
         tlv_var_data = rpc_proto_tlv_data(tlv);
         memcpy(&threshold, tlv_var_data, tlv_len);
         TRACE_RPD("Encoded  Segmentation threshold rate %i",
                            threshold.ptnl_seg_threshold_rate);
         TRACE_RPD("Encoded Fan out threshold %i",
                            threshold.ptnl_fan_out_threshold);
     }

     /*
      * Display PTNL Flags
      */
     tlv = tlv_array[EXTR_FLOW_SPEC_TLV_PTNL_FLAGS];
     if (tlv) {
         tlv_len = rpc_proto_tlv_data_length(tlv);
         if (tlv_len != sizeof(u_int32_t)) {
             TRACE_RPD("PTNL Flags tlv malformed in flowspec update");
             return;
         }
         tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
         TRACE_RPD("Encoded PTNL Flags %s", 
                rpd_extr_flowspec_flags_get_string(tlv_32bit_data));
     }
}

/**
 * Encodes a flowspec info in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] update_msg Message that needs to be encoded
 *
 * @return 0 when the message cannot be successfully decoded
 * @return length Encoded msg length
 */
static int
pccd_rpd_ipc_extr_flowspec_encode_update (u_int8_t *buf, u_int bytes_left,
                  rpd_msg_extr_flow_spec_update_t *update_msg)
{
    rpc_tlv *cur_tlv;
    u_int length;
    rpd_extr_flow_spec_info_t *rpd_fs_info;
    boolean res;

    if (!update_msg) {
        return 0;
    }

    if (!buf) {
        return 0;
    }

    cur_tlv = (rpc_tlv *)(void *)buf;
    length = 0;
    rpd_fs_info = &update_msg->pupd_lsp_params;

    /*
     * Encoding name of the controller
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_CLIENT_ID,
                                       update_msg->lsp_controller.name,
                                       strlen(update_msg->lsp_controller.name));
    if (!res) {
        return 0;
    }

    /*
     * Encode Context
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_CONTEXT,
                                       &update_msg->context,
                                       sizeof(u_int32_t));
    if (!res) {
        return 0;
    }

    /*
     * Encode lsp name
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_LSP_NAME,
                                       rpd_fs_info->lsp_name,
                                       strlen(rpd_fs_info->lsp_name));
    if (!res) {
        return 0;
    }

    /*
     * Encode FS ID
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_FS_ID,
                                       &rpd_fs_info->fs_id,
                                       sizeof(u_int32_t));
    if (!res) {
        return 0;
    }

    /*
     * Encode Address Family
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_ADDR_FAMILY,
                                       &rpd_fs_info->addr_family,
                                       sizeof(u_int32_t));
    if (!res) {
        return 0;
    }

    /*
     * Encode ptnl flags
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_PTNL_FLAGS,
                                       &rpd_fs_info->ptnl_flags,
                                       sizeof(u_int32_t));
    if (!res) {
        return 0;
    }

    if ((rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_SRC_GRP) ||
        (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_WCSRC_GRP)) {

        /*
         * Encode group prefix and length
         */
        res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                           &bytes_left, &length,
                                           EXTR_FLOW_SPEC_TLV_GRP_PREFIX,
                                           &rpd_fs_info->mc_grp_prefix,
                                           sizeof(fs_prefix_info));
        if (!res) {
            return 0;
        }
    }

    if (rpd_fs_info->ptnl_flags & RPD_EXTR_FLOW_SPEC_TYPE_S_SRC_GRP) {

        /*
         * Encode source prefixa and length
         */
        res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                           &bytes_left, &length,
                                           EXTR_FLOW_SPEC_TLV_SRC_PREFIX,
                                           &rpd_fs_info->src_prefix,
                                           sizeof(fs_prefix_info));
        if (!res) {
            return 0;
        }
    }

    /*
     * Encode route distinguisher upper and lower bytes
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_RD,
                                       &rpd_fs_info->rd,
                                       sizeof(fs_rd_info));
    if (!res) {
        return 0;
    }

    /*
     * Encode segmentation threshold rate and fan out threshold rate
     */
    res = rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                       &bytes_left, &length,
                                       EXTR_FLOW_SPEC_TLV_THRESHOLD,
                                       &rpd_fs_info->threshold,
                                       sizeof(fs_threshold_info));
    if (!res) {
        return 0;
    }

    pccd_rpd_ipc_extr_flowspec_display_tlv(buf, (u_int16_t)length);

    return length;
}

/**
 * Sends encoded flowspec info to RPD
 *
 * @param[in] handle RPD session handle
 * @param[in] context
 * @param[in] client_name client name = 'pccd'
 * @param[in] params msg that needs to be sent
 *
 * @return -1 when the message cannot be successfully sent
 * @return 0  when the message can be successfully sent
 */
int
pccd_rpd_ipc_extr_flowspec_send_update (rpd_session_handle handle, u_int32_t context,
                                const char *client_name,
                                const rpd_extr_flow_spec_info_t *params)
{
    ipc_msg_t hdr;
    rpd_msg_extr_flow_spec_update_t msg;
    u_int length;

    TRACE_FUNCTION_ENTRY();

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTR_FLOW_SPEC_UPDATE;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    msg.context = context;
    if (!client_name || strlen(client_name) >= sizeof(msg.lsp_controller.name)) {
        errno = EINVAL;
        TRACE_FUNCTION_RETURN(-1);
    }
    strncpy(msg.lsp_controller.name, client_name, sizeof(msg.lsp_controller.name));
    msg.lsp_controller.name[sizeof(msg.lsp_controller.name) - 1] = '\0';
    msg.pupd_lsp_params = *params;

    length =  pccd_rpd_ipc_extr_flowspec_encode_update(tx_buffer_ptr, TX_BUFFER_LEN, &msg);
    if (!length) {
        TRACE_RPD("pccd-rpd flow spec update msg encode failed");
        TRACE_FUNCTION_RETURN(-1);
    }

    hdr.length = (u_int16_t)length;

    TRACE_FUNCTION_RETURN(rpd_client_msg_write(handle, &hdr, tx_buffer_ptr));
}

int
pccd_rpd_ipc_extr_flowspec_send_get_all_info (rpd_session_handle handle)
{
    ipc_msg_t hdr;

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTR_FLOW_SPEC_GET_ALL;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;
    hdr.length = 0;

    return rpd_client_msg_write(handle, &hdr, NULL);
}

