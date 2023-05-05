/*
 * $Id$
 *
 * Copyright (c) 2017, Juniper Networks, Inc.
 * All rights reserved.
 */

/*
 * Define the following to make us run over the private instance.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <jnx/netinet/tcp.h>

#include <jnx/bits.h>
#include <jnx/aux_types.h>
#include <jnx/thread.h>
#include <jnx/layer3-common/accessor_inlines.h>
#include <jnx/redblack.h>
#include <jnx/patricia.h>
#include <jnx/bitmap.h>

#include <jnx/task_defines.h>
#include <jnx/task_assert.h>
#include <jnx/task_defs.h>
#include <jnx/task_basic_types.h>
#include <jnx/jsockaddr.h>
#include <jnx/task_types.h>
#include <jnx/jtrace.h>
#include <jnx/fep/mgmt_proto.h>
#include <jnx/task_mgmt.h>
#include <jnx/task.h>
#include <jnx/task_mem.h>
#include <jnx/task_daemon.h>
#include <jnx/task_module.h>
#include <jnx/bit_hi_lo.h>
#include <jnx/task_radix.h>
#include <jnx/task_queue.h>
#include <jnx/jsockaddr_mc.h>
#include <jnx/jsockaddr_composite.h>

#include <jnx/inttypes.h>
#include <jnx/rpd-common/common_types.h>
#include <jnx/pol_types.h>
#include <jnx/rpd-pol/pol_types.h>
#include <jnx/rpd-rt/rt_types.h>
#include <jnx/jnx_types.h>
#include <jnx/rpd-if/if_types.h>
#include <jnx/rpd-krt/krt_types.h>
#include <jnx/rpd-mc/mc_types.h>
#include <jnx/rpd-mpls/tag_types.h>

#include <net/if_types.h>
#include <jnx/ipc_types.h>
#include <jnx/jipc/ipc.h>
#include <jnx/librpd/shared.h>
#include <jnx/librpd/lspinfo.h>
#include <jnx/librpd/ipc_rpd.h>
#include <jnx/librpd/librpd.h>



#include <jnx/rpd-rt/rt_table_api.h>

#include <jnx/bit_vector.h>
#include <jnx/task_time.h>
#include <jnx/task_timers.h>
#include <jnx/task_stdio.h>
#include <jnx/rpd-rt/rt_resolve_public.h>
#include <jnx/rpd-rt/rt_table.h>
#include <jnx/rpd-rt/rt_table_structs.h>

#include <jnx/rpd-if/if_api.h>
#include <jnx/task_io.h>
#include <jnx/jsockaddr_inet.h>
#include <jnx/jsockaddr_inet6.h>
#include <jnx/librpd/dns.h>
#include <jnx/rpd-ip/ipv6_ra.h>
#include <jnx/rpd-ip/ipv6_ra_config_objs.h>
#include <jnx/rpd-if/if.h>
#include <jnx/jsockaddr_dli.h>
#include <jnx/rpd-rt/gw_sel.h>
#include <jnx/route_filter.h>
#include <jnx/rpd-rt/rt_nexthops_template.h>
#include <jnx/policy.h>
#include <jnx/rpd-pol/policy.h>
#include <jnx/rpd-krt/krt_inh.h>

#include <jnx/interface_info_pan.h>
#include <jnx/rpd-krt/krt_var.h>

#include <jnx/rpd-ctx/rpd_vector.h>
#include <jnx/rpd-ctx/app_ctx.h>
#include <jnx/rpd-pol/aspath.h>

#include <jnx/jsockaddr_inetvpn.h>

#include <jnx/task_lr.h>
#include <jnx/jsockaddr_un.h>
#include <jnx/task_job.h>
#include <jnx/rt_table.h>

#include <jnx/rpd-rt/rt_walk.h>
#include <jnx/rpd-krt/krt.h>
#include <jnx/rpd-krt/krt_cnh.h>
#include <jnx/rpd-krt/krt_var.h>
#include <jnx/rpd-common/mgmt_config.h>
#include <jnx/rpd-pol/com.h>
#include <jnx/rpd-mpls/mpls_tag.h>
#include <jnx/rpd-mpls/mpls_tag_element.h>
#include <jnx/task_nsr.h>
#include <jnx/rpd-rt/lsys_nsr.h>
#include <jnx/rpd-rt/rpd_server.h>
#include <jnx/rpd-rt/rpd_server_extctrl.h>
#include <jnx/nh_shared_pan.h>
#include <jnx/ipc_types_defs.h>
#include <jnx/interface_info_pan.h>
#include <jnx/rt_shared_pan.h>
#include <jnx/jnx_paths.h>
#include <jnx/task_string.h>
#include <jnx/rpd-rt/rpd_mdiagd_extern.h>
#include <rtsock/rnh_comp_pan.h>

#include <jnx/rpd-spring-te/spring_te_addr.h>
#include <jnx/librpd/shared.h>
#include <jnx/dfw_shared.h>
//#include <jnx/bandwidth.h>
#include <jnx/pol_types.h>
#include <jnx/layer3-common/gmpls.h>
//#include <jnx/lmp.h>
//#include <jnx/lsping_common.h>
#include <jnx/ppm/bfd_hdr.h>
#include <jnx/ppm/bfd_tnl.h>
#include <jnx/ppm/bfd_proto_defs.h>
#include <jnx/ppm/rpc_proto.h>
#include <itable/itable.h>

#include "rt_nexthop_gen_hdr.h"
#include "rt_table_private.h"
#include "gw.h"
#include "rpd_server_pvt.h"
#include "rpd_mdiagd.h"
#include "rt_ribgroups_pvt.h"
#include <jnx/rpd-rt/rpd_mdiagd_extern.h>

#include <jnx/rpd-spring-te/spring_te_addr.h>
#include <jnx/rpd-spring-te/spring_te_cfgdb.h>
#include <jnx/rpd-spring-te/spring_te.h>

#include "rpd_server_extctrl_pvt.h"
#include "rt_startup.h"

/*
 * File local definitions
 */
TASK_TLS u_int8_t *tx_buffer_ptr;
static TASK_TLS char * sr_ero_str; /* Buffer to hold stringized SR-ERO's */

struct rpd_server_extctrl_vector_s
		*rpd_server_extctrl_vector[RPD_EXTCTRL_LSP_SETUP_TYPE_MAX];

void rpd_server_extctrl_set_vector(extctrl_setup_type type,
									rpd_server_extctrl_vector_t *vector)
{
	if (type < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX) {
		rpd_server_extctrl_vector[type] = vector;
    }
}

static void
rpd_server_extctrl_print_str (const char *str_to_print, char **str, int *len)
{
    int n;

    n = task_snprintf(*str, *len, "%s", str_to_print);

    (*str) += n;
    (*len) -= n;
}

static void
rpd_server_extctrl_print_uint (unsigned u, char **str, int *len)
{
    int n;

    n = task_snprintf(*str, *len, "%u", u);

    (*str) += n;
    (*len) -= n;
}

static void
rpd_server_extctrl_print_ipv4 (uint32_t ip_addr, char **str, int *len)
{
    int n;
    char s[16];

    inet_ntop(AF_INET, &ip_addr, s, sizeof(s));
    n = task_snprintf(*str, *len, "%s", s);

    (*str) += n;
    (*len) -= n;
}

static void
rpd_server_extctrl_print_ipv6 (u_int8_t *ip_addr, char **str, int *len)
{
    int n;
    char s[48];

    inet_ntop(AF_INET6, ip_addr, s, sizeof(s));
    
    n = task_snprintf(*str, *len, "%s", s);

    (*str) += n;
    (*len) -= n;
}

static void
rpd_server_extctrl_rpd_sr_ero_nai_to_str (rpd_sr_ero_nai_t *nai, char **str,
					  int *len)
{
    rpd_sr_ero_nai_ipv4_adj_t *ipv4_adj;
    rpd_sr_ero_nai_ipv6_adj_t *ipv6_adj;
    rpd_sr_ero_nai_unnum_t *unnum;
    
    switch (nai->rsen_type) {
      case RPD_SR_ERO_NAI_TYPE_ABSENT:
	rpd_server_extctrl_print_str("No NAI", str, len);
	break;
      case RPD_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
	rpd_server_extctrl_print_str("IPv4 Node:", str, len);
	rpd_server_extctrl_print_ipv4(nai->u.rsen_node_ipv4_addr, str, len);
	break;
	break;
      case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
	rpd_server_extctrl_print_str("IPv6 Node:", str, len);
	rpd_server_extctrl_print_ipv6(nai->u.rsen_node_ipv6_addr, str, len);
	break;
      case RPD_SR_ERO_NAI_TYPE_IPV4_ADJ_ID :
	rpd_server_extctrl_print_str("IPv4 Adj:", str, len);
	ipv4_adj = &nai->u.rsen_adj_ipv4;
	rpd_server_extctrl_print_ipv4(ipv4_adj->rsen_local_addr, str, len);
	rpd_server_extctrl_print_str("->", str, len);
	rpd_server_extctrl_print_ipv4(ipv4_adj->rsen_remote_addr, str, len);
	break;
      case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
	rpd_server_extctrl_print_str("IPv6 Adj:", str, len);
	ipv6_adj = &nai->u.rsen_adj_ipv6;
	rpd_server_extctrl_print_ipv6(ipv6_adj->rsen_local_addr, str, len);
	rpd_server_extctrl_print_str("->", str, len);
	rpd_server_extctrl_print_ipv6(ipv6_adj->rsen_remote_addr, str, len);
	break;
      case RPD_SR_ERO_NAI_TYPE_UNNUMBERED:
	rpd_server_extctrl_print_str("Unnumbered:", str, len);
	unnum = &nai->u.rsen_unnumbered;
	rpd_server_extctrl_print_ipv4(unnum->rsen_local_node_id, str, len);
	rpd_server_extctrl_print_uint(ntohl(unnum->rsen_local_intf_id), str, len);
	rpd_server_extctrl_print_ipv4(unnum->rsen_remote_node_id, str, len);
	rpd_server_extctrl_print_uint(ntohl(unnum->rsen_remote_intf_id), str, len);
	break;
      default:
	rpd_server_extctrl_print_str("???", str, len);
    }
}

static void
rpd_server_extctrl_rpd_srv6_ero_nai_to_str (rpd_sr_ero_nai_t *nai, char **str,
                      int *len)
{
    rpd_sr_ero_nai_ipv6_adj_t *ipv6_adj;
    rpd_sr_ero_nai_ipv6_linklocal_adj_t *ipv6_linklocal_adj;

    switch (nai->rsen_type) {
      case RPD_SR_ERO_NAI_TYPE_ABSENT:
    rpd_server_extctrl_print_str("No NAI", str, len);
    break;
      case RPD_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
    rpd_server_extctrl_print_str("IPv6 Node:", str, len);
    rpd_server_extctrl_print_ipv6(nai->u.rsen_node_ipv6_addr, str, len);
    break;
      case RPD_SR_ERO_NAI_TYPE_IPV6_ADJ_ID:
    rpd_server_extctrl_print_str("IPv6 Adj:", str, len);
    ipv6_adj = &nai->u.rsen_adj_ipv6;
    rpd_server_extctrl_print_ipv6(ipv6_adj->rsen_local_addr, str, len);
    rpd_server_extctrl_print_str("->", str, len);
    rpd_server_extctrl_print_ipv6(ipv6_adj->rsen_remote_addr, str, len);
    break;
      case RPD_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
    rpd_server_extctrl_print_str("Ipv6 LinkLocal Adj:", str, len);
    ipv6_linklocal_adj = &nai->u.rsen_linklocal_adj_ipv6;
    rpd_server_extctrl_print_ipv6(ipv6_linklocal_adj->rsen_local_node_addr, str, len);
    rpd_server_extctrl_print_uint(ntohl(ipv6_linklocal_adj->rsen_local_intf_id), str, len);
    rpd_server_extctrl_print_ipv6(ipv6_linklocal_adj->rsen_remote_node_addr, str, len);
    rpd_server_extctrl_print_uint(ntohl(ipv6_linklocal_adj->rsen_remote_intf_id), str, len);
    break;
      default:
    rpd_server_extctrl_print_str("???", str, len);
    }
}

static void
rpd_server_extctrl_rpd_sr_ero_sid_to_str (rpd_sr_ero_sid_t *sid, char **str,
					  int *len)
{
    u_int32_t val;
    
    switch (sid->rses_type) {
      case RPD_SR_ERO_SID_TYPE_NONE:
	rpd_server_extctrl_print_str("No SID", str, len);
	break;
      case RPD_SR_ERO_SID_TYPE_INDEX:
	rpd_server_extctrl_print_str("Index:", str, len);
	val = ntohl(sid->u.rses_index);
	rpd_server_extctrl_print_uint(val, str, len);
	break;
      case RPD_SR_ERO_SID_TYPE_LABEL_20:
	rpd_server_extctrl_print_str("L-20:", str, len);
	val = sid->u.rses_label_20;
	val = ntohl(val);
	rpd_server_extctrl_print_uint(val, str, len);
	break;
      case RPD_SR_ERO_SID_TYPE_LABEL_32:
	rpd_server_extctrl_print_str("L-32:", str, len);
	val = ntohl(sid->u.rses_label_32);
	rpd_server_extctrl_print_uint(val, str, len);
	break;
      default:
	break;
    }
}

static void
rpd_server_extctrl_rpd_srv6_ero_sid_to_str (rpd_sr_ero_sid_t *sid, char **str,
                      int *len)
{
    switch (sid->rses_type) {
      case RPD_SR_ERO_SID_TYPE_NONE:
    rpd_server_extctrl_print_str("No SID", str, len);
    break;
      case RPD_SR_ERO_SID_TYPE_SRV6: {
          rpd_server_extctrl_print_str("SRv6:", str, len);
          rpd_server_extctrl_print_ipv6(sid->u.rses_addr, str, len);
      }
    break;
      default:
          rpd_server_extctrl_print_str("??", str, len);
    break;
    }
}

static void
rpd_server_extctrl_rpd_sr_ero_to_str (rpd_sr_ero_t *ero, char **str, int *len)
{
    rpd_server_extctrl_print_str("[ ", str, len);
    rpd_server_extctrl_print_str(ero->rse_loose ? "L, " : "S, ", str, len);
    
    rpd_server_extctrl_rpd_sr_ero_nai_to_str(&ero->rse_nai, str, len);
    rpd_server_extctrl_print_str(",", str, len);
    rpd_server_extctrl_rpd_sr_ero_sid_to_str(&ero->rse_sid, str, len);
    
    rpd_server_extctrl_print_str(" ]", str, len);
}

static void
rpd_server_extctrl_rpd_srv6_ero_to_str (rpd_sr_ero_t *ero, char **str, int *len)
{
    rpd_server_extctrl_print_str("[ ", str, len);
    rpd_server_extctrl_print_str(ero->rse_srv6_loose ? "L, " : "S, ", str, len);
    rpd_server_extctrl_print_uint(ero->rse_srv6_sid_verification, str, len);
    rpd_server_extctrl_print_str(", ", str, len);
    rpd_server_extctrl_print_uint(ero->rse_srv6_endpoint_behavior, str, len);
    rpd_server_extctrl_print_str(", ", str, len);

    rpd_server_extctrl_rpd_srv6_ero_nai_to_str(&ero->rse_nai, str, len);
    rpd_server_extctrl_print_str(",", str, len);
    rpd_server_extctrl_rpd_srv6_ero_sid_to_str(&ero->rse_sid, str, len);

    rpd_server_extctrl_print_str(" ]", str, len);
}

static void
rpd_server_sr_ero_to_str(rpd_sr_ero_list_t *ero_list, char *str)
{
    unsigned i;
    int len = 1020;
    rpd_sr_ero_t *ero;

    if (NULL == ero_list) {
        goto end_ero_list_str;
    }

    if (ero_list->rsel_type == RPD_SR_ERO_LIST_SRMPLS) {
        for (i = 0; i < ero_list->rsel_n_eros && len > 1; ++i) {
            ero = &ero_list->rsel_ero[i];
            rpd_server_extctrl_rpd_sr_ero_to_str(ero, &str, &len);
        }
    } else {
        for (i = 0; i < ero_list->rsel_n_eros && len > 1; ++i) {
            ero = &ero_list->rsel_ero[i];
            rpd_server_extctrl_rpd_srv6_ero_to_str(ero, &str, &len);
        }
    }

  end_ero_list_str:
    *str = '\0';
}

/*
 * Get displayed string for LSP flags
 *
 * @param[in] flags  LSP flags
 *
 * @return Displayed string for LSP flags
 */
static const char *
rpd_server_extctrl_get_lsp_flags (u_int8_t flags)
{
    if (!flags) {
        return "0";
    }

    if (BIT_ISSET(flags, TAG_EXTCTRL_LSP_FLAGS_DELETE)) {
        return "Delete";
    }

    return "";
}

/*
 * Get displayed string for LSP PATH flags
 *
 * @param[in] flags  LSP PATH flags
 *
 * @return Displayed string for LSP PATH flags
 */
static const char *
rpd_server_extctrl_lsp_path_flags_get_string (u_int16_t flags)
{

    if (!flags) {
        return "0";
    }

    if (BIT_ISSET(flags, LSP_PATH_TYPE_PRIMARY)) {
        return "Primary ";
    }
    if (BIT_ISSET(flags, LSP_PATH_TYPE_SECONDARY)) {
        return "Secondary ";
    }
    if (BIT_ISSET(flags, LSP_PATH_TYPE_SECONDARY_STANDBY)) {
        return "Secondary standby";
    }
    /*
     * FIXME: add the below code when we have scripts to cover those(read
     * 100% cc)
     */
#if 0
    if (BIT_ISSET(flags, LSP_PATH_STATE_ASSOCIATION_REMOVED)) {
	return "assc removed";
    }
    if (BIT_ISSET(flags, LSP_PATH_TYPE_AUTOBW)) {
        return  "autobw";
    }
    if (BIT_ISSET(flags, LSP_PATH_TYPE_TE_PLUS_PLUS)) {
        return "te++";
    }
    if (BIT_ISSET(flags, LSP_PATH_TYPE_P2MP)) {
        return "p2mp";
    }
#endif

    return "";
}

/* Print rpd_sr_ero_list_t  info */
static void
rpd_server_extctrl_print_srte_ero_info(void *srte_multi_segment, u_int8_t total_srte_segment_list){
    u_int8_t count = 0;
    rpd_sr_ero_list_t *srte_ero_list;
    srte_ero_list =  (rpd_sr_ero_list_t *)srte_multi_segment;
    while (count < total_srte_segment_list) {
        char ero_str1[1024];
        rpd_server_sr_ero_to_str(srte_ero_list, ero_str1);
        rpd_server_trace_general(" SRTE-ERO[%d] Number of ERO--->%d Path id---> %d  Type --> %s  State -->%s ",
                                   count+1, srte_ero_list->rsel_n_eros, srte_ero_list->rsel_path_id,
                                   rpd_server_extctrl_lsp_path_flags_get_string(srte_ero_list->resel_path_flags),
                                   tag_extctrl_lsp_state_get_string(srte_ero_list->rsel_op_state));
        rpd_server_trace_general("          %s", ero_str1);
        srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
        count++;
    }
}

static void
rpd_server_extctrl_print_assoc_info (lsp_association_info info[], u_int32_t num_assoc_info)
{
    u_int32_t count = 0;
    while (count < num_assoc_info) {
        char assoc_src[INET6_ADDRSTRLEN];
        char assoc_src_v4[INET_ADDRSTRLEN];

        if (info[count].is_assoc_src_ipv6) {
            if(!inet_ntop(AF_INET6, info[count].assoc_source_u.v6,
                          assoc_src, sizeof(assoc_src))) {
                strlcpy(assoc_src, "<unknown>", sizeof(assoc_src));
            }
        } else {
            if (!inet_ntop(AF_INET,  &info[count].assoc_source_u.v4,
                           assoc_src_v4, INET_ADDRSTRLEN)) {
                strlcpy(assoc_src, "<unknown>", sizeof(assoc_src));
            }
        }

        rpd_server_trace_general("count %u grp_id %u, source:%s type %u", count,
                info[count].assoc_grp_id, assoc_src, info[count].assoc_type);

        if ( info[count].assoc_type == LSP_ASSOCIATION_TYPE_SRPAG ) {
            char origiator_address[INET6_ADDRSTRLEN];

            if(!inet_ntop(AF_INET6, info[count].sr_srpag_t.originator_addr_u.v6,
                    origiator_address, sizeof(origiator_address))) {
                if (!inet_ntop(AF_INET,  &info[count].sr_srpag_t.originator_addr_u.v4,
                        origiator_address, INET_ADDRSTRLEN)) {
                    strlcpy(origiator_address, "<unknown>", sizeof(origiator_address));
                }
            }
            rpd_server_trace_general("color:%u, proto origin:%u, originator asn: %u,"
                "originator ip: %s, discriminator: %u",
            info[count].sr_srpag_t.color, info[count].sr_srpag_t.sr_proto_origin, 
            info[count].sr_srpag_t.originator_asn, origiator_address,
            info[count].sr_srpag_t.discriminator );

            if (info[count].sr_srpag_t.preference_valid) {
                rpd_server_trace_general("preference:%u", info[count].sr_srpag_t.preference);
            }
        }
        count++;
    }
}

/*
 * Display LSP config status parameters
 *
 * @param[in] lcs       Pointer to config status parameters
 * @param[in] print_str String to be displayed
 */
void
rpd_server_extctrl_display_config_status (rpd_extctrl_lsp_config_status_info_t *lcs,
					  const char *print_str)
{
    const char *ero_str;
    const char *ero_type;
    lsp_type_info_t *lsp_type_info = &lcs->lsp_type_info;
    char src[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];

    memset(src, 0, INET6_ADDRSTRLEN);
    memset(dest, 0, INET6_ADDRSTRLEN);

    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = (in_addr_t) lcs->srcaddr_u.v4;
        dst_addr.s_addr = (in_addr_t) lcs->dstaddr_u.v4;
        memcpy(src, inet_ntoa(src_addr), 20);
        memcpy(dest, inet_ntoa(dst_addr), 20);
    } else {
        struct in6_addr srcv6_addr, dstv6_addr;
        memcpy(&srcv6_addr, lcs->srcaddr_u.v6, 16);
        memcpy(&dstv6_addr, lcs->dstaddr_u.v6, 16);
        inet_ntop(AF_INET6, &srcv6_addr, src, sizeof(src));
        inet_ntop(AF_INET6, &dstv6_addr, dest, sizeof(dest));
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE) 
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
	ero_type = "ERO";
	ero_str = APP_CTX_PROTO_RETCALLDEF(rsvp_show_rro, char *, "",
					   lcs->ero_info);
    } else if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
                (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {
	ero_type = "SR-ERO";
        ero_str = "";
    } else {
	ero_type = "Unknown ERO Type";
	ero_str = "";
    }

    rpd_server_trace_general("%s parameters for LSP %s %s, setup type %u,"
			     "src %s, dst %s, type %s, "
			     "flags %s, bandwidth %qu bps, admin grp (exclude "
			     "- %" PRIu32 ", include any - %" PRIu32 ", include "
			     "all - %" PRIu32 "), max-segment-list %u, setup priority %u, hold priority %u"
			     "local_cspf %"PRIu8 ",%s %s, path flags: 0x%x, binding type %"PRIu16
			     ", binding value %"PRIu32 " num association info %"PRIu32 " ,ERO %s",
			     print_str,
			     lcs->name, lcs->path_name, lsp_type_info->setup_type,
			     src, dest,
			     tag_extctrl_lsp_type_get_string(lcs->type),
			     rpd_server_extctrl_get_lsp_flags(lcs->lsp_flags),
			     lcs->bandwidth,
			     lcs->relcsi_admin_grp_exclude_any,
			     lcs->relcsi_admin_grp_include_any,
			     lcs->relcsi_admin_grp_include_all,
                             lcs->max_segment_list,
			     lcs->setup_prio, lcs->hold_prio,
			     lcs->relcsi_local_cspf,
			     ero_type, ero_str,
			     lcs->path_flags,
			     lcs->lsp_binding_sid.binding_type,
			     lcs->lsp_binding_sid.binding_value,
			     lcs->num_assoc_info,
			     ero_str);

    if ((lcs->srte_total_ero_count) &&
        ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
        (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE))) {
            rpd_server_extctrl_print_srte_ero_info(lcs->srte_ero_info, lcs->srte_total_ero_count);
    }

    if (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        rpd_server_trace_general("bypass parameters: protected nexhtop %zi,"
                     "protection %u (node=1, link=0), Subsc rate %"PRIu32,
                     ntohl(lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr),
                     lcs->rbyp_params.rbp_prot_type, lcs->rbyp_params.rbp_subscr);
    }

    rpd_server_extctrl_print_assoc_info (lcs->assoc_info, lcs->num_assoc_info);

}

/**
 * rpd_server_extctrl_lsp_prefix_to_str
 *
 * Get lsp prefix in string
 *
 * @param[in]  pfx_info   ptr to prefix info
 * @param[out] str_buff   string buffer to be formed
 * @param[in]  buff_size  size of string buffer
 */
static void
rpd_server_extctrl_lsp_prefix_to_str (prefix_info_t *pfx_info, char* str_buff,
                        uint32_t buff_size)
{
    unsigned i;
    int len = 0;

    if (NULL == pfx_info) {
    return;
    }

    for (i = 0; i < pfx_info->pfx_cnt; ++i) {
    len += snprintf(str_buff + len, buff_size -len, "%s/%u ",
                        inet_ntoa(pfx_info->pfx_buff[i].addr),
                        pfx_info->pfx_buff[i].mask);
    }
}

/**
 * rpd_server_extctrl_get_metric_type_string
 *
 * return metric type string
 *
 * @param[in] metric_type  metric type
 *
 * @return    Displayed string for Metric Type
 */
static const char *
rpd_server_extctrl_get_metric_type_string (u_int8_t metric_type)
{
    switch(metric_type) {
        case RPD_LSP_METRIC_TYPE_IGP:
            return "IGP";
        case RPD_LSP_METRIC_TYPE_TE:
            return "TE";
        case RPD_LSP_METRIC_TYPE_PATH_DELAY_MIN:
            return "PATH DELAY";
        case RPD_LSP_METRIC_TYPE_HOP_COUNT:
            return "HOP COUNT";
        case RPD_LSP_METRIC_TYPE_SEGMENT_LIST_DEPTH:
            return "SID DEPTH";
        default:
            return "UNKNOWN METRIC";
    }
}

/**
 * rpd_server_extctrl_lsp_optimization_metric_to_str
 *
 * Get optimiation metrics in string
 *
 * @param[in]  metric_type_list_t   ptr to optimization metric info
 * @param[out] str_buff             string buffer to be formed
 * @param[in]  buff_size            size of string buffer
 */
static void
rpd_server_extctrl_lsp_optimization_metric_to_str (metric_type_list_t *optimization_metric_info,
        char* str_buff, uint32_t buff_size)
{
    unsigned i;
    int len = 0;

    if (NULL == optimization_metric_info) {
    return;
    }

    for (i = 0; i < optimization_metric_info->list_len; i++) {
    len += snprintf(str_buff + len, buff_size -len, "%s ",
            rpd_server_extctrl_get_metric_type_string(optimization_metric_info->metric_type[i]));
    }
}

/**
 * rpd_server_extctrl_lsp_metric_list_to_str
 *
 * Get metric list in string
 *
 * @param[in]  metric_list_t   ptr to optimization metric info
 * @param[out] str_buff        string buffer to be formed
 * @param[in]  buff_size       size of string buffer
 */
static void
rpd_server_extctrl_lsp_metric_list_to_str (metric_list_t *metric_info, char* str_buff,
                        uint32_t buff_size)
{
    unsigned i;
    int len = 0;

    if (NULL == metric_info) {
    return;
    }

    for (i = 0; i < metric_info->list_len; i++) {
    len += snprintf(str_buff + len, buff_size -len, "%s:%qu ",
            rpd_server_extctrl_get_metric_type_string(metric_info->metric[i].metric_type),
            metric_info->metric[i].metric_val);
    }
}


/**
 * Display TLV contents
 *
 * @param[in] msg_data   The message
 * @param[in] msg_length Length of message
 */
static void
rpd_server_extctrl_display_tlv (u_int8_t *msg_data, u_int32_t msg_length)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int8_t *tlv_8bit_data;
    u_int8_t setup_type = RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE;
    u_int32_t tlv_32bit_data;
    u_int32_t bwh, bwl;
    u_int64_t bandwidth;
    const char *str;
    u_int32_t metric;
    u_int32_t p2mp_id;
    u_int16_t num_paths;
    u_int8_t total_srte_ero;
    u_int8_t total_srte_rro;
    prefix_info_t  *inst_pfx_info = NULL;
    u_int16_t num_assoc_info;
    metric_type_list_t *optimization_metric_info = NULL;
    metric_list_t *bound_metric_info = NULL, *actual_metric_info = NULL;
    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));

    total_srte_ero = 0;
    total_srte_rro = 0;
    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        return;
    }
    
    /* 
     * Display lsp name 
     */  
    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        rpd_server_trace_general("LSP name tlv absent");
        return;
    }
    rpd_server_trace_general("State Report for LSP %s", rpc_proto_tlv_data(tlv));
    
    /* 
     * Display lsp path name 
     */  
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_NAME];
    if (!tlv) {
        rpd_server_trace_general("  path name tlv absent");
    }else {
        rpd_server_trace_general("  path: %s ",
				 rpc_proto_tlv_data(tlv));
    }

    /* 
     * Display lsp template name
     */  
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_TEMPLATE_NAME];
    if (!tlv) {
        rpd_server_trace_general("  template name tlv absent");
    } else {
        rpd_server_trace_general("  template: %s",
				 rpc_proto_tlv_data(tlv));
    }

    /* 
     * P2mp id 
     */ 
    tlv = tlv_array[EXTCTRL_TLV_P2MP_ID];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        p2mp_id= get_long(tlv_var_data);
        rpd_server_trace_general("  p2mp Id %u", p2mp_id);
    }

    /*
     * Display src dest address type
     */
    tlv = tlv_array[EXTCTRL_TLV_SRC_DEST_ADDR_TYPE];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  src dest addr type %u", *tlv_8bit_data);
    }

    /* 
     * Display destination address
     */
    tlv = tlv_array[EXTCTRL_TLV_DEST_ADDR];
    if (tlv) {
        rpd_server_trace_general("  destination %zi", 
				 ntohl(get_long(rpc_proto_tlv_data(tlv))));
    }
    
    /* 
     * Display source address
     */
    tlv = tlv_array[EXTCTRL_TLV_SRC_ADDR];
    if (tlv) {
        rpd_server_trace_general("  source %zi", 
				 ntohl(get_long(rpc_proto_tlv_data(tlv))));
    }

    /*
     * Display type field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_TYPE];
    if (tlv) {
	str = tag_extctrl_lsp_type_get_string(get_short(rpc_proto_tlv_data(tlv)));
	rpd_server_trace_general("  type %s", str);
    }

    /*
     * Display state field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_STATE];
    if (tlv) {
	str = tag_extctrl_lsp_state_get_string(get_short(rpc_proto_tlv_data(tlv)));
        rpd_server_trace_general("  state %s", str);
    }

    /*
     * Display lsp_flags field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_FLAGS];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  lsp flags %s", 
				 rpd_server_extctrl_get_lsp_flags(*tlv_8bit_data));
    }
    
    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY];
    if (tlv) {
	tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
        rpd_server_trace_general("  admin grp exclude any %"PRIu32, tlv_32bit_data);
    }

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY];
    if (tlv) {
	tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
        rpd_server_trace_general("  admin grp include any %"PRIu32, tlv_32bit_data);
    }

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL];
    if (tlv) {
	tlv_32bit_data = get_long(rpc_proto_tlv_data(tlv));
        rpd_server_trace_general("  admin grp include all %"PRIu32, tlv_32bit_data);
    }
    
    /* 
     * Display setup priority 
     */
    tlv = tlv_array[EXTCTRL_TLV_SETUP_PRIO];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  setup priority %u", *tlv_8bit_data);
    }
    
    /* 
     * Display hold priority 
     */
    tlv = tlv_array[EXTCTRL_TLV_HOLD_PRIO];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  hold priority %u", *tlv_8bit_data);
    }
   
    /* 
     * Display bandwidth 
     */ 
    tlv = tlv_array[EXTCTRL_TLV_BANDWIDTH];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bwh = get_long(tlv_var_data);
        bwl = get_long(tlv_var_data + 4);
        bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;
        rpd_server_trace_general("  bandwidth %qu bps", bandwidth);
    }
    
    /* 
     * Display LSP ID
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_ID];
    if (tlv) {
        rpd_server_trace_general("  LSP ID %u", 
				 get_short(rpc_proto_tlv_data(tlv)));
    }
    
    /* 
     * Display Tunnel ID
     */
    tlv = tlv_array[EXTCTRL_TLV_TUNNEL_ID];
    if (tlv) {
        rpd_server_trace_general("  tunnel ID %u", 
				 get_short(rpc_proto_tlv_data(tlv)));
    }


    /* 
     * Display path ero 
     */
    tlv = tlv_array[EXTCTRL_TLV_ERO_INFO];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  ero %s",
				 APP_CTX_PROTO_RETCALLDEF(rsvp_show_rro,
							  char *, "",
							  tlv_var_data));
    }

    /* 
     * Display path rro 
     */
    tlv = tlv_array[EXTCTRL_TLV_RRO_INFO];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  rro %s",
				 APP_CTX_PROTO_RETCALLDEF(rsvp_show_rro,
							  char *,
							  "",
							  tlv_var_data));

    }
    
    /*
     * Display path_flags field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_FLAG];
    if (tlv) {
        rpd_server_trace_general("  path flags %s", 
				 rpd_server_extctrl_lsp_path_flags_get_string(get_short(rpc_proto_tlv_data(tlv))));
    }
    /*
     * Display association obj
     */
    num_assoc_info = 0;
    tlv = tlv_array[EXTCTRL_TLV_NUM_ASSOCIATION_INFO];
    if (tlv) {
	num_assoc_info = get_short(rpc_proto_tlv_data(tlv));
        rpd_server_trace_general("  number of assoc obj %u",
				 num_assoc_info);
    }

    if(num_assoc_info) {
	tlv = tlv_array[EXTCTRL_TLV_ASSOCIATION_INFO];
	if (tlv) {
	    tlv_var_data = rpc_proto_tlv_data(tlv);
	    rpd_server_extctrl_print_assoc_info((lsp_association_info *)
						tlv_var_data,
						num_assoc_info);
	}
    }
    /* 
     * newly requested bandwith for AUTO BW
     */ 
    tlv = tlv_array[EXTCTRL_TLV_PATH_AUTO_BANDWIDTH];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bwh = get_long(tlv_var_data);
        bwl = get_long(tlv_var_data + 4);
        bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;
        rpd_server_trace_general("  auto_bandwidth %qu bps", bandwidth);
    }
    /* 
     * Display metric
     */ 
    tlv = tlv_array[EXTCTRL_TLV_LSP_METRIC];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        metric = get_long(tlv_var_data);
        rpd_server_trace_general("  metric value %u", metric);
    }
    /* 
     * Display number of paths
     */ 
    tlv = tlv_array[EXTCTRL_TLV_LSP_NUM_PATHS];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        num_paths = get_short(tlv_var_data);
        rpd_server_trace_general("  number of paths %u", num_paths);
    }

    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        setup_type = *tlv_8bit_data;
        rpd_server_trace_general("  Setup type %u", setup_type);
    }

    tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  Sub type %u", *tlv_8bit_data);
    }

    tlv = tlv_array[EXTCTRL_TLV_SRTE_MAX_SEGMENT_LIST_INFO];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        num_paths = get_short(tlv_var_data);
        rpd_server_trace_general(" Max number of segment lists %u", num_paths);
    }

    tlv = tlv_array[EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        total_srte_ero = *tlv_8bit_data;
        rpd_server_trace_general("  Total no of SRTE-ERO %u", total_srte_ero);
        if (total_srte_ero) {
            tlv = tlv_array[EXTCTRL_TLV_SRTE_ERO_INFO];
            if (tlv) {
                tlv_var_data = rpc_proto_tlv_data(tlv);
                rpd_server_trace_general("SRTE MULTI ERO INFO");
                rpd_server_extctrl_print_srte_ero_info((void *)
                                                    tlv_var_data,
                                                    total_srte_ero);
            }
        }
    }

    tlv = tlv_array[EXTCTRL_TLV_SRTE_TOTAL_RRO_COUNT];
    if (tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        total_srte_rro = *tlv_8bit_data;
        rpd_server_trace_general("  Total no of SRTE-RRO %u", total_srte_rro);
        if (total_srte_rro) {
            tlv = tlv_array[EXTCTRL_TLV_SRTE_RRO_INFO];
            if (tlv) {
                tlv_var_data = rpc_proto_tlv_data(tlv);
                rpd_server_trace_general("SRTE MULTI RRO INFO");
                rpd_server_extctrl_print_srte_ero_info((void *)
                                                    tlv_var_data,
                                                    total_srte_rro);
            }
        }
    }

    tlv = tlv_array[EXTCTRL_TLV_TE_PATH_BINDING_TYPE];
    if (tlv) {
        tlv_var_data = rpc_proto_tlv_data(tlv);
        rpd_server_trace_general("  binding type %u",
                                 get_short(rpc_proto_tlv_data(tlv)));
    }

    tlv = tlv_array[EXTCTRL_TLV_TE_PATH_BINDING_VAL];
    if (tlv) {
        rpd_server_trace_general("  binding value %u",
                                 get_long(rpc_proto_tlv_data(tlv)));
    }

    /* PCE Initiated Bypass : begin */ 
    tlv = tlv_array[EXTCTRL_TLV_BYP_PROT_TYPE];
    if (tlv) {
        rpd_server_trace_general("  bypass protection type %u",
                                 rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_PRIMARY_NHOP];
    if (tlv) {
        rpd_server_trace_general("  bypass primary nexthop 0x%x",
                                 get_long(rpc_proto_tlv_data(tlv)));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_SUBSCR];
    if (tlv) {
        rpd_server_trace_general("  bypass suscription rate %d",
                                 get_long(rpc_proto_tlv_data(tlv)));
    }

    tlv = tlv_array[EXTCTRL_TLV_BYP_IN_USE];
    if (tlv) {
        rpd_server_trace_general("  bypass in use state %d",
                                 get_long(rpc_proto_tlv_data(tlv)));
    }
    /* PCE Initiated Bypass : end */ 

    tlv = tlv_array[EXTCTRL_TLV_INSTALL_PFX];
    if (tlv) {
        char print_str[2048] = {0};
        tlv_var_data = rpc_proto_tlv_data(tlv);
        inst_pfx_info = (prefix_info_t *) tlv_var_data;
        rpd_server_extctrl_lsp_prefix_to_str(inst_pfx_info, print_str,
                        sizeof(print_str));

        rpd_server_trace_general("  install-prefix count: %u, prefix: %s",
            inst_pfx_info->pfx_cnt, print_str);
    }

    /*
     * Display optimization metric
     */
    tlv = tlv_array[EXTCTRL_TLV_OPTIMIZATION_METRIC];
    if (tlv) {
        char print_str[2048] = {0};
        tlv_var_data = rpc_proto_tlv_data(tlv);
        optimization_metric_info = (metric_type_list_t *) tlv_var_data;
        rpd_server_extctrl_lsp_optimization_metric_to_str(optimization_metric_info,
                print_str, sizeof(print_str));

        rpd_server_trace_general("  optimization metric: %s", print_str);
    }

    /*
     * Display bound metric
     */
    tlv = tlv_array[EXTCTRL_TLV_BOUND_METRIC];
    if (tlv) {
        char print_str[2048] = {0};
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bound_metric_info = (metric_list_t *) tlv_var_data;
        rpd_server_extctrl_lsp_metric_list_to_str(bound_metric_info,
                print_str, sizeof(print_str));

        rpd_server_trace_general("  bound metric: %s", print_str);
    }

    /*
     * Display actual metric
     */
    tlv = tlv_array[EXTCTRL_TLV_ACTUAL_METRIC];
    if (tlv) {
        char print_str[2048] = {0};
        tlv_var_data = rpc_proto_tlv_data(tlv);
        actual_metric_info = (metric_list_t *) tlv_var_data;
        rpd_server_extctrl_lsp_metric_list_to_str(actual_metric_info,
                print_str, sizeof(print_str));

        rpd_server_trace_general("  actual metric: %s", print_str);
    }
}

/**
 * @brief
 * This is to cleanup after decoding pcupdate
 *
 * @param[in] info Pointer to config/status data structure
 */
void
rpd_server_extctrl_config_status_cleanup (rpd_extctrl_lsp_config_status_info_t *info) 
{
    if (info->ero_info) {
        task_mem_free(NULL, info->ero_info);
        info->ero_len = 0;
    }
    if (info->rro_info) {
        task_mem_free(NULL, info->rro_info);
        info->rro_len = 0;
    }
    if (info->error_spec_obj) {
        task_mem_free(NULL, info->error_spec_obj);
        info->error_spec_obj_len = 0;
    }

    if (info->srte_ero_info) {
        task_mem_free(NULL, info->srte_ero_info);
        info->srte_ero_info = NULL;
        info->srte_total_ero_count = 0;
    }
    if (info->srte_rro_info) {
        task_mem_free(NULL, info->srte_rro_info);
        info->srte_rro_info = NULL;
        info->srte_total_rro_count = 0;
    }
}

/* PCE Initiated Bypass : begin */ 
/**
 * If tlv_array contains bypass params (primary nexthop, subscription rate, 
 protection type tlv), populate it in lcs
 *
 * @param[in] tlv_array Pointer to TLV's
 * @param[in,out] lcs Configuration status structure pointer
 *
 * @return TRUE on success; FALSE on failure.
 */
static boolean
rpd_server_extctrl_decode_bypass_params (rpc_tlv *tlv_array[],
                                         rpd_extctrl_lsp_config_status_info_t *lcs)
{
    rpc_tlv *tlv;
    u_int tlv_len;
    boolean res = TRUE;

    /* 1. If Bypass Nexthop field isn't there, then nothing to do */
    tlv = tlv_array[EXTCTRL_TLV_BYP_PRIMARY_NHOP];
    if (!tlv) {  
        /* Reaching here means, it's not a bypass lsp */
        res = TRUE;
        goto end;
    }

    /* Make sure Bypass Nexthop TLV is of proper length */
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(uint32_t)) {
        rpd_server_trace_general("Bypass primary nexthop tlv malformed in pcupdate");
        res = FALSE;
        goto end;
    }

    lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr = get_long(rpc_proto_tlv_data(tlv));

    /* 2. If Bypass protection field isn't there, then nothing to do */
    tlv = tlv_array[EXTCTRL_TLV_BYP_PROT_TYPE];
    if (!tlv) {
        res = FALSE;
        goto end;
    }

    /* Make sure Bypass Nexthop TLV is of proper length */
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(uint32_t)) {
        rpd_server_trace_general("Bypass protection type tlv malformed in pcupdate");
        res = FALSE;
        goto end;
    }

    lcs->rbyp_params.rbp_prot_type = get_long(rpc_proto_tlv_data(tlv));

    /* 3. If Bypass subscription field isn't there, then nothing to do */
    tlv = tlv_array[EXTCTRL_TLV_BYP_SUBSCR];
    if (!tlv) {        
        res = FALSE;
        goto end;
    }

    /* Make sure Bypass Subscription TLV is of proper length */
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(uint32_t)) {
        rpd_server_trace_general("Bypass subscription rate tlv malformed in pcupdate");
        res = FALSE;
        goto end;
    }

    lcs->rbyp_params.rbp_subscr = get_long(rpc_proto_tlv_data(tlv));    
end:
	rpd_server_trace_general("Bypass params decode %s", 
							(res ? "success" : "failure"));
    return res;
}
/* PCE Initiated Bypass : end */ 

/**
 * If tlv_array contains metric, populate it in lcs
 *
 * @param[in] tlv_array Pointer to TLV's
 * @param[in,out] lcs Configuration status structure pointer
 *
 * @return TRUE on success; FALSE on failure.
 */
static boolean
rpd_server_extctrl_decode_lsp_metric (rpc_tlv *tlv_array[],
				      rpd_extctrl_lsp_config_status_info_t *lcs)
{
    rpc_tlv *tlv;
    u_int tlv_len;
    boolean res;

    res = TRUE;
    lcs->metric_valid = FALSE;
    
    /* If LSP metric field isn't there, then nothing to do */
    tlv = tlv_array[EXTCTRL_TLV_LSP_METRIC];
    if (!tlv) {
        goto end;
    }

    /* Make sure the TLV is of proper length */
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(lcs->metric)) {
        rpd_server_trace_general("LSP metric tlv malformed in pcupdate");
        res = FALSE;
        goto end;
	
    }

    /* Read metric from tlv_array into our data structure */
    lcs->metric = get_long(rpc_proto_tlv_data(tlv));
    lcs->metric_valid = TRUE;
    
  end:
    return res;
}

/**
 * Decode a pcupdate message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] pcupdate_msg Decoded pcupdate message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
boolean
rpd_server_extctrl_decode_pcupdate (struct rpd_server_client *rsc UNUSED,
				    u_int8_t *msg_data, u_int32_t msg_length,
				    rpd_msg_pcupdate_t *pcupdate_msg)
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
    u_int32_t params_flags;
    prefix_info_t* prefix_info = NULL;
    char src[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
    
    if (!pcupdate_msg) {
        return FALSE;
    }

    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));
    lcs = &pcupdate_msg->pupd_lsp_params;
    lsp_type_info = &lcs->lsp_type_info;
    params_flags = 0;

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        return FALSE;
    }
   
    /*
     * Decode Client ID
     */
    tlv = tlv_array[EXTCTRL_TLV_CLIENT_ID];
    if (!tlv) {
        rpd_server_trace_general("Client identification tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > (TAG_LSP_NAME_SIZE+1)) {
	rpd_server_trace_general("Client name too long in pcupdate"); 
        return FALSE;
    }
    if (tlv_len > sizeof(pcupdate_msg->lsp_controller.name)) {
	rpd_server_trace_general("Client identification tlv malformed in pcupdate"); 
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, pcupdate_msg->lsp_controller.name, tlv_len);
  
    /* Decode per lsp context */ 
    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
	rpd_server_trace_general("LSP context tlv absent in pcupdate");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        rpd_server_trace_general("LSP context malformed in pcupdate");
        return FALSE;
    }
    pcupdate_msg->context = get_long(rpc_proto_tlv_data(tlv));

    /*
     * Decode type field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_TYPE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        return FALSE;
    }
    lcs->type = get_short(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  type %d", lcs->type);
    
    /* Decode lsp name */  
    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        rpd_server_trace_general("LSP name tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > sizeof(lcs->name)) {
        rpd_server_trace_general("LSP name tlv malformed in pcupdate");
        return FALSE;
    }
    if (tlv_len > (TAG_LSP_NAME_SIZE + 1)) {
        rpd_server_trace_general("LSP name too long in pcupdate");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, lcs->name, tlv_len);
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_NAME);
    rpd_server_trace_general("Received PCUpdate for LSP %s", lcs->name);

    /*P2mp*/
    /* P2MP name decode */
    tlv = tlv_array[EXTCTRL_TLV_P2MP_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->p2mp_name)) {
            return FALSE;
        }
        if (tlv_len > (TAG_LSP_NAME_SIZE + 1)) {
            rpd_server_trace_general("P2MP LSP name too long in pcupdate");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        strncpy(lcs->p2mp_name, tlv_var_data, sizeof(lcs->p2mp_name));
        lcs->p2mp_name[sizeof(lcs->p2mp_name) - 1] = '\0';
        rpd_server_trace_general("Received PCUpdate for P2MP LSP %s", lcs->p2mp_name);
    } else {
        bzero(lcs->p2mp_name, sizeof(lcs->p2mp_name));
    }

    /*
     * Decode p2mp mbb flag field
     */
    tlv = tlv_array[EXTCTRL_TLV_P2MP_MBB_FLAG];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int16_t)) {
            return FALSE;
        }
        lcs->p2mp_mbb_flag = get_short(rpc_proto_tlv_data(tlv));
        rpd_server_trace_general(" p2mp mbb flag %d", lcs->p2mp_mbb_flag);
    }

    /* Decode lsp path name */  
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_NAME];
    if (!tlv) {
        rpd_server_trace_general("LSP path name tlv absent in pcupdate");
        bzero(lcs->path_name, sizeof(lcs->path_name));
    } else {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len > sizeof(lcs->path_name)) {
            rpd_server_trace_general("LSP path name tlv malformed in pcupdate");
            return FALSE;
        }
        if (tlv_len > (TAG_LSP_NAME_SIZE + 1)) {
            rpd_server_trace_general("LSP path name too long in pcupdate");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bcopy(tlv_var_data, lcs->path_name, tlv_len);
        BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_PATH_NAME);
        rpd_server_trace_general("Received PCUpdate for LSP %s and path %s",
				 lcs->name, lcs->path_name);
    }

    /* Decode setup type */
    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (!tlv) {
	rpd_server_trace_general("Setup-Type absent in pcupdate");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
	rpd_server_trace_general("Setup-Type tlv malformed in pcupdate");
	return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lsp_type_info->setup_type = *tlv_8bit_data;

    /* Decode sub type */
    tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
    if(tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int8_t)) {
            rpd_server_trace_general("Sub-Type tlv malformed in pcupdate");
            return FALSE;
        }
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        lsp_type_info->sub_type = *tlv_8bit_data;
    }

    /*
     * Decode lsp_flags field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_FLAGS];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->lsp_flags = *tlv_8bit_data;
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_LSPS_FLAGS);
    rpd_server_trace_general("  lsp flags %s", 
			     rpd_server_extctrl_get_lsp_flags(lcs->lsp_flags));
    if (lsp_type_info->setup_type != RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        if (BIT_ISSET(lcs->lsp_flags, TAG_EXTCTRL_LSP_FLAGS_DELETE)) {
            return TRUE;
        }
    }

    /*
    * Decode path_flags field
     */
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_FLAG];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int16_t)) {
        return FALSE;
    }
    lcs->path_flags = get_short(rpc_proto_tlv_data(tlv));
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_LSP_PATHFLAGS);
    rpd_server_trace_general("  path flags 0x%x", lcs->path_flags);
    if (BIT_ISSET(lcs->path_flags, LSP_PATH_HINT_TEAR_DOWN)) {
        return TRUE;
    }
    
    /* Decode is src dest type ipv6 */
    tlv = tlv_array[EXTCTRL_TLV_SRC_DEST_ADDR_TYPE];
    if (!tlv) {
        rpd_server_trace_general("LSP src dest type ipv6 absent in pcupdate, default is ipv4");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        rpd_server_trace_general("LSP src dest type tlv malformed in pcupdate");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->is_lsp_src_dst_addr_type_ipv6 = *tlv_8bit_data;
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_SRC_DEST_ADDR_TYPE_IPV6);
    rpd_server_trace_general("  is LSP src dest ype IPv6 %u", lcs->is_lsp_src_dst_addr_type_ipv6);

    /* 
     * Decode destination address
     */
    tlv = tlv_array[EXTCTRL_TLV_DEST_ADDR];
    if (!tlv) {
        rpd_server_trace_general("LSP destination address tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    tlv_var_data = rpc_proto_tlv_data(tlv);

    memset(dest, 0, INET6_ADDRSTRLEN);

    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        struct in_addr dst_addr;

        if (tlv_len != sizeof(u_int32_t)) {
            rpd_server_trace_general("LSP destination IPv4 address tlv malformed in pcupdate");
            return FALSE;
        }
        bcopy(tlv_var_data, &lcs->dstaddr_u.v4, tlv_len);
        dst_addr.s_addr = (in_addr_t) lcs->dstaddr_u.v4;
        memcpy(dest, inet_ntoa(dst_addr), 20);
    } else {
        struct in6_addr dstv6_addr;
        if (tlv_len != 16) {
            rpd_server_trace_general("LSP destination IPv6 address tlv malformed in pcupdate");
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->dstaddr_u.v6, tlv_len);
        memcpy(&dstv6_addr, lcs->dstaddr_u.v6, 16);
        inet_ntop(AF_INET6, &dstv6_addr, dest, sizeof(dest));
    }
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_DSTADDR);
    rpd_server_trace_general("  destination %s", dest);
    
    /* 
     * Decode source address
     */
    tlv = tlv_array[EXTCTRL_TLV_SRC_ADDR];
    if (!tlv) {
        rpd_server_trace_general("LSP source address tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    tlv_var_data = rpc_proto_tlv_data(tlv);

    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        struct in_addr src_addr;
        if (tlv_len != sizeof(u_int32_t)) {
            rpd_server_trace_general("LSP source IPv4 address tlv malformed in pcupdate");
            return FALSE;
        }
        bcopy(tlv_var_data, &lcs->srcaddr_u.v4, tlv_len);
        src_addr.s_addr = (in_addr_t) lcs->srcaddr_u.v4;
        memcpy(src, inet_ntoa(src_addr), 20);
    } else {
        struct in6_addr srcv6_addr;
        if (tlv_len != 16) {
            rpd_server_trace_general("LSP source IPv6 address tlv malformed in pcupdate");
            return FALSE;
        }
        bcopy(tlv_var_data, lcs->srcaddr_u.v6, tlv_len);
        memcpy(&srcv6_addr, lcs->srcaddr_u.v6, 16);
        inet_ntop(AF_INET6, &srcv6_addr, src, sizeof(src));
    }
    
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_SRCADDR);
    rpd_server_trace_general("  source %s", src);

    /* PCE Initiated Bypass : begin */ 
    /* Decode Bypass params */
    if (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE) {
        if (!rpd_server_extctrl_decode_bypass_params(tlv_array, lcs)) {
            return FALSE;
        }

        if (BIT_ISSET(lcs->lsp_flags, TAG_EXTCTRL_LSP_FLAGS_DELETE)) {
            return TRUE;
        }
    }
    /* PCE Initiated Bypass : end */ 

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY];
    if (!tlv) {
	rpd_server_trace_general("LSP admin grp exclude tlv absent in pcupdate");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
	rpd_server_trace_general("LSP admin grp exclude tlv malformed"
				 " in pcupdate");
	return FALSE;
    }
    lcs->relcsi_admin_grp_exclude_any = get_long(rpc_proto_tlv_data(tlv));
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_ADMIN_GRP_EXCLUDE_ANY);
    rpd_server_trace_general("  admin grp exclude %"PRIu32,
		      lcs->relcsi_admin_grp_exclude_any);

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY];
    if (!tlv) {
	rpd_server_trace_general("LSP admin grp include any tlv absent in "
				 "pcupdate");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
	rpd_server_trace_general("LSP admin grp include any tlv malformed in "
				 "pcupdate");
	return FALSE;
    }
    lcs->relcsi_admin_grp_include_any = get_long(rpc_proto_tlv_data(tlv));
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_ADMIN_GRP_INCLUDE_ANY);
    rpd_server_trace_general("  admin grp include any %"PRIu32,
		      lcs->relcsi_admin_grp_include_any);

    tlv = tlv_array[EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL];
    if (!tlv) {
	rpd_server_trace_general("LSP admin grp include all tlv absent in "
				 "pcupdate");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
	rpd_server_trace_general("LSP admin grp include all tlv malformed in"
				 "pcupdate");
	return FALSE;
    }
    lcs->relcsi_admin_grp_include_all = get_long(rpc_proto_tlv_data(tlv));
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_ADMIN_GRP_INCLUDE_ALL);
    rpd_server_trace_general("  admin grp include all %"PRIu32,
		      lcs->relcsi_admin_grp_include_all);
    
    /* Decode setup priority */
    tlv = tlv_array[EXTCTRL_TLV_SETUP_PRIO];
    if (!tlv) {
        rpd_server_trace_general("LSP setup priority tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        rpd_server_trace_general("LSP setup priority tlv malformed in pcupdate");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->setup_prio = *tlv_8bit_data;
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_SETUP_PRIO);
    rpd_server_trace_general("  setup priority %u", lcs->setup_prio);

    /* Decode hold priority */
    tlv = tlv_array[EXTCTRL_TLV_HOLD_PRIO];
    if (!tlv) {
        rpd_server_trace_general("LSP hold priority tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int8_t)) {
        rpd_server_trace_general("LSP hold priority tlv malformed in pcupdate");
        return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lcs->hold_prio = *tlv_8bit_data;
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_HOLD_PRIO);
    rpd_server_trace_general("  hold priority %u", lcs->hold_prio);

    /* Decode bandwidth */ 
    tlv = tlv_array[EXTCTRL_TLV_BANDWIDTH];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(u_int64_t)) {
            rpd_server_trace_general("LSP bandwidth tlv malformed in pcupdate");
            return FALSE;
        }
        tlv_var_data = rpc_proto_tlv_data(tlv);
        bwh = get_long(tlv_var_data);
        bwl = get_long(tlv_var_data + 4);
        lcs->bandwidth = ((bwh & 0x00000000ffffffffULL) << 32) | bwl;
        BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_BANDWIDTH);
        rpd_server_trace_general("  bandwidth %qu bps", lcs->bandwidth);
    } else {
	rpd_server_trace_general("No bandwidth in pcupdate");
    }

    tlv = tlv_array[EXTCTRL_TLV_NUM_ASSOCIATION_INFO];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        if (tlv_len != sizeof(lcs->num_assoc_info)) {
            return FALSE;
        }
        lcs->num_assoc_info = get_short(rpc_proto_tlv_data(tlv));
    }

    tlv = tlv_array[EXTCTRL_TLV_ASSOCIATION_INFO];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);
        memcpy(lcs->assoc_info, tlv_var_data, tlv_len);
    }

    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_TE)
        || (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_RSVP_BYPASS_TE)) {
	/* Decode primary path ero */
	tlv = tlv_array[EXTCTRL_TLV_ERO_INFO];
	if (tlv) {
	    tlv_len = rpc_proto_tlv_data_length(tlv);
	    tlv_var_data = rpc_proto_tlv_data(tlv);
	    lcs->ero_info = task_mem_malloc(NULL,tlv_len);
	    if (! lcs->ero_info) {
		return FALSE;
	    }
	    bcopy(tlv_var_data, lcs->ero_info, tlv_len);
	    rpd_server_trace_general("  ero is %s",
				     APP_CTX_PROTO_RETCALLDEF(rsvp_show_rro,
							      char *,
							      "",
							      lcs->ero_info));

	} else {
	    rpd_server_trace_general("No path ero in pcupdate");
	}
    } /* End RSVP-TE LSP */

    /* Grab SR-ERO for SR tunnels */
    if ((lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE) ||
        (lsp_type_info->setup_type == RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE)) {

        /* Get total number of ERO */
        tlv = tlv_array[EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT];
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        lcs->srte_total_ero_count = *tlv_8bit_data;

        /* Process ERO info if number of ero is valid */
        if (lcs->srte_total_ero_count) {
            tlv = tlv_array[EXTCTRL_TLV_SRTE_ERO_INFO];
            tlv_len = rpc_proto_tlv_data_length(tlv);
            tlv_var_data = rpc_proto_tlv_data(tlv);
            lcs->srte_ero_info = task_mem_malloc(NULL, tlv_len);
            if (!lcs->srte_ero_info) {
                return FALSE;
            }
            memcpy(lcs->srte_ero_info, tlv_var_data, tlv_len);
            rpd_server_trace_general("Received PCUpdate with %u SRTE Segment List(s)",
                                        lcs->srte_total_ero_count);
            rpd_server_extctrl_print_srte_ero_info(lcs->srte_ero_info, lcs->srte_total_ero_count);
        } else {
            rpd_server_trace_general("Received PCUpdate with no SRTE-ERO");
        }
    } /* End SR-TE LSP */

    
    lcs->relcsi_local_cspf = 0;
    BIT_SET(params_flags, TAG_EXTCTRL_PARAMS_LOCAL_CSPF);
    tlv = tlv_array[EXTCTRL_TLV_LOCAL_CSPF];
    if (tlv) {
	tlv_len = rpc_proto_tlv_data_length(tlv);
	if (tlv_len != sizeof(u_int8_t)) {
	    rpd_server_trace_general("LSP vendor local cspf tlv, malformed in pcupdate");
	    return FALSE;
	}
	tlv_8bit_data = rpc_proto_tlv_data(tlv);
	lcs->relcsi_local_cspf = *tlv_8bit_data;
	rpd_server_trace_general("  vendor local cspf %"PRIu8,
				 lcs->relcsi_local_cspf);
    }

    /* Decode LSP metric */
    if (!rpd_server_extctrl_decode_lsp_metric(tlv_array, lcs)) {
	return FALSE;
    }

    lcs->lcs_params_flags = params_flags;

    /* Decode LSP install-prefixes */
    tlv = tlv_array[EXTCTRL_TLV_INSTALL_PFX];
    if (tlv) {
        char print_str[256] = {0};

        tlv_len = rpc_proto_tlv_data_length(tlv);
        tlv_var_data = rpc_proto_tlv_data(tlv);

        prefix_info = (prefix_info_t*)tlv_var_data;
        rpd_server_extctrl_lsp_prefix_to_str(prefix_info, print_str,
                        sizeof(print_str));
        rpd_server_trace_general("  install-prefix %s", print_str);

        lcs->install_prefix_info = task_mem_malloc(NULL, tlv_len);
        if (!lcs->install_prefix_info) {
             rpd_server_trace_general("  Error in install-prefix decoding in pcupdate");
             return FALSE;
        }
        bcopy(tlv_var_data, lcs->install_prefix_info, tlv_len);
    } else {
        lcs->install_prefix_info = NULL;
        rpd_server_trace_general("  no install-prefix in pcupdate");
    }

    return TRUE;
}

/**
 * Decode a fragmented srte pcupdate message in a buffer.
 *
 * @param[in] msg_data Buffer in which the message is present
 * @param[in] msg_length Length of the message
 * @param[out] pcupdate_msg Decoded fragmented pcupdate message
 *
 * @return FALSE when the message cannot be successfully decoded
 * @return TRUE  when the message is successfully decoded
 */
static boolean
rpd_server_extctrl_decode_srte_frag_pcupdate (struct rpd_server_client *rsc UNUSED,
				    u_int8_t *msg_data, u_int16_t msg_length,
				    rpd_msg_frag_pcupdate_t *pcupdate_msg)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data;
    u_int tlv_len;
    rpd_extctrl_lsp_config_status_frag_info_t *frag_info;

    if (!pcupdate_msg) {
        return FALSE;
    }

    err_msg = "Missing params";
    bzero(&tlv_array, sizeof(tlv_array));
    frag_info = &pcupdate_msg->pupd_frag_info;

    if (rpc_proto_buffer_parse_tlvs(msg_data, msg_length,
                                    tlv_array, &err_msg,
                                    EXTCTRL_TLV_MAX)) {
        return FALSE;
    }

    /*
     * Decode Client ID
     */
    tlv = tlv_array[EXTCTRL_TLV_CLIENT_ID];
    if (!tlv) {
        rpd_server_trace_general("Client identification tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len > (TAG_LSP_NAME_SIZE+1)) {
        rpd_server_trace_general("Client name too long in pcupdate");
        return FALSE;
    }
    if (tlv_len > sizeof(pcupdate_msg->lsp_controller.name)) {
        rpd_server_trace_general("Client identification tlv malformed in pcupdate");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, pcupdate_msg->lsp_controller.name, tlv_len);

    /* Decode per lsp context */
    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
        rpd_server_trace_general("LSP context tlv absent in pcupdate");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        rpd_server_trace_general("LSP context malformed in pcupdate");
        return FALSE;
    }
    pcupdate_msg->context = get_long(rpc_proto_tlv_data(tlv));

    /* Decode message id */
    tlv = tlv_array[EXTCTRL_TLV_MSG_ID];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    frag_info->message_id = get_long(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  message_id %u", frag_info->message_id);

    /*
     * Decode total fragments field
     */
    tlv = tlv_array[EXTCTRL_TLV_TOTAL_FRAGMENTS];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    frag_info->total_fragments = get_long(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  total_fragments %u", frag_info->total_fragments);

    /* Decode current fragment number */
    tlv = tlv_array[EXTCTRL_TLV_CURRENT_FRAGMENT];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    frag_info->current_fragment = get_long(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  current_fragment %u", frag_info->current_fragment);

    /* Decode total msg size */
    tlv = tlv_array[EXTCTRL_TLV_TOTAL_MESSAGE_SIZE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    frag_info->total_msg_size = get_long(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  total_msg_size %u", frag_info->total_msg_size);

    /* Decode current fragment size */
    tlv = tlv_array[EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE];
    if (!tlv) {
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        return FALSE;
    }
    frag_info->current_fragment_size = get_long(rpc_proto_tlv_data(tlv));
    rpd_server_trace_general("  current_fragment_size %u", frag_info->current_fragment_size);

    /* Decode Fragment Raw Data */
    tlv = tlv_array[EXTCTRL_TLV_FRAGMENT_DATA];
    if (!tlv) {
        return FALSE;
    }

    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (((tlv_len < 1) || (tlv_len > MAX_FRAGMENT_DATA))
        || (tlv_len != frag_info->current_fragment_size)) {
        return FALSE;
    }

    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, frag_info->rcv_fragment_data, tlv_len);

    return TRUE;
}

/*
 * This sends empty messages with just the subtype to controller when
 * - controller is accepted/rejected
 * - no lsps are configured and there is a query to get LSPs
 */

boolean
rpd_server_extctrl_send_msgcode (struct rpd_server_client *rsc,
				 u_int32_t subtype) 
{
    ipc_msg_t hdr;

    if (rsc == NULL) {
	return FALSE;
    }
    
    hdr.type = 0;
    hdr.subtype = subtype;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;
    hdr.length = 0;

    return rpd_server_msg_write(rsc, &hdr, NULL);

}

/**
 * Encode an lsp error message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static int
rpd_server_extctrl_encode_lsp_error (u_int8_t *buf, u_int bytes_left,
				     rpd_msg_extctrl_lsp_error_t *msg)
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

    lsp_type_info = &msg->lsp_type_info;
    cur_tlv = (rpc_tlv *)buf;
    length = 0;

    /*
     * Encoding the per lsp context (received in last pcupdate)
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        return 0;
    }
   
    /*
     * Encoding name of the controller
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      strlen(msg->lsp_controller.name))) {
        return 0;
    }
   
    /*
     * Encode the error code
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_RETURN_CODE,
                                      &msg->error,
                                      sizeof(u_int16_t))) {
        return 0;
    }
   
    /*
     * Encoding name of the LSP
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      msg->lsp_name,
                                      strlen(msg->lsp_name))) {
        return 0;
    }

   /*
    * Encode SETUP TYPE
    */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_TYPE,
                                      &lsp_type_info->setup_type,
                                      sizeof(lsp_type_info->setup_type))) {
        return 0;
    }

   /*
    * Encode SUB TYPE only for spring_te lsp's
    */
    if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
       (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {

        if(!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(lsp_type_info->sub_type))) {
            return 0;
        }

    }

    /*
     * Encode PATH flags
     */
    if(msg->flags & LSP_FLAG_P2MP) {
        u_int16_t ele_path_flags = LSP_PATH_TYPE_P2MP;
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_FLAG,
                                          &ele_path_flags,
                                          sizeof(ele_path_flags))) {
            return 0;
        }
    }

    return length;
}

/**
 * Send an lsp error message
 *
 * @param[in] context  Conext
 * @param[in] rsc      Client handle
 * @param[in] lspname  LSP name
 * @param[in] err_code Error code
 *
 * @return TRUE if message is sent successfully, FLASE otherwise.
 */
boolean
rpd_server_extctrl_lsp_error_send (u_int32_t context,
                                   u_int8_t  ele_setup_type,
                                   u_int8_t  ele_sub_type,
                                   struct rpd_server_client *rsc,
                                   const char *lspname,
                                   const char *pathname,
                                   u_int32_t flags,
                                   tag_extctrl_err_type err_code)
{
    ipc_msg_t hdr;
    u_int length;
    boolean msg_send_succeeded;
    rpd_msg_extctrl_lsp_error_t lsperr; 
    
    if (rsc == NULL) {
        return FALSE;
    }

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_LSP_ERROR;
    hdr.length = sizeof(lsperr);
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    bzero(&lsperr, sizeof(lsperr));

    lsperr.context = context;
    task_strncpy(lsperr.lsp_controller.name, rsc->rsc_name,
            strlen(rsc->rsc_name));
    lsperr.error = err_code;
    lsperr.lsp_type_info.setup_type = ele_setup_type;
    lsperr.lsp_type_info.sub_type = ele_sub_type;
    lsperr.flags = flags;

    if(pathname && strlen(pathname)) {
        task_snprintf(lsperr.lsp_name, sizeof(lsperr.lsp_name),
		 "%s/%s", lspname, pathname);
    } else {
        strlcpy(lsperr.lsp_name, lspname, sizeof(lsperr.lsp_name));
    }
    
    length = rpd_server_extctrl_encode_lsp_error(tx_buffer_ptr, TX_BUFFER_LEN,
						 &lsperr);
    if (!length) {
        msg_send_succeeded = FALSE;
    } else {
        hdr.length = length;
        msg_send_succeeded =
            rpd_server_msg_write(rsc, &hdr, tx_buffer_ptr);
    }

    if (!msg_send_succeeded) {
        rpd_server_trace_general("Failed to send LSP error '%s' for LSP %s to "
				 "controller %s",
				 tag_extctrl_error_get_string(err_code),
				 lspname, rsc->rsc_name);

    } else {
        rpd_server_trace_general("Sent LSP error '%s' for LSP %s to "
				 "controller %s",
				 tag_extctrl_error_get_string(err_code),
				 lspname, rsc->rsc_name);
    }

    return msg_send_succeeded;
}


/**
 * Encode a pcrequest message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
u_int32_t
rpd_server_extctrl_encode_pcrequest (u_int8_t *buf, u_int bytes_left,
				     rpd_msg_pcrequest_status_t *msg)
{
    rpc_tlv *cur_tlv;
    u_int32_t length;
    rpd_extctrl_lsp_config_status_info_t *lcs;
    u_int8_t bw[sizeof(u_int64_t)];
    lsp_type_info_t *lsp_type_info;
    
    if (!msg) {
        return 0;
    }

    if (!buf) {
        return 0;
    }

    cur_tlv = (rpc_tlv *)buf;
    length = 0;
    lcs = &msg->lsp_config_status;
    lsp_type_info = &lcs->lsp_type_info;

    rpd_server_extctrl_display_config_status(lcs, "Encoding with");

    /*
     * Encode per lsp context received in last pcupdate or the default one
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        return 0;
    }
   
    /*
     * Encode the return code for requested operation
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_RETURN_CODE,
                                      &msg->return_code,
                                      sizeof(u_int16_t))) {
        return 0;
    }
   
    /*
     * Encode lsp name
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      lcs->name,
                                      strlen(lcs->name))) {
        return 0;
    }
    
    /*
     * Encode lsp path name
     */
    if(strlen(lcs->path_name)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_NAME,
                                          lcs->path_name,
                                          strlen(lcs->path_name))) {
            return 0;
        }
    }

    /*
     * Encode lsp active path name
     */
    if(strlen(lcs->active_path_name)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_ACTIVE_PATH_NAME,
                                          lcs->active_path_name,
                                          (unsigned int)strlen(lcs->active_path_name))) {
            return 0;
        }
    }

    /*
     * Encode lsp template name
     */
    if(strlen(lcs->template_name)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_TEMPLATE_NAME,
                                          lcs->template_name,
                                          strlen(lcs->template_name))) {
            return 0;
        }
    }

    /*
     * Encode is LSP sec dest addr type ipv6
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                      &bytes_left, &length,
                      EXTCTRL_TLV_SRC_DEST_ADDR_TYPE,
                      &lcs->is_lsp_src_dst_addr_type_ipv6,
                      sizeof(u_int8_t))) {
    return 0;
    }

    /*
     * Encode destination address of lsp
     */
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
				          &bytes_left, &length,
				          EXTCTRL_TLV_DEST_ADDR,
				          &lcs->dstaddr_u.v4,
				          sizeof(u_int32_t))) {
            return 0;
        }
    } else {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                          &bytes_left, &length,
                          EXTCTRL_TLV_DEST_ADDR,
                          lcs->dstaddr_u.v6,
                          16)) {
            return 0;
        }
    }

    /*
     * Encode source address of lsp
     */
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
				          &bytes_left, &length,
				          EXTCTRL_TLV_SRC_ADDR,
				          &lcs->srcaddr_u.v4,
				          sizeof(u_int32_t))) {
            return 0;
        }
    } else {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                          &bytes_left, &length,
                          EXTCTRL_TLV_SRC_ADDR,
                          lcs->srcaddr_u.v6,
                          16)) {
            return 0;
        }
    }

    /*
     * Encode reason for triggering the message 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_MSG_TRIGGER_REASON,
				      &lcs->msg_trigger_reason,
				      sizeof(u_int32_t))) {
	return 0;
    }

    /*
     * Encode lsp type 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LSP_TYPE,
				      &lcs->type,
				      sizeof(u_int16_t))) {
	return 0;
    }

    /*
     * Encode state of lsp
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LSP_STATE,
				      &lcs->state,
				      sizeof(u_int16_t))) {
	return 0;
    }

    /*
     * Encode control status of LSP 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_CONTROL_STATUS,
				      &lcs->control_status,
				      sizeof(u_int8_t))) {
	return 0;
    }

    /*
     * Encode LSP flags 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LSP_FLAGS,
				      &lcs->lsp_flags,
				      sizeof(u_int8_t))) {
	return 0;
    }


    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_ADMIN_GRP_EXCLUDE_ANY,
				      &lcs->relcsi_admin_grp_exclude_any,
				      sizeof(u_int32_t))) {
	return 0;
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ANY,
				      &lcs->relcsi_admin_grp_include_any,
				      sizeof(u_int32_t))) {
	return 0;
    }

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_ADMIN_GRP_INCLUDE_ALL,
				      &lcs->relcsi_admin_grp_include_all,
				      sizeof(u_int32_t))) {
	return 0;
    }

    /*
     * Encode setup priority configured value 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_CONF_SETUP_PRIO,
				      &lcs->configured_setup_prio,
				      sizeof(u_int8_t))) {
	return 0;
    }

    /*
     * Encode hold priority configured value
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_CONF_HOLD_PRIO,
				      &lcs->configured_hold_prio,
				      sizeof(u_int8_t))) {
	return 0;
    }

    /*
     * Encode setup priority -controller provided value
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_SETUP_PRIO,
				      &lcs->setup_prio,
				      sizeof(u_int8_t))) {
	return 0;
    }

    /*
     * Encode hold priority -controller provided value
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_HOLD_PRIO,
				      &lcs->hold_prio,
				      sizeof(u_int8_t))) {
	return 0;
    }

    /* Encode LSP ID */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LSP_ID,
				      &lcs->lsp_id,
				      sizeof(u_int16_t))) {
	return 0;
    }
    
    /* Encode tunnel ID */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_TUNNEL_ID,
				      &lcs->tunnel_id,
				      sizeof(u_int16_t))) {
	return 0;
    }


    /*
     * Encode bandwidth -controller provided value
     */

    put_long(&bw[0], (lcs->bandwidth & 0xffffffff00000000ULL) >> 32);
    put_long(&bw[4], lcs->bandwidth & 0xffffffff);
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
				      &bytes_left, &length,
				      EXTCTRL_TLV_BANDWIDTH,
				      bw,
				      sizeof(u_int64_t))) {
	return 0;
    } 
    /*
     * Encode configured bandwidth 
     */

    put_long(&bw[0], (lcs->configured_bandwidth & 0xffffffff00000000ULL) >> 32);
    put_long(&bw[4], lcs->configured_bandwidth & 0xffffffff);
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
				      &bytes_left, &length,
				      EXTCTRL_TLV_CONF_BANDWIDTH,
				      bw,
				      sizeof(u_int64_t))) {
	return 0;
    }

    /*
     * Encode configured hops for primary path 
     */

    if (lcs->ero_info) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					  &bytes_left, &length,
					  EXTCTRL_TLV_ERO_INFO,
					  lcs->ero_info,
					  lcs->ero_len)) {
	    return 0;
	}
    }

    /*
     * Encode actual hops for primary path
     */
    if (lcs->rro_info) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					  &bytes_left, &length,
					  EXTCTRL_TLV_RRO_INFO,
					  lcs->rro_info,
					  lcs->rro_len)) {
	    return 0;
	}
    }

    if(lcs->error_spec_obj_len && lcs->error_spec_obj) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					  &bytes_left, &length,
					  EXTCTRL_TLV_ERRORSPECOBJ,
					  lcs->error_spec_obj,
					  lcs->error_spec_obj_len)) {
	    return 0;
	}
    }


    /*
     * Encode PATH flags 
     */

    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_LSP_PATH_FLAG,
				      &lcs->path_flags,
				      sizeof(lcs->path_flags))) {
	return 0;
    }

    if (lcs->num_assoc_info) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
					  &bytes_left, &length,
					  EXTCTRL_TLV_NUM_ASSOCIATION_INFO,
					  &lcs->num_assoc_info,
					  sizeof(u_int16_t))) {
	    return 0;
	}

	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					  &bytes_left, &length,
					  EXTCTRL_TLV_ASSOCIATION_INFO,
					  lcs->assoc_info,
					  lcs->num_assoc_info * sizeof(lsp_association_info))) {
	    return 0;
	}
    }

    /*
     * Disjoint Assoc Info Count
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_DISJOINT_ASSOC_INFO_COUNT,
                                      &lcs->div_assoc_info_count,
                                      sizeof(u_int32_t))) {
        return 0;
    }
    if (lcs->div_assoc_info_count) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_DISJOINT_ASSOC_INFO,
                                          lcs->div_assoc_info,
                                          lcs->div_assoc_info_count * sizeof(lsp_association_info))) {
            return 0;
        }
    }

    /*
     * Encode AUTO bandwidth 
     */

    put_long(&bw[0], (lcs->auto_bandwidth & 0xffffffff00000000ULL) >> 32);
    put_long(&bw[4], lcs->auto_bandwidth & 0xffffffff);
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
				      &bytes_left, &length,
				      EXTCTRL_TLV_PATH_AUTO_BANDWIDTH,
				      bw,
				      sizeof(u_int64_t))) {
	return 0;
    } 

    if(lcs->metric_valid) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
					  &bytes_left, &length,
					  EXTCTRL_TLV_LSP_METRIC,
					  &lcs->metric,
					  sizeof(u_int32_t))) {
	    return 0;
	}
    }

    if (lcs->path_flags & LSP_PATH_TYPE_P2MP) {
	/*
	 * Encode lsp p2mp tree name
	 */
	if(strlen(lcs->p2mp_name)) {
	    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
					      &bytes_left, &length,
					      EXTCTRL_TLV_P2MP_NAME,
					      lcs->p2mp_name,
					      strlen(lcs->p2mp_name))) {
		return 0;
	    }
	}
	// P2MP_ID
	if (lcs->p2mp_id) {
	    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
					      &bytes_left, &length,
					      EXTCTRL_TLV_P2MP_ID,
					      &lcs->p2mp_id,
					      sizeof(u_int32_t))) {
		return 0;
	    }
	}
        // P2MP_MBB_FLAG
        if (lcs->p2mp_mbb_flag) {
            if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                                    &bytes_left, &length,
                                                    EXTCTRL_TLV_P2MP_MBB_FLAG,
                                                    &lcs->p2mp_mbb_flag,
                                                    sizeof(u_int16_t))) {
                return 0;
            }
        }
    }

    if(lcs->num_paths) {
	if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
					  &bytes_left, &length,
					  EXTCTRL_TLV_LSP_NUM_PATHS,
					  &lcs->num_paths,
					  sizeof(u_int16_t))) {
	}
    }
    
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
				      &bytes_left, &length,
				      EXTCTRL_TLV_SETUP_TYPE,
				      &lsp_type_info->setup_type,
				      sizeof(u_int8_t))) {
	return 0;
    }

   /*
    * Encode SUB TYPE
    */
    if(lsp_type_info->sub_type) {

        if(!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(lsp_type_info->sub_type))) {
            return 0;
        }

    }

    /* Encode SRTE multi EROs*/
    if (lcs->srte_total_ero_count) {
        u_int8_t count = 0;
        u_int total_ero_len = 0;

        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_TOTAL_ERO_COUNT,
                                          &lcs->srte_total_ero_count,
                                          sizeof(u_int8_t))) {
            return 0;
        }

        rpd_sr_ero_list_t *srte_ero_list;
        srte_ero_list =  (rpd_sr_ero_list_t *)lcs->srte_ero_info;
        while (count < lcs->srte_total_ero_count) {
           total_ero_len = total_ero_len + srte_ero_list->rsel_n_eros;
           srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
           count++;
        }

        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_ERO_INFO,
                                          lcs->srte_ero_info,
                                          RPD_SRTE_MULTI_SEGMENT_LIST_LEN(lcs->srte_total_ero_count, total_ero_len))) {
            return 0;
        }
    }

    /* Encode SRTE multi RROs*/
    if (lcs->srte_total_rro_count) {
        u_int8_t count = 0;
        u_int total_rro_len = 0;

        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_TOTAL_RRO_COUNT,
                                          &lcs->srte_total_rro_count,
                                          sizeof(u_int8_t))) {
            return 0;
        }
        rpd_sr_ero_list_t *srte_rro_list;
        srte_rro_list =  (rpd_sr_ero_list_t *)lcs->srte_rro_info;
        while (count < lcs->srte_total_rro_count) {
           total_rro_len = total_rro_len + srte_rro_list->rsel_n_eros;
           srte_rro_list = (rpd_sr_ero_list_t *)&(srte_rro_list->rsel_ero[srte_rro_list->rsel_n_eros]);
           count++;
        }

        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_RRO_INFO,
                                          lcs->srte_rro_info,
                                          RPD_SRTE_MULTI_SEGMENT_LIST_LEN(lcs->srte_total_rro_count, total_rro_len))){
            return 0;
       }
    }

    if (lcs->max_segment_list) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SRTE_MAX_SEGMENT_LIST_INFO,
                                          &lcs->max_segment_list,
                                          sizeof(u_int16_t))) {
        }
    }

    /* Encode LSP Binding SID */
    if (lcs->lsp_binding_sid.binding_value) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_TE_PATH_BINDING_TYPE,
                          &lcs->lsp_binding_sid.binding_type,
                          sizeof(u_int16_t))) {
            return 0;
        }
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_TE_PATH_BINDING_VAL,
                          &lcs->lsp_binding_sid.binding_value,
                          sizeof(u_int32_t))) {
            return 0;
        }
    }

    /* PCE Initiated Bypass : begin */
    if (lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr != 0) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_BYP_PROT_TYPE,
                          &lcs->rbyp_params.rbp_prot_type,
                          sizeof(u_int32_t))) {
            return 0;
        }
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_BYP_PRIMARY_NHOP,
                          &lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr,
                          sizeof(u_int32_t))) {
            return 0;
        }
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_BYP_SUBSCR,
                          &lcs->rbyp_params.rbp_subscr,
                          sizeof(u_int32_t))) {
            return 0;
        }
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                          &bytes_left, &length,
                          EXTCTRL_TLV_BYP_IN_USE,
                          &lcs->rbyp_state.rbs_in_use,
                          sizeof(u_int32_t))) {
            return 0;
        }        
    }
    /* PCE Initiated Bypass : end */ 

    /**
     * Encode install-prefix list
     */
    if (lcs->install_prefix_info) {
        unsigned len = RPD_PREFIX_BUFF_LEN(lcs->install_prefix_info);
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                     &bytes_left, &length,
                     EXTCTRL_TLV_INSTALL_PFX,
                     lcs->install_prefix_info,
                     len)) {
            return 0;
        }
    }

    /**
     * Encode optimization metric list
     */
    if (lcs->optimization_metric_list) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                     &bytes_left, &length,
                     EXTCTRL_TLV_OPTIMIZATION_METRIC,
                     lcs->optimization_metric_list,
                     RPD_GET_OPT_METRIC_LIST_SIZE(lcs->optimization_metric_list->list_len))) {
            return 0;
        }
    }

    /**
     * Encode bound metric list
     */
    if (lcs->bound_metric_list) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                     &bytes_left, &length,
                     EXTCTRL_TLV_BOUND_METRIC,
                     lcs->bound_metric_list,
                     RPD_GET_METRIC_LIST_SIZE(lcs->bound_metric_list->list_len))) {
            return 0;
        }
    }

    /**
     * Encode actual metric list
     */
    if (lcs->actual_metric_list) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                     &bytes_left, &length,
                     EXTCTRL_TLV_ACTUAL_METRIC,
                     lcs->actual_metric_list,
                     RPD_GET_METRIC_LIST_SIZE(lcs->actual_metric_list->list_len))) {
            return 0;
        }
    }

    rpd_server_extctrl_display_tlv(buf, length);

    return length;
}

/**
 * Estimate Encode length for a pcrequest message
 * @param[in] msg Message for that needs to calculate encoded length
 *
 * @return estimated Length of the encoded message
 */
u_int32_t
rpd_server_extctrl_estimate_encode_pcrequest_length (
				     rpd_msg_pcrequest_status_t *msg)
{
    u_int32_t length;
    rpd_extctrl_lsp_config_status_info_t *lcs;

    if (!msg) {
        return 0;
    }

    length = 0;
    lcs = &msg->lsp_config_status;

    /*
     * Encode length for per lsp context received in last pcupdate or the default one
     */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /*
     * Encode length for the return code for requested operation
     */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /*
     * Encode length for lsp name
     */
    length += sizeof(rpc_tlv) + strlen(lcs->name);

    /*
     * Encode length for lsp path name
     */
    if(strlen(lcs->path_name)) {
        length += sizeof(rpc_tlv) + strlen(lcs->path_name);
    }

    /*
     * Encode length for lsp active path name
     */
    if(strlen(lcs->active_path_name)) {
        length += sizeof(rpc_tlv) + strlen(lcs->active_path_name);
    }

    /*
     * Encode length for lsp template name
     */
    if(strlen(lcs->template_name)) {
        length += sizeof(rpc_tlv) + strlen(lcs->template_name);
    }

    /*
     * Encode length for LSP sec dest addr type ipv6
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for destination address of lsp
     */
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    } else {
        length += sizeof(rpc_tlv) + 16;
    }

    /*
     * Encode length for source address of lsp
     */
    if (!lcs->is_lsp_src_dst_addr_type_ipv6) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    } else {
        length += sizeof(rpc_tlv) + 16;
    }

    /*
     * Encode length for reason for triggering the message
     */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /*
     * Encode length for lsp type
     */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /*
     * Encode length for state of lsp
     */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /*
     * Encode length for control status of LSP
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for LSP flags
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for Admin group exclude any, include any, include all
     */
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    length += sizeof(rpc_tlv) + sizeof(u_int32_t);

    /*
     * Encode length for setup priority configured value
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for hold priority configured value
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for setup priority -controller provided value
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for hold priority -controller provided value
     */
    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /* Encode length for LSP ID */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /* Encode length for tunnel ID */
    length += sizeof(rpc_tlv) + sizeof(u_int16_t);

    /*
     * Encode length for bandwidth -controller provided value
     */
    length += sizeof(rpc_tlv) + sizeof(u_int64_t);

    /*
     * Encode length for configured bandwidth
     */
    length += sizeof(rpc_tlv) + sizeof(u_int64_t);

    /*
     * Encode length for configured hops for primary path
     */
    if (lcs->ero_info) {
        length += sizeof(rpc_tlv) + lcs->ero_len;
    }

    /*
     * Encode length for actual hops for primary path
     */
    if (lcs->rro_info) {
        length += sizeof(rpc_tlv) + lcs->rro_len;
    }

    if(lcs->error_spec_obj_len && lcs->error_spec_obj) {
        length += sizeof(rpc_tlv) + lcs->error_spec_obj_len;
    }

    /*
     * Encode length for PATH flags
     */
    length += sizeof(rpc_tlv) + sizeof(lcs->path_flags);

    if (lcs->num_assoc_info) {
        length += sizeof(rpc_tlv) + sizeof(u_int16_t);
        length += sizeof(rpc_tlv) +
                    (lcs->num_assoc_info * sizeof(lsp_association_info));
    }

    /*
     * Encode length for AUTO bandwidth
     */
    length += sizeof(rpc_tlv) + sizeof(u_int64_t);

    if(lcs->metric_valid) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    }

    if (lcs->path_flags & LSP_PATH_TYPE_P2MP) {
        /*
        * Encode length for lsp p2mp tree name
        */
        if(strlen(lcs->p2mp_name)) {
            length += sizeof(rpc_tlv) + strlen(lcs->p2mp_name);
        }
        /*
         * Encode length for P2MP_ID
         */
        if (lcs->p2mp_id) {
            length += sizeof(rpc_tlv) + sizeof(u_int32_t);
        }
        /*
         * Encode length for P2MP_MBB_FLAG
         */
        if (lcs->p2mp_mbb_flag) {
            length += sizeof(rpc_tlv) + sizeof(u_int16_t);
        }
    }

    if(lcs->num_paths) {
        length += sizeof(rpc_tlv) + sizeof(u_int16_t);
    }

    length += sizeof(rpc_tlv) + sizeof(u_int8_t);

    /*
     * Encode length for SUB TYPE
     */
    if(lcs->lsp_type_info.sub_type) {
        length += sizeof(rpc_tlv) + sizeof(lcs->lsp_type_info.sub_type);
    }

    /* Encode length for SRTE multi EROs*/
    if (lcs->srte_total_ero_count) {
        u_int8_t count = 0;
        u_int total_ero_len = 0;
        rpd_sr_ero_list_t *srte_ero_list;
        srte_ero_list =  (rpd_sr_ero_list_t *)lcs->srte_ero_info;
        while (count < lcs->srte_total_ero_count) {
           total_ero_len = total_ero_len + srte_ero_list->rsel_n_eros;
           srte_ero_list = (rpd_sr_ero_list_t *)&(srte_ero_list->rsel_ero[srte_ero_list->rsel_n_eros]);
           count++;
        }

        length += sizeof(rpc_tlv) + sizeof(u_int8_t);
        length += sizeof(rpc_tlv) + RPD_SRTE_MULTI_SEGMENT_LIST_LEN(lcs->srte_total_ero_count, total_ero_len);
    }

    /* Encode length for SRTE multi RROs*/
    if (lcs->srte_total_rro_count) {
        u_int8_t count = 0;
        u_int total_rro_len = 0;
        rpd_sr_ero_list_t *srte_rro_list;
        srte_rro_list =  (rpd_sr_ero_list_t *)lcs->srte_rro_info;
        while (count < lcs->srte_total_rro_count) {
           total_rro_len = total_rro_len + srte_rro_list->rsel_n_eros;
           srte_rro_list = (rpd_sr_ero_list_t *)&(srte_rro_list->rsel_ero[srte_rro_list->rsel_n_eros]);
           count++;
        }

        length += sizeof(rpc_tlv) + sizeof(u_int8_t);
        length += sizeof(rpc_tlv) + RPD_SRTE_MULTI_SEGMENT_LIST_LEN(lcs->srte_total_rro_count, total_rro_len);
    }

    if (lcs->max_segment_list) {
        length += sizeof(rpc_tlv) + sizeof(u_int16_t);
    }

    /* Encode length for LSP Binding SID */
    if (lcs->lsp_binding_sid.binding_value) {
        length += sizeof(rpc_tlv) + sizeof(u_int16_t);
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    }

    /* Encode length for PCE Initiated Bypass */
    if (lcs->rbyp_params.rbp_nhaddr.rbn_ipv4_addr != 0) {
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
        length += sizeof(rpc_tlv) + sizeof(u_int32_t);
    }

    /**
     * Encode length for install-prefix list
     */
    if (lcs->install_prefix_info) {
        length += sizeof(rpc_tlv) + RPD_PREFIX_BUFF_LEN(lcs->install_prefix_info);
    }

    /**
     * Encode length for optimization metric list
     */
    if (lcs->optimization_metric_list) {
        length += sizeof(rpc_tlv) + RPD_GET_OPT_METRIC_LIST_SIZE(lcs->optimization_metric_list->list_len);
    }

    /**
     * Encode length for bound metric list
     */
    if (lcs->bound_metric_list) {
        length += sizeof(rpc_tlv) + RPD_GET_METRIC_LIST_SIZE(lcs->bound_metric_list->list_len);
    }

    /**
     * Encode length for actual metric list
     */
    if (lcs->actual_metric_list) {
        length += sizeof(rpc_tlv) + RPD_GET_METRIC_LIST_SIZE(lcs->actual_metric_list->list_len);
    }

    return length;
}

/**
 * Encode a SRTE Fragmented pcrequest message in a buffer.
 *
 * @param[in] buf Buffer to encode the message
 * @param[in] bytes_left Size of the buffer
 * @param[in] msg Message that needs to be encoded
 *
 * @return Length of the encoded message
 */
static int
rpd_server_extctrl_encode_srte_frag_pcrequest (u_int8_t *buf, u_int bytes_left,
				                        rpd_msg_pcrequest_frag_status_t *msg)
{
    rpc_tlv *cur_tlv;
    u_int length;
    rpd_extctrl_lsp_config_status_frag_info_t *lcs_frag;

    if (!msg) {
        return 0;
    }

    if (!buf) {
        return 0;
    }

    cur_tlv = (rpc_tlv *)buf;
    length = 0;
    lcs_frag = &msg->lcs_frag_info;

    /*
     * Encode per lsp context received in last pcupdate or the default one
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /*
     * Encode the return code for requested operation
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_RETURN_CODE,
                                      &msg->return_code,
                                      sizeof(u_int16_t))) {
        return 0;
    }

    /*
     * Encode total fragments field
     */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_TOTAL_FRAGMENTS,
                                      &lcs_frag->total_fragments,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /* Encode current fragment number */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CURRENT_FRAGMENT,
                                      &lcs_frag->current_fragment,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /* Encode total msg size */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_TOTAL_MESSAGE_SIZE,
                                      &lcs_frag->total_msg_size,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /* Encode current fragment size */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CURRENT_FRAGMENT_SIZE,
                                      &lcs_frag->current_fragment_size,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /* Encode message id */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_MSG_ID,
                                      &lcs_frag->message_id,
                                      sizeof(u_int32_t))) {
        return 0;
    }

    /* Encode Fragment Raw Data */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_FRAGMENT_DATA,
                                      lcs_frag->send_fragment_data,
                                      lcs_frag->current_fragment_size)) {
        return 0;
    }

    return length;
}

boolean
rpd_server_extctrl_send_pcrequest (struct rpd_server_client *rsc,
				   rpd_msg_pcrequest_status_t *msg)
{
    u_int32_t length;
    boolean msg_send_succeeded;
    ipc_msg_t hdr;

    if (rsc == NULL) {
	return FALSE;
    }
    
    hdr.type = 0;
    hdr.subtype = RPD_MSG_PCREQUEST_N_LSPSTATUS;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    length = rpd_server_extctrl_encode_pcrequest(tx_buffer_ptr, TX_BUFFER_LEN,
						 msg);
    if (!length) {
	msg_send_succeeded = FALSE;
    } else {
	hdr.length = length;
	msg_send_succeeded =
	    rpd_server_msg_write(rsc, &hdr, tx_buffer_ptr);
    }

    return msg_send_succeeded;
}

/**
 * @brief Encode and send fragmented pcrequest to controller
 *
 * @param rsc Client handle
 * @param msg fragmented pcrequest message to be encoded and send
 * @return TRUE if message send successful
 * @return FALSE otherwise
 */
boolean
rpd_server_extctrl_send_srte_frag_pcrequest (struct rpd_server_client *rsc,
				   rpd_msg_pcrequest_frag_status_t *msg)
{
    int length;
    boolean msg_send_succeeded;
    ipc_msg_t hdr;

    if (rsc == NULL) {
        return FALSE;
    }

    hdr.type = 0;
    hdr.subtype = RPD_MSG_EXTCTRL_SRTE_FRAG_PCREQUEST;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;

    length = rpd_server_extctrl_encode_srte_frag_pcrequest(tx_buffer_ptr, TX_BUFFER_LEN, msg);
    if (!length) {
        msg_send_succeeded = FALSE;
    } else {
        hdr.length = (u_int16_t)length;
        msg_send_succeeded = rpd_server_msg_write(rsc, &hdr, tx_buffer_ptr);
    }

    return msg_send_succeeded;
}

/**
 * Send out the msg for old instance down in case of MBB
 */
boolean
rpd_server_extctrl_send_MBB_down (struct rpd_server_client *rsc,
				  rpd_msg_pcrequest_status_t *pcrequest_msg)
{
    u_int length;
    boolean res;
    ipc_msg_t hdr;

    length = rpd_server_extctrl_encode_pcrequest(tx_buffer_ptr, TX_BUFFER_LEN,
						 pcrequest_msg);
    if (length == 0) {
	res = FALSE;
	goto mbb_down_end;
    }
    
    hdr.type = 0;
    hdr.subtype = RPD_MSG_PCREQUEST_N_LSPSTATUS;
    hdr.opcode = IPC_MSG_ACTION_NONE;
    hdr.error = IPC_ERROR_OK;
    hdr.length = length;
    
    res = rpd_server_msg_write(rsc, &hdr, tx_buffer_ptr);
    
  mbb_down_end:
    return res;
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
rpd_server_extctrl_encode_lsp_request (u_int8_t *buf, u_int bytes_left,
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

    lsp_type_info = &msg->lsp_type_info;
    cur_tlv = (rpc_tlv *)buf;
    length = 0;

    /*
     * Encoding the per lsp context (received in last pcupdate)
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_32_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CONTEXT,
                                      &msg->context,
                                      sizeof(u_int32_t))) {
        return 0;
    }
   
    /*
     * Encoding name of the LSP
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_LSP_NAME,
                                      msg->name,
                                      strlen(msg->name))) {
        return 0;
    }

    /*
     * Encoding name of the LSP PATH
     */
    if(strlen(msg->path_name)) {
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_NAME,
                                          msg->path_name,
                                          strlen(msg->path_name))) {
            return 0;
        }
    }

   /*
    * Encode SETUP TYPE
    */
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_SETUP_TYPE,
                                      &lsp_type_info->setup_type,
                                      sizeof(lsp_type_info->setup_type))) {
        return 0;
    }

   /*
    * Encode SUB TYPE only for spring_te lsp's
    */
    if((RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE == lsp_type_info->setup_type) ||
       (RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_SRV6_TE == lsp_type_info->setup_type)) {

        if(!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_8_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_SUB_TYPE,
                                          &lsp_type_info->sub_type,
                                          sizeof(lsp_type_info->sub_type))) {
            return 0;
        }

    }

    /*
     * Encode PATH flags for p2mp lsp's
     */
    if(msg->is_p2mp_lsp) {
        u_int16_t path_flags = LSP_PATH_TYPE_P2MP;
        if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_16_BIT,
                                          &bytes_left, &length,
                                          EXTCTRL_TLV_LSP_PATH_FLAG,
                                          &path_flags,
                                          sizeof(path_flags))) {
            return 0;
        }
    }


    /*
     * Encoding name of the controller
     */ 
    if (!rpc_proto_build_complete_tlv(&cur_tlv, RPC_TLV_DATA_VARIABLE,
                                      &bytes_left, &length,
                                      EXTCTRL_TLV_CLIENT_ID,
                                      msg->lsp_controller.name,
                                      strlen(msg->lsp_controller.name))) {
        return 0;
    }
    
    return length;
}

boolean
rpd_server_extctrl_send_lsp_request (struct rpd_server_client *rsc,
				     rpd_msg_extctrl_lsp_request_t *lspreq,
				     u_int32_t sub_type)
{
    int length;
    boolean res;
    ipc_msg_t hdr;

    if (rsc == NULL) {
	return FALSE;
    }
    
    length = rpd_server_extctrl_encode_lsp_request(tx_buffer_ptr, TX_BUFFER_LEN,
						   lspreq);
    if (length) {
	hdr.type = 0;
	hdr.subtype = sub_type;
	hdr.opcode = IPC_MSG_ACTION_NONE;
	hdr.error = IPC_ERROR_OK;
        hdr.length = length;
	
        res = rpd_server_msg_write(rsc, &hdr, tx_buffer_ptr);
    } else {
        res = FALSE;
    }

    return res;
}

static void
rpd_server_extctrl_process_client_id (struct rpd_server_client *rsc,
									ipc_msg_t *msg)
{
	rpd_msg_client_identification_t *clnt;
	uint8_t accept_count = 0;

	clnt = (rpd_msg_client_identification_t *)msg->data;


	for (int i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
	{
		if (EXTCTRL_CTX_PROTO_RETCALL(i, authenticate_ext_ctrlr, 
										boolean, clnt->name, rsc))
		accept_count++;
	}

	if (!accept_count) {
		rpd_server_trace_general("Authentication failed for client %s",
								clnt->name);
		rpd_server_extctrl_send_msgcode(rsc,RPD_MSG_EXTCTRLER_REJECTED);
		rpd_server_client_close(rsc);
	} else {
		rpd_server_trace_general("Client %s is connected", clnt->name);
		rsc->client_id = RPD_SERVER_CLIENT_LSPCTRLER;
		strlcpy(rsc->rsc_name, clnt->name, sizeof(rsc->rsc_name));
		rpd_server_extctrl_send_msgcode(rsc,RPD_MSG_EXTCTRLER_ACCEPTED);
	}
}

/**
 * @brief Process the fragmented pcupdate message
 *
 * @param rsc client handle
 * @param msg received encoded fragmented pcupdate
 */
static void
rpd_server_extctrl_process_srte_frag_pcupdate (struct rpd_server_client *rsc,
				                               ipc_msg_t *msg)
{
    rpd_msg_frag_pcupdate_t *pcupdate;
    rpd_msg_frag_pcupdate_t  pcupdate_msg;
    boolean res;
    boolean accepted = FALSE;

    bzero(&pcupdate_msg, sizeof(pcupdate_msg));
    pcupdate = &pcupdate_msg;

    res = rpd_server_extctrl_decode_srte_frag_pcupdate(rsc, msg->data, msg->length,
					     &pcupdate_msg);
    if (!res) {
        rpd_server_trace_general("Error decoding fragmented pcupdate message");
        rpd_server_extctrl_send_msgcode(rsc, RPD_MSG_INVALID_LSP_PARAMS);
        rpd_server_client_close(rsc);
        return;
    }

    if (rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
        rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
        rpd_server_client_close(rsc);
        return;
    }

    accepted = EXTCTRL_CTX_PROTO_RETCALL(RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE, authenticate_ext_ctrlr,
                                            boolean, pcupdate->lsp_controller.name, rsc);
    if (accepted) {
        EXTCTRL_CTX_PROTO_CALL(RPD_EXTCTRL_LSP_SETUP_TYPE_SPRING_TE,
                                process_ctrlr_frag_update_tunnel, pcupdate);
    } else {
        rpd_server_trace_general("Unknown client %s attemping update Spring-TE LSP",
                                 pcupdate->lsp_controller.name);
        rpd_server_client_close(rsc);
    }
}

static void
rpd_server_extctrl_process_pcupdate (struct rpd_server_client *rsc,
				     ipc_msg_t *msg)
{
    rpd_msg_pcupdate_t *pcupdate;
    rpd_msg_pcupdate_t  pcupdate_msg;
    boolean res;
    boolean accepted = FALSE;
    rpd_extctrl_lsp_config_status_info_t *info;
    lsp_type_info_t *lsp_type_info;

    bzero(&pcupdate_msg, sizeof(pcupdate_msg));
    pcupdate = &pcupdate_msg;

    res = rpd_server_extctrl_decode_pcupdate(rsc, msg->data, msg->length,
					     &pcupdate_msg);
    if (FALSE == res) {
	rpd_server_trace_general("Error decoding pcupdate message");
	rpd_server_extctrl_send_msgcode(rsc, RPD_MSG_INVALID_LSP_PARAMS);
	rpd_server_client_close(rsc); 
	return;
    }

    info = &pcupdate->pupd_lsp_params;
    lsp_type_info = &info->lsp_type_info;

    rpd_server_trace_general("Received PCUpdate from controller %s "
			     "for LSP %s(%d)",
			     pcupdate->lsp_controller.name,
			     info->name, lsp_type_info->setup_type);

    if (rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
	rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
	rpd_server_client_close(rsc);
	return;
    }

    rpd_server_extctrl_display_config_status(info, "Received");

    if (lsp_type_info->setup_type >= RPD_EXTCTRL_LSP_SETUP_TYPE_MAX) {
        rpd_server_trace_general("Unknown provisioing type %u from "
                     "controller %s", lsp_type_info->setup_type,
                     pcupdate->lsp_controller.name);
    } else {
        accepted = EXTCTRL_CTX_PROTO_RETCALL(lsp_type_info->setup_type, authenticate_ext_ctrlr, 
                                             boolean, pcupdate->lsp_controller.name, rsc);
        if (accepted) {
            EXTCTRL_CTX_PROTO_CALL(lsp_type_info->setup_type, process_ctrlr_update_tunnel, pcupdate);
        }
    }
    
    rpd_server_extctrl_config_status_cleanup(&pcupdate->pupd_lsp_params);
    
    if (!accepted) {
        rpd_server_trace_general("Unknown client %s attemping update of LSP %s",
                                 pcupdate->lsp_controller.name, info->name);
        rpd_server_client_close(rsc);
        return;
    }
}    

static void
rpd_server_extctrl_process_get_all_lsp_info (struct rpd_server_client *rsc,
					     ipc_msg_t *msg)
{
    rpd_msg_client_identification_t *clnt;
    boolean accepted[RPD_EXTCTRL_LSP_SETUP_TYPE_MAX] = {false};
    boolean external_only;
    uint32_t reply_code = 0;
    uint8_t i, accept_count = 0;
    char module_str[RPD_SERVER_CLIENT_NAME_LEN];
    
    clnt = (rpd_msg_client_identification_t *)msg->data;

    if(msg->subtype == RPD_MSG_EXTCTRL_GET_ALL_LSPINFO) {
        rpd_server_trace_general("%s needs information on all LSPs", clnt->name);
        external_only = FALSE;
    } else {
        rpd_server_trace_general("%s expects all PCRequests/Notifications to "
                                 "be resent for LSPs",
                                 clnt->name);
        external_only = TRUE;
    } 
    
    if(rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
         rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
         rpd_server_client_close(rsc);
         return;
    }

    for (i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
    {
        accepted[i] = EXTCTRL_CTX_PROTO_RETCALL(i, authenticate_ext_ctrlr, 
                                             boolean, clnt->name, rsc);
        if (accepted[i])
            accept_count++;
    }

    if (!accept_count) {
        rpd_server_trace_general("Unknown client %s querying lsp", clnt->name);
        rpd_server_client_close(rsc);
        return;    
    }

    /* reaching here means atleast one accepted client exists */
    for (i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
    {
        if (accepted[i]) {
            EXTCTRL_CTX_PROTO_CALL(i, process_ctrlr_get_all_tunnel_info, 
                                   clnt->name, msg->subtype);
        }
        else {
            EXTCTRL_CTX_PROTO_CALL(i, get_all_tunnel_info_eor, external_only,
                                   &reply_code, module_str, 
                                   RPD_SERVER_CLIENT_NAME_LEN);

            rpd_server_trace_general("%s did not accept client %s, "
                                     "sending end-of-record", module_str, 
                                     clnt->name);

            rpd_server_extctrl_send_msgcode(rsc, reply_code);
        }
    }
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
rpd_server_extctrl_decode_lsp_request (u_int8_t *msg_data, u_int16_t msg_length,
				       rpd_msg_extctrl_lsp_request_t *lspreq_msg)
{
    rpc_tlv *tlv;
    const char *err_msg;
    rpc_tlv *tlv_array[EXTCTRL_TLV_MAX + 1];
    u_int8_t *tlv_var_data, *tlv_8bit_data;
    lsp_type_info_t *lsp_type_info;
    u_int tlv_len;
    
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

    /* Decode context */
    tlv = tlv_array[EXTCTRL_TLV_CONTEXT];
    if (!tlv) {
	rpd_server_trace_general("No context tlv in per lsp command from "
				 "controller");
	return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    if (tlv_len != sizeof(u_int32_t)) {
        rpd_server_trace_general("Malformed context tlv in per lsp command from"
				 " controller");
        return FALSE;
    }
    lspreq_msg->context = get_long(rpc_proto_tlv_data(tlv));

    /* Deocde LSP name */
    tlv = tlv_array[EXTCTRL_TLV_LSP_NAME];
    if (!tlv) {
        rpd_server_trace_general("No lsp name tlv in per lsp command from "
				 "controller");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    
    if (tlv_len > (TAG_LSP_NAME_SIZE+1)) {
        rpd_server_trace_general("Too long lsp name tlv in per lsp command from "
				 "controller");
        return FALSE;
    }
    if (tlv_len > sizeof(lspreq_msg->name)) {
        rpd_server_trace_general("Malformed lsp name tlv in per lsp command "
				 "from controller");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, lspreq_msg->name, tlv_len);

    /* Decode LSP path name */
    tlv = tlv_array[EXTCTRL_TLV_LSP_PATH_NAME];
    if (tlv) {
        tlv_len = rpc_proto_tlv_data_length(tlv);

        tlv_var_data = rpc_proto_tlv_data(tlv);
        bcopy(tlv_var_data, lspreq_msg->path_name, tlv_len);
    }

    /* Decode client-id */
    tlv = tlv_array[EXTCTRL_TLV_CLIENT_ID];
    if (!tlv) {
	rpd_server_trace_general("No controller name tlv in per lsp command "
				 "from controller");
        return FALSE;
    }
    tlv_len = rpc_proto_tlv_data_length(tlv);
    
    if (tlv_len > (TAG_LSP_NAME_SIZE+1)) {
        rpd_server_trace_general("Controller name too long in per lsp command "
				 "from controller");
        return FALSE;
    }
    if (tlv_len > sizeof(lspreq_msg->lsp_controller.name)) {
	rpd_server_trace_general("Controller name tlv malformed in per lsp "
				 "command from controller");
        return FALSE;
    }
    tlv_var_data = rpc_proto_tlv_data(tlv);
    bcopy(tlv_var_data, lspreq_msg->lsp_controller.name, tlv_len);

    /* Decode setup type */
    tlv = tlv_array[EXTCTRL_TLV_SETUP_TYPE];
    if (!tlv) {
	rpd_server_trace_general("Failing client \'%s\' attempt to "
				 "retrieve LSP %s information without setup type",
				 lspreq_msg->lsp_controller.name,
				 lspreq_msg->name);
	return FALSE;
    }
    tlv_8bit_data = rpc_proto_tlv_data(tlv);
    lsp_type_info->setup_type = *tlv_8bit_data;
    
    /* Decode sub type */
    tlv = tlv_array[EXTCTRL_TLV_SUB_TYPE];
    if(tlv) {
        tlv_8bit_data = rpc_proto_tlv_data(tlv);
        lsp_type_info->sub_type = *tlv_8bit_data;
    }
    return TRUE;
}

static void
rpd_server_extctrl_process_get_one_lsp_info (struct rpd_server_client *rsc,
					     ipc_msg_t *msg)
{
    rpd_msg_extctrl_lsp_request_t lspreq;
    boolean accepted;
    boolean res, close_conn;
    u_int32_t err_code;

    close_conn = FALSE;
    err_code = 0;
    memset(&lspreq, 0, sizeof(lspreq));

    /* Decode the received message */
    res = rpd_server_extctrl_decode_lsp_request(msg->data, msg->length,
						&lspreq);
    /* Bail out on improper messages */
    if (FALSE == res) {
	rpd_server_trace_general("Error decoding lsp get info message");
	err_code = RPD_MSG_INVALID_LSP_PARAMS;
	goto get_info_end;
    }

    rpd_server_trace_general("Received lsp-get-info request from "
			     "controller %s for LSP %s",
			     lspreq.lsp_controller.name, lspreq.name);

    if (rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
	rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
	close_conn = TRUE;
	goto get_info_end;
    }

    if (lspreq.lsp_type_info.setup_type >= RPD_EXTCTRL_LSP_SETUP_TYPE_MAX)
    {
        rpd_server_trace_general("Unrecognized setup type %u from controller %s "
                     "for LSP %s", lspreq.lsp_type_info.setup_type,
                     lspreq.lsp_controller.name, lspreq.name);
        err_code = RPD_MSG_INVALID_LSP_PARAMS;
        goto get_info_end;
    }
    else
    {
        accepted = EXTCTRL_CTX_PROTO_RETCALL(lspreq.lsp_type_info.setup_type, authenticate_ext_ctrlr, 
                                         boolean, lspreq.lsp_controller.name, rsc);
        if (accepted) {
            EXTCTRL_CTX_PROTO_CALL(lspreq.lsp_type_info.setup_type, process_get_tunnel_info, &lspreq);
        }
        else
        {
            close_conn = TRUE;
            goto get_info_end;
        }
    }

  get_info_end:
    if (err_code) {
	rpd_server_extctrl_send_msgcode(rsc, err_code);
	rpd_server_client_close(rsc);
    } else if (close_conn) {
	rpd_server_client_close(rsc);
    }
}

static void
rpd_server_extctrl_process_control_one_lsp (struct rpd_server_client *rsc,
					    ipc_msg_t *msg)
{
    rpd_msg_extctrl_lsp_request_t lspreq;
    u_int32_t err_code;
    boolean accepted, close_conn, res;

    err_code = 0;
    close_conn = FALSE;
    memset(&lspreq, 0, sizeof(lspreq));

    res = rpd_server_extctrl_decode_lsp_request(msg->data, msg->length,
						&lspreq);
    if (FALSE == res) {
	rpd_server_trace_general("Error decoding get/return control message");
	err_code = RPD_MSG_INVALID_LSP_PARAMS;
	goto control_one_lsp_end;
    }

    rpd_server_trace_general("Received control-status change for LSP(%s) "
			     "setup type(%u) from controller %s", lspreq.name,
			     lspreq.lsp_type_info.setup_type, lspreq.lsp_controller.name);

    if (rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
	rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
	close_conn = TRUE;
	goto control_one_lsp_end;
    }

    if (lspreq.lsp_type_info.setup_type >= RPD_EXTCTRL_LSP_SETUP_TYPE_MAX)
    {
        rpd_server_trace_general("Unrecognized setup-type %u received from "
               "controller %s for LSP %s",
               lspreq.lsp_type_info.setup_type,
               lspreq.lsp_controller.name,
               lspreq.name);
        err_code = RPD_MSG_INVALID_LSP_PARAMS;
        goto control_one_lsp_end;
    }
    else
    {
        accepted = EXTCTRL_CTX_PROTO_RETCALL(lspreq.lsp_type_info.setup_type, authenticate_ext_ctrlr, 
                                           boolean, lspreq.lsp_controller.name, rsc);
        if (accepted) {
            EXTCTRL_CTX_PROTO_CALL(lspreq.lsp_type_info.setup_type, process_control_one_lsp, &lspreq,
                                   msg->subtype);
        }
        else
        {
            close_conn = TRUE;
        }
    }
    
  control_one_lsp_end:
    if (err_code) {
	rpd_server_extctrl_send_msgcode(rsc, err_code);
	rpd_server_client_close(rsc);
    } else if (close_conn) {
	rpd_server_client_close(rsc);
    }
}

static void
rpd_server_extctrl_process_control_all_lsps (struct rpd_server_client *rsc,
					     ipc_msg_t *msg)
{
    rpd_msg_client_identification_t *clnt;
    boolean close_conn;
    uint8_t i, accept_count = 0;
    boolean accepted[RPD_EXTCTRL_LSP_SETUP_TYPE_MAX] = {false};
    close_conn = FALSE;
    
    clnt = (rpd_msg_client_identification_t *)msg->data;

    rpd_server_trace_general("Received control-status change for all LSPs",
			     " from controller %s", clnt->name);

    if (rsc->client_id != RPD_SERVER_CLIENT_LSPCTRLER) {
	rpd_server_trace_general("Error: Expected Client ID is LSPCTRLER");
	close_conn = TRUE;
	goto control_all_lsps_end;
    }

    for (i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
    {
      accepted[i] = EXTCTRL_CTX_PROTO_RETCALL(i, authenticate_ext_ctrlr, 
                                              boolean, clnt->name, rsc);
      if (accepted[i])
          accept_count++;
    }

    if (!accept_count) {
        close_conn = TRUE;
        goto control_all_lsps_end;
    }

    /* reaching here means atleast one accepted client exists */
    for (i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
    {
      if (accepted[i])
          EXTCTRL_CTX_PROTO_CALL(i, process_control_all_lsps, clnt->name,
                                 msg->subtype);
    }

  control_all_lsps_end:
    if (close_conn) {
	rpd_server_client_close(rsc);
    }
}

void
rpd_server_extctrl_recv (struct rpd_server_client *rsc,
			 ipc_msg_t *msg)
{
    rpd_server_trace_general("rpd_server_extctrl_recv: received msg:", msg->subtype);
    switch (msg->subtype) {
      case RPD_MSG_CLIENT_IDENTIFICATION:
	rpd_server_extctrl_process_client_id(rsc, msg);
	break;
      case RPD_MSG_EXTCTRL_PCUPDATE:
	rpd_server_extctrl_process_pcupdate(rsc, msg);
	break;
      case RPD_MSG_EXTCTRL_RETRY_PCREQUESTS:
      case RPD_MSG_EXTCTRL_GET_ALL_EXTCTRLLSPINFO:
      case RPD_MSG_EXTCTRL_GET_ALL_LSPINFO:
	rpd_server_extctrl_process_get_all_lsp_info(rsc, msg);
	break;
      case RPD_MSG_EXTCTRL_LSP_GET_INFO:
	rpd_server_extctrl_process_get_one_lsp_info(rsc, msg);
	break;
      case RPD_MSG_EXTCTRLLSP_GET_CONTROL:
      case RPD_MSG_EXTCTRLLSP_RETURN_CONTROL:
	rpd_server_extctrl_process_control_one_lsp(rsc, msg);
	break;
      case RPD_MSG_EXTCTRL_RETURN_CTRL_FOR_ALL:
      case RPD_MSG_EXTCTRL_TAKE_CTRL_FOR_ALL:
	rpd_server_extctrl_process_control_all_lsps(rsc, msg);
	break;
      case RPD_MSG_EXTCTRL_SRTE_FRAG_PCUPDATE:
	rpd_server_extctrl_process_srte_frag_pcupdate(rsc, msg);
	break;
      default:
	/* If we got here for any other message type, it's a coding bug */
	assert(0);
	break;
    }
}


void
rpd_server_extctrl_client_cleanup (struct rpd_server_client *rsc)

{
    if (rsc->client_id == RPD_SERVER_CLIENT_LSPCTRLER) {
        rpd_server_trace_general("External controller closed connection !");
        for (int i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
        {
            EXTCTRL_CTX_PROTO_CALL(i, disconnect_ext_ctrlr, rsc, rsc->rsc_name);
        }    
    }
}

void
rpd_server_extctrl_client_unblocked (struct rpd_server_client *rsc)
{
    if (rsc->client_id == RPD_SERVER_CLIENT_LSPCTRLER) {
        rpd_server_trace_general("External controller is writable");
        for (int i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
        {
            EXTCTRL_CTX_PROTO_CALL(i, resume_write_to_ext_ctrlr, rsc->rsc_name);
        }    
    }
}

/**
 * Close the pipe if the controller is  unknown to both the clients
 */
void
rpd_server_extctrl_close (struct rpd_server_client *rsc)
{
    uint8_t known_count = 0;
    
    assert(rsc->client_id == RPD_SERVER_CLIENT_LSPCTRLER);
    
    for (int i = 0; i < RPD_EXTCTRL_LSP_SETUP_TYPE_MAX; i++)
    {
        if (EXTCTRL_CTX_PROTO_RETCALL(i, is_known_ext_ctrlr, boolean, rsc->rsc_name))
            known_count++;
    }    

    if (!known_count) {
        rpd_server_client_close(rsc);
    }
}

void
rpd_server_extctrl_startup (void)
{
    if (!tx_buffer_ptr) {
	sr_ero_str = task_mem_malloc(NULL, SR_ERO_STRLEN);
	tx_buffer_ptr = task_mem_malloc(NULL, TX_BUFFER_LEN);
    }
}

