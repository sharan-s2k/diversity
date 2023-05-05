/**
 * @file libpcep/object.c
 *
 * Path Computation Element Protocol, object-handling functions.
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: object.c 1332071 2023-04-25 18:01:55Z gchandraseka $ */
#include "object.h"

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#include "core.h"
#include "log.h"
#include "util.h"
#include "buffer.h"

#include <jnx/aux_types.h>

#include <jnx/swversion.h>

#define MAX_OBJ_LEN 65528
#define TLV_HEADER_LEN 4
#define PADDING 4

#define PCEP_SRV6_ERO_LEN_NAI_TYPE_ABSENT_WITH_SID_STRUCTURE 32
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_ABSENT_WITHOUT_SID_STRUCTURE 24
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE 24
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITH_SID_STRUCTURE 32
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITHOUT_SID_STRUCTURE 40
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITH_SID_STRUCTURE 48
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE 40
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITH_SID_STRUCTURE 48
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITHOUT_SID_STRUCTURE 56
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITH_SID_STRUCTURE 64
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITHOUT_SID_STRUCTURE 48
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITH_SID_STRUCTURE 56
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITHOUT_SID_STRUCTURE 64
#define PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITH_SID_STRUCTURE 72

#define PCEP_SRV6_RRO_LEN_NAI_TYPE_ABSENT_WITH_SID_STRUCTURE 32
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_ABSENT_WITHOUT_SID_STRUCTURE 24
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE 24
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITH_SID_STRUCTURE 32
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITHOUT_SID_STRUCTURE 40
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITH_SID_STRUCTURE 48
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE 40
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITH_SID_STRUCTURE 48
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITHOUT_SID_STRUCTURE 56
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITH_SID_STRUCTURE 64
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITHOUT_SID_STRUCTURE 48
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITH_SID_STRUCTURE 56
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITHOUT_SID_STRUCTURE 64
#define PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITH_SID_STRUCTURE 72

#define PCEP_MAX_COMPUTED_SEGMENT_LIST 128
/**
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 * | Flags                   |O|B|W|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
 * Junos PCC supports only weight TLV
 * Junos PCC partially supports Backup TLV
 */
#define PCEP_DEFAULT_MULTIPATH_FLAGS 3
#define PCEP_PATH_ATTRIBUTE_DEFAULT_BACKUP_FLAG 1

en_assoc_obj_complaince assoc_obj_complaince = ASSOC_OBJ_RFC_COMPLAINT;
bool obj_s2ls_IANA_compliant = true;
bool tlv_p2mp_ipv4_lsp_id_IANA_compliant = true;

/*SRv6*/
uint8_t srv6_ero_subobject_type = PCEP_ERO_SUB_SRV6_DEFAULT;
uint8_t srv6_rro_subobject_type = PCEP_RRO_SUB_SRV6_DEFAULT;
uint8_t srv6_pst_type = SRV6_PST_TYPE_DEFAULT;
uint8_t srcap_pst_type = SR_PST_TYPE;
uint16_t srv6_pce_capability_sub_tlv_type = SRV6_PCE_CAPABILITY_SUB_TLV_TYPE_DEFAULT;
uint16_t pathattribute_color_tlv_type = TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT;
uint8_t maximum_srv6_segment_list_depth = MAX_H_ENCAPS_MSD_VALUE_DEFAULT;

struct pcep_tlv {
    const tlv_type_t type;
    const uint16_t   length;
    const uint8_t    * const data;
};

struct pcep_tlv_ops {
    const char *name;
    unsigned   fixlen;
};

static const struct pcep_tlv_ops tlv_ops[] = {
    [TLV_NO_PATH_VECTOR] = {
        .name   = "NO-PATH-VECTOR",
        .fixlen = TLV_NO_PATH_VECTOR_FIXED_LEN,
    },
    [TLV_OVERLOADED_DURATION] = {
        .name   = "OVERLOADED-DURATION",
        .fixlen = TLV_OVERLOADED_DURATION_FIXED_LEN,
    },
    [TLV_REQ_MISSING] = {
        .name   = "REQ-MISSING",
        .fixlen = TLV_REQ_MISSING_FIXED_LEN,
    },
    [TLV_STATEFUL_PCE_CAPABILITY] = {
        .name   = "TLV_STATEFUL_PCE_CAPABILITY",
        .fixlen = TLV_STATEFUL_PCE_CAPABILITY_FIXED_LEN,
    },
    [TLV_LSP_SYMBOLIC_NAME] = {
        .name   = "TLV_LSP_SYMBOLIC_NAME",
        .fixlen = TLV_LSP_SYMBOLIC_NAME_FIXED_LEN,
    },
    [TLV_IPV4_LSP_IDENTIFIERS] = {
        .name   = "TLV_IPV4_LSP_IDENTIFIERS",
        .fixlen = TLV_IPV4_LSP_IDENTIFIERS_FIXED_LEN,
    },
    [TLV_IPV6_LSP_IDENTIFIERS] = {
        .name   = "TLV_IPV6_LSP_IDENTIFIERS",
        .fixlen = TLV_IPV6_LSP_IDENTIFIERS_FIXED_LEN,
    },
    [TLV_IPV4_RSVP_ERROR_SPEC] = {
        .name   = "TLV_IPV4_RSVP_ERROR_SPEC",
        .fixlen = TLV_IPV4_RSVP_ERROR_SPEC_FIXED_LEN,
    },
    [TLV_IPV6_RSVP_ERROR_SPEC] = {
        .name   = "TLV_IPV6_RSVP_ERROR_SPEC",
        .fixlen = TLV_IPV6_RSVP_ERROR_SPEC_FIXED_LEN,
    },
    [TLV_LSP_UPDATE_ERROR_CODE] = {
        .name   = "TLV_LSP_UPDATE_ERROR_CODE",
        .fixlen = TLV_LSP_UPDATE_ERROR_CODE_FIXED_LEN,
    },
    [TLV_LSP_DB_VERSION] = {
        .name   = "TLV_LSP_DB_VERSION",
        .fixlen = TLV_LSP_DB_VERSION_FIXED_LEN,
    },
    [TLV_NODE_IDENTIFIER] = {
        .name   = "TLV_NODE_IDENTIFIER",
        .fixlen = TLV_NODE_IDENTIFIER_FIXED_LEN,
    },
    [TLV_VENDOR_LSP_QUALIFIER] = {
        .name = "TLV_VENDOR_LSP_QUALIFIER",
        .fixlen = TLV_VENDOR_LSP_QUALIFIER_FIXED_LEN,
    },
    [TLV_VENDOR_LSP_BW] = {
        .name = "TLV_VENDOR_LSP_BW",
        .fixlen = TLV_VENDOR_LSP_BW_FIXED_LEN,
    },
    [TLV_VENDOR_LSP_ROUTE_PREFERENCE] = {
        .name = "TLV_VENDOR_ROUTE_PREFERENCE",
        .fixlen = TLV_VENDOR_ROUTE_PREFERENCE_FIXED_LEN,
    },
    /*
     * FIXME:dilip : add p2mp related fields here.
     */
    [TLV_VENDOR_P2MP_TREE_NAME] = {
        .name = "TLV_VENDOR_P2MP_TREE_NAME",
        .fixlen = 0,
    },
    /*
     * TLV type for TLV_VENDOR_LOCAL_CSPF is same as
     * TLV_SR_CANDIDATE_PATH_IDENTIFIER. So, cannot do length
     * check for TLV_VENDOR_LOCAL_CSPF here. Also, making
     * fixlen for TLV_SR_CANDIDATE_PATH_IDENTIFIER as 0
     *
     * Length check is done in decoding function
     *
     * Below code is commented intentionally as this
     * code should not be added again by mistake
     *
    [TLV_VENDOR_LOCAL_CSPF] = {
        .name = "TLV_VENDOR_LOCAL_CSPF",
        .fixlen = TLV_VENDOR_LOCAL_CSPF_FIXED_LEN,
    },
    */
    [TLV_SR_PCE_CAPABILITY] = {
        .name = "TLV_SR_PCE_CAPABILITY",
        .fixlen = TLV_SR_PCE_CAPABILITY_FIXED_LEN,
    },
    [TLV_PATH_SETUP_TYPE_CAPABILITY] = {
        .name = "TLV_PATH_SETUP_TYPE_CAPABILITY",
        .fixlen = TLV_PATH_SETUP_TYPE_CAPABILITY_LEN,
    },
    [TLV_PATH_SETUP_TYPE] = {
        .name = "TLV_PATH_SETUP_TYPE",
        .fixlen = TLV_PATH_SETUP_TYPE_FIXED_LEN,
    },
    [TLV_TE_PATH_BINDING] = {
        .name = "TLV_TE_PATH_BINDING",
        .fixlen = 0,
    },
    [TLV_BYPASS] = {
        .name = "TLV_BYPASS",
        .fixlen = TLV_BYPASS_FIXED_LEN,
    },
    [TLV_MULTIPATH_CAPABILITY] = {
        .name = "TLV_MULTIPATH_CAPABILITY",
        .fixlen = TLV_MULTIPATH_CAPABILITY_FIXED_LEN,
    },
    [TLV_MULTIPATH_WEIGHT] = {
        .name = "TLV_MULTIPATH_WEIGHT",
        .fixlen = TLV_MULTIPATH_WEIGHT_FIXED_LEN,
    },
    [TLV_MULTIPATH_BACKUP] = {
        .name = "TLV_MULTIPATH_BACKUP",
        .fixlen = TLV_MULTIPATH_BACKUP_LEN,
    },
    [TLV_PCE_FLOWSPEC_CAPABILITY] = {
        .name = "TLV_PCE_FLOWSPEC_CAPABILITY",
        .fixlen = TLV_PCE_FLOWSPEC_CAPABILITY_LEN,
    },
    [TLV_FLOWSPEC_FLOWFILTER] = {
        .name = "TLV_FLOWSPEC_FLOWFILTER",
        .fixlen = 0,
    },
    [TLV_PATH_PROTECTION_ASSOCIATION] = {
        .name = "TLV_PATH_PROTECTION_ASSOCIATION",
        .fixlen = TLV_PATH_PROTECTION_ASSOC_FIXED_LEN,
    },
    [TLV_EXTENDED_ASSOCIATION_ID] = {
        .name = "TLV_EXTENDED_ASSOCIATION_ID",
        .fixlen = 0,
    },
    [TLV_ASSOCIATION_TYPE_LIST] = {
        .name = "TLV_ASSOCIATION_TYPE_LIST",
        .fixlen = 0,
    },
    [TLV_DISJOINT_CONFIGURATION] = {
        .name = "TLV_DISJOINT_ASSOCIATION_CONFIGURATION",
        .fixlen = TLV_DISJOINT_CONFIGURATION_FIXED_LEN,
    },
    [TLV_DISJOINT_STATUS] = {
        .name = "TLV_DISJOINT_ASSOCIATION_STATUS",
        .fixlen = TLV_DISJOINT_STATUS_FIXED_LEN,
    },
    /*
     * TLV type for TLV_VENDOR_LOCAL_CSPF is same as
     * TLV_SR_CANDIDATE_PATH_IDENTIFIER. So, cannot do length
     * check for TLV_SR_CANDIDATE_PATH_IDENTIFIER here. So, making
     * fixlen for TLV_SR_CANDIDATE_PATH_IDENTIFIER as 0
     *
     * Length check is done in decoding function
     */
    [TLV_SR_CANDIDATE_PATH_IDENTIFIER] = {
        .name = "TLV_SR_CANDIDATE_PATH_IDENTIFIER",
        .fixlen = 0,
    },
    [TLV_SR_PREFERENCE] = {
        .name = "TLV_SR_PREFERENCE",
        .fixlen = TLV_SR_PREFERENCE_FIXED_LEN,
    },
    [TLV_VERSION_INFO] = {
        .name   = "TLV_VERSION_INFO",
        .fixlen = TLV_VERSION_INFO_FIXED_LEN,
    }
};

static const struct pcep_tlv_ops cli_configurable_tlv_ops[] = {
    [TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT] = {
        .name = "TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT",
        .fixlen = TLV_MULTIPATH_PATHATTRIBUTE_COLOR_FIXED_LEN,
    }
};

/**
 *  If TLV type is configurable, refer cli_configurable_tlv_ops array,
 *  if TLV type is not configurable, refer tlv_ops array
 */
const struct pcep_tlv_ops *
get_pcep_tlv_ops (uint16_t tlv_type)
{
    /*
     * Add configurable TLV types here
     */
     if (tlv_type == pathattribute_color_tlv_type) 
         return (cli_configurable_tlv_ops + TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT);


    /* Get pcep_tlv_ops structure from tlv_ops array as TLV is not configurable */
    return (tlv_ops + tlv_type);
}

static bool
is_pcep_tlv_cli_configurable (const tlv_type_t tlv_type UNUSED)
{
    bool flag =  false;

    if (tlv_type == pathattribute_color_tlv_type) {
        flag =  true;
    }

    return flag;
}


/**
 * Parse a bandwidth object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_bandwidth (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                     uint16_t datalen UNUSED)
{
    struct pcep_obj_bandwidth *obj = ptr;
    obj->bps = ntoh_float(data);
    return 4;
}

/**
 * Parse a close object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_close (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                 uint16_t datalen UNUSED)
{
    struct pcep_obj_close *obj = ptr;
    /* First two bytes are reserved */
    /* Third byte is flags */
    obj->reason = data[3];
    return 4;
}

/**
 * Parse a endpoints_ipv4 object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_endpoints_ipv4 (struct pcep *pcep UNUSED, void *ptr,
                          const uint8_t *data, uint16_t datalen UNUSED)
{
    struct pcep_obj_endpoints_ipv4 *obj = ptr;
    memcpy(&obj->source, data, 4);
    memcpy(&obj->destination, data + 4, 4);
    return 8;
}

/**
 * Parse a endpoints_ipv6 object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_endpoints_ipv6 (struct pcep *pcep UNUSED, void *ptr,
                          const uint8_t *data, uint16_t datalen UNUSED)
{
    struct pcep_obj_endpoints_ipv6 *obj = ptr;
    memcpy(&obj->source, data, 16);
    memcpy(&obj->destination, data + 16, 16);
    return 32;
}

/**
 * Parse a endpoints_ipv4 object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_p2mp_endpoints_ipv4 (struct pcep *pcep UNUSED, void *ptr,
                          const uint8_t *data, uint16_t datalen)
{
    struct pcep_obj_p2mp_endpoints_ipv4 *obj = ptr;
     /* append all subs to the object */
     unsigned suboffset=0;
     uint8_t sub_len = sizeof(uint32_t);
     int read = 0;
     obj->subcount=0;

    /* Read Leaf Type */
     obj->leaftype = (LeafType)ntoh_uint32_t(data);
     datalen-=sub_len;
     suboffset+=sub_len; 
     read += sub_len;

     /* Read Source address */
     memcpy(&obj->source, data + suboffset, 4);
     datalen-=sub_len;
     suboffset+=sub_len;
     read += sub_len;

     /* Read all destination addresses */
     while (datalen>0) {
         if (datalen < PADDING) {
            log_error(pcep, "Incomplete subobject. Object len: %d, min 4",
                      datalen);
            return -1;
         }

        memcpy(&obj->destinations[obj->subcount], data + suboffset, 4);

        datalen-=sub_len;
        suboffset+=sub_len;
        obj->subcount++;
        read += sub_len;
    }
    return read;
}

/**
 * Parse an error object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_error (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                 uint16_t datalen UNUSED)
{
    struct pcep_obj_error *obj = ptr;
    /* First byte is flags */
    obj->type  = data[1];
    obj->value = data[2];
    /* Fourth byte is reserved */
    return 4;
}

/**
 * Parse a loadbalancing object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_loadbalancing (struct pcep *pcep UNUSED, void *ptr,
                         const uint8_t *data, uint16_t datalen UNUSED)
{
    struct pcep_obj_loadbalancing *obj = ptr;
    /* First two bytes are reserved */
    /* Third byte is flags */
    obj->max_lsp       = data[3];
    obj->min_bandwidth = ntoh_float(data + 4);
    return 8;
}

/**
 * Parse a lsp object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 *
 * RFC 8623 Compliant
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                PLSP-ID                |Flg|F|N|C|  O  |A|R|S|D|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //                        TLVs                                 //
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static int
parse_obj_lsp (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
               uint16_t datalen UNUSED)
{
    struct pcep_obj_lsp *obj = ptr;

    obj->plsp_id     = (data[0] << 12) | (data[1] << 4) | (data[2] >> 4);

    /* Next 12 bits are flags */
    obj->fragment = (data[2] & 0x02) >> 1;
    obj->p2mp_branch = data[2] & 0x01;

    obj->pce_created =  data[3] & 0x80;

    /* Three bits for operational flag
     * 0 - Down: not active
     * 1 - UP: signalled
     * 2 - ACTIVE: up and carrying traffic.
     * 3 - GOING-DOWN: LSP is being torn down, resources are being released
     * 4 - GOING-UP: LSP is being signalled
     * 5-7 - Reserved: these values are reserved for future use.
     */
    obj->operational = (data[3] & 0x70) >> 4;
    obj->administrative = (data[3] & 0x08) >> 3;
    obj->remove      = (data[3] & 0x04) >> 2;
    obj->last_update = (data[3] & 0x02) >> 1;
    obj->delegated   = (data[3] & 0x01);
    
    return 4;
}

/**
 * Parse a lspa object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_lspa (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                uint16_t datalen UNUSED)
{
    struct pcep_obj_lspa *obj = ptr;
    obj->pol_exclude_any = ntoh_uint32_t(data);
    obj->pol_include_any = ntoh_uint32_t(data + 4);
    obj->pol_include_all = ntoh_uint32_t(data + 8);
    obj->setup_prio  = data[12];
    obj->hold_prio   = data[13];
    /* First 7 bits are flags */
    obj->local_prot  = data[14] & 1;
    /* Sixteenth byte is reserved */
    return 16;
}

/**
 * Parse a metric object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_metric (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                  uint16_t datalen UNUSED)
{
    struct pcep_obj_metric *obj = ptr;
    /* First two bytes are reserved */
    /* Third byte is flags */
    obj->computed = (data[2] >> 1) & 1;
    obj->bound    =  data[2]       & 1;
    obj->type     =  data[3];
    obj->value    = ntoh_float(data + 4);
    return 8;
}

/**
 * Parse a nopath object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_nopath (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                  uint16_t datalen UNUSED)
{
    struct pcep_obj_nopath *obj = ptr;
    obj->issue       = data[0];
    obj->constraints = data[1] >> 7;
    /* Next 15 bits are flags */
    /* Fourth byte is reserved */
    return 4;
}

/**
 * Parse a notification object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_notification (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                        uint16_t datalen UNUSED)
{
    struct pcep_obj_notification *obj = ptr;
    /* First byte is reserved */
    /* Second byte is flags */
    obj->type  = data[2];
    obj->value = data[3];
    return 4;
}

/**
 * Parse an open object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_open (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                uint16_t datalen UNUSED)
{
    struct pcep_obj_open *obj = ptr;
    obj->version    = data[0] >> 5;
    /* Next 5 bits are flags */
    obj->keepalive  = data[1];
    obj->deadtimer  = data[2];
    obj->session_id = data[3];
    obj->stateful = 0;
    obj->active = 0;
    obj->lsp_provisioning = 0;
    obj->p2mp_lsp_report_capability = 0;
    obj->p2mp_lsp_update_capability = 0;
    obj->p2mp_lsp_init_capability = 0;
	obj->spring_capability = 0;
    obj->srv6_capability = 0;
    obj->pce_flowspec_capability = 0;
    obj->path_protection_association = false;
    obj->srpag_association = false;
    obj->multipath_capability = false;
    obj->max_segment_list = 1;
    obj->disjoint_assoc_capability = false;
    return 4;
}

/**
 * Parse a rp object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size, -1 in case of error
 */
static int
parse_obj_rp (struct pcep *pcep, void *ptr, const uint8_t *data,
              uint16_t datalen UNUSED)
{
    struct pcep_obj_rp *obj = ptr;
    /* First 26 bits are flags */
    obj->loose          = (data[3] >>  5) & 1;
    obj->bidirectional  = (data[3] >>  4) & 1;
    obj->reoptimization = (data[3] >>  3) & 1;
    obj->priority       =  data[3]        & 7;
    obj->request_id     = ntoh_uint32_t(data + 4);

    if (obj->request_id == 0) {
        log_error(pcep, "Invalid RP object (request_id=%u)", obj->request_id);
        return -1;
    }
    return 8;
}

/**
 * Parse an ero object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size, -1 in case of error
 */
static int
parse_obj_ero (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
               uint16_t datalen)
{
    struct pcep_obj_ero *obj = ptr;
    
     /* append all subs to the object */
     unsigned suboffset=0;
     uint8_t sub_len = 0;
     int read = 0;
     obj->subcount=0;
     while (datalen>0) {
         if (datalen < PADDING) {
            log_error(pcep, "Incomplete subobject. Object len: %d, min 4",
                      datalen);
            return -1;
         }
         obj->subs[obj->subcount].loose = (data[suboffset] & 0x80);
         obj->subs[obj->subcount].type = data[suboffset] & 0x7F;
         sub_len = data[suboffset + 1];
         if (sub_len % PADDING) {
             log_error(pcep, "Subobject length: %d is not padded to 4",
                       sub_len);
             return -1;
         }

         if (obj->subs[obj->subcount].type == srv6_ero_subobject_type) {

             unsigned srv6_read = suboffset + 2; /* Type and Length is already parsed */
             struct pcep_obj_ero_sub_srv6 *srv6_ero = NULL;

             if (sub_len < 24) {
                 log_error(pcep, "Invalid sub-object length: %d for SRV6-ERO",
                           sub_len);
                 return -1;
             }

             srv6_ero = &obj->subs[obj->subcount].data.srv6_ero;
             srv6_ero->nai_type = ((data[srv6_read] >> 4) & 0x0F);
             srv6_read += 1;
             srv6_ero->V_bit = ((data[srv6_read] >> 3) & 0x1);
             srv6_ero->T_bit = ((data[srv6_read] >> 2) & 0x1);
             srv6_ero->F_bit = ((data[srv6_read] >> 1) & 0x1);
             srv6_ero->S_bit = (data[srv6_read] & 0x1);
             srv6_read += 1;

             srv6_read += 2; //Don't read Reserved bytes
             srv6_ero->endpoint_behavior = ntoh_uint16_t(data + srv6_read);
             srv6_read += 2;

             if (!srv6_ero->S_bit) {
                 memcpy(&srv6_ero->sid, data+srv6_read, 16);
             }
             srv6_read += 16;

             switch (srv6_ero->nai_type) {
                 case PCEP_SR_ERO_NAI_TYPE_ABSENT:
                     break;
                 case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                     memcpy(&srv6_ero->NAI_data.ipv6_node_id.address,
                            data+srv6_read, 16);
                     srv6_read += 16;
                     break;
                 case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
                     memcpy(&srv6_ero->NAI_data.ipv6_adjacency.local,
                            data+srv6_read, 16);
                     srv6_read += 16;
                     memcpy(&srv6_ero->NAI_data.ipv6_adjacency.remote,
                            data+srv6_read, 16);
                     srv6_read += 16;
                     break;
                 case PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                     memcpy(&srv6_ero->NAI_data.ipv6_linklocal_adj.local_ipv6_addr,
                            data+srv6_read, 16);
                     srv6_read += 16;
                     srv6_ero->NAI_data.ipv6_linklocal_adj.local_interface_id =
                         ntoh_uint32_t(data+srv6_read);
                     srv6_read += 4;
                     memcpy(&srv6_ero->NAI_data.ipv6_linklocal_adj.remote_ipv6_addr,
                            data+srv6_read, 16);
                     srv6_read += 16;
                     srv6_ero->NAI_data.ipv6_linklocal_adj.remote_interface_id =
                         ntoh_uint32_t(data+srv6_read);
                     srv6_read += 4;
                     break;
                 default:
                     srv6_ero->nai_type = PCEP_SR_ERO_NAI_TYPE_INVALID;
                     log_error(pcep, "Invalid subobject:SRV6-ERO, NAI type %d",
                             srv6_ero->nai_type);
                     break;
             }

             if (srv6_ero->T_bit) {
                 srv6_ero->sid_structure.lb_length = data[srv6_read];
                 srv6_read += 1;
                 srv6_ero->sid_structure.ln_length = data[srv6_read];
                 srv6_read += 1;
                 srv6_ero->sid_structure.fun_length = data[srv6_read];
                 srv6_read += 1;
                 srv6_ero->sid_structure.arg_length = data[srv6_read];
                 srv6_read += 1;
             }
         } else {
             switch (obj->subs[obj->subcount].type) {
             case PCEP_ERO_SUB_IPV4:
                 if (sub_len != 8) {
                     log_error(pcep, "Invalid sub-object length: %d for IPv4",
                               sub_len);
                     return -1;
                 }
                memcpy(&obj->subs[obj->subcount].data.ipv4_prefix.address,
                       data+suboffset+2, 4);
                 obj->subs[obj->subcount].data.ipv4_prefix.prefix_length =
                    data[suboffset+6];
                break;
             case PCEP_ERO_SUB_IPV6:
                 if (sub_len != 20) {
                     log_error(pcep, "Invalid sub-object length: %d for IPv6",
                               sub_len);
                     return -1;
                 }
                memcpy(&obj->subs[obj->subcount].data.ipv6_prefix.address,
                       data+suboffset+2, 16);
                 obj->subs[obj->subcount].data.ipv6_prefix.prefix_length =
                    data[suboffset+18];
                break;
            case PCEP_ERO_SUB_LABEL:
                 if (sub_len != 8) {
                     log_error(pcep, "Invalid sub-object length: %d for Label",
                               sub_len);
                     return -1;
                 }
                 obj->subs[obj->subcount].data.label.upstream = (data[suboffset+2]
                                                                 & 0x80);
                obj->subs[obj->subcount].data.label.ctype = data[suboffset+3];
                obj->subs[obj->subcount].data.label.label=
                    ntoh_uint32_t(data+suboffset+4);
                break;
            case PCEP_ERO_SUB_UNNUMBERED_IID:
                 if (sub_len != 12) {
                     log_error(pcep, "Invalid sub-object length: %d for Unnumbered "
                               "Interface ID", sub_len);
                     return -1;
                 }
                obj->subs[obj->subcount].data.unnumbered_iid.router_id=
                    ntoh_uint32_t(data+suboffset+4);
                obj->subs[obj->subcount].data.unnumbered_iid.interface_id=
                    ntoh_uint32_t(data+suboffset+8);
                break;
            case PCEP_ERO_SUB_AUTONOMOUS:
                 if (sub_len != 4) {
                     log_error(pcep, "Invalid sub-object length: %d for Autonomous",
                               sub_len);
                     return -1;
                 }
             obj->subs[obj->subcount].data.autonomous.system_number=
                    ntoh_uint16_t(data+suboffset+2);
                break;
            case PCEP_ERO_SUB_SR:
                {
                    struct pcep_obj_ero_sub_sr *sr_ero = NULL;
                    if (sub_len < 8) {
                        log_error(pcep, "Invalid sub-object length: %d for SR-ERO",
                                  sub_len);
                        return -1;
                    }
                    sr_ero = &obj->subs[obj->subcount].data.sr_ero;
                    sr_ero->nai_type = ((data[suboffset+2] >> 4) & 0x0F);
                    sr_ero->F_bit = ((data[suboffset+3] >> 3) & 0x1);
                    sr_ero->S_bit = ((data[suboffset+3] >> 2) & 0x1);
                    sr_ero->C_bit = ((data[suboffset+3] >> 1) & 0x1);
                    sr_ero->M_bit = (data[suboffset+3] & 0x1);
    
                    if (sr_ero->S_bit) {
                        if (sr_ero->F_bit) {
                            log_error(pcep, "Invalid subobject:SR-ERO");
                            return -1;
                        }
                    } else {
                        if (sr_ero->M_bit) {
                            sr_ero->sid = (ntoh_uint32_t(data+suboffset+4)>>12);
                        }
                        else {
                            sr_ero->sid = ntoh_uint32_t(data+suboffset+4);
                        }
                    }
    
                    switch (sr_ero->nai_type) {
                        case PCEP_SR_ERO_NAI_TYPE_ABSENT:
                            break;
                        case PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                            memcpy(&sr_ero->NAI_data.ipv4_node_id.address,
                                data+suboffset+8, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                            memcpy(&sr_ero->NAI_data.ipv6_node_id.address,
                                data+suboffset+8, 16);
                            break;
#endif
                        case PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ:
                            memcpy(&sr_ero->NAI_data.ipv4_adjacency.local,
                                data+suboffset+8, 4);
                            memcpy(&sr_ero->NAI_data.ipv4_adjacency.remote,
                                data+suboffset+12, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
                            memcpy(&sr_ero->NAI_data.ipv6_adjacency.local,
                                data+suboffset+8, 16);
                            memcpy(&sr_ero->NAI_data.ipv6_adjacency.remote,
                                data+suboffset+24, 16);
                            break;
#endif
#ifdef PCEP_SR_UNNUMBERED
                        case PCEP_SR_ERO_NAI_TYPE_UNNUMBERED:
                            sr_ero->NAI_data.unnum_adj.local_node_id =
                                ntoh_uint32_t(data+suboffset+8);
                            sr_ero->NAI_data.unnum_adj.local_interface_id =
                                ntoh_uint32_t(data+suboffset+12);
                            sr_ero->NAI_data.unnum_adj.remote_node_id =
                                ntoh_uint32_t(data+suboffset+16);
                            sr_ero->NAI_data.unnum_adj.remote_interface_id =
                                ntoh_uint32_t(data+suboffset+20);
                            break;
#endif
                        default:
                        /* don't know what do with empty ero type or unknown type so return error */
                            log_error(pcep, "Invalid subobject:SR-ERO");
                            return -1;
                    }
                    break;
                }
            default:
                log_error(pcep, "Invalid subobject: %d", obj->subs[obj->subcount].type);
                return -1;
             }
        }
        datalen-=sub_len;      // substract sub length from data length
        suboffset+=sub_len;    // and add it to offset for next object
        obj->subcount++;
        read += sub_len;
    }
    return read;
}

/**
 * Parse a rro object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size, -1 in case of error
 */
static int
parse_obj_rro (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
               uint16_t datalen)
{
    struct pcep_obj_rro *obj = ptr;
    int read = 0;
    /* append all subs to the object */
    uint suboffset=0;
    uint8_t sub_len = 0;

    obj->subcount=0;
    while (datalen>0) {
        if (datalen < PADDING) {
            log_error(pcep, "Incomplete subobject. Object len: %d, min 4",
                   datalen);
            return -1;
        }
        obj->subs[obj->subcount].type = data[suboffset];
        sub_len = data[suboffset+1];
        if (sub_len % PADDING) {
            log_error(pcep, "Subobject length: %d is not padded to 4",
                   sub_len);
            return -1;
        }
        if (obj->subs[obj->subcount].type == srv6_rro_subobject_type) {

            uint srv6_read = suboffset + 2; /** Type and length is already parsed*/
            struct pcep_obj_rro_sub_srv6 *srv6_rro = NULL;

            if (sub_len < 24) {
                log_error(pcep, "Invalid sub-object length: %d for SRV6-RRO",
                          sub_len);
                return -1;
            }

            srv6_rro = &obj->subs[obj->subcount].data.srv6_rro;
            srv6_rro->nai_type = ((data[srv6_read] >> 4) & 0x0F);
            srv6_read += 1;
            srv6_rro->V_bit = ((data[srv6_read] >> 3) & 0x1);
            srv6_rro->T_bit = ((data[srv6_read] >> 2) & 0x1);
            srv6_rro->F_bit = ((data[srv6_read] >> 1) & 0x1);
            srv6_rro->S_bit = (data[srv6_read] & 0x1);
            srv6_read += 1;

            srv6_read += 2; //Reserved field should not be parsed
            srv6_rro->endpoint_behavior = ntoh_uint16_t(data + srv6_read);
            srv6_read += 2;

            if (srv6_rro->S_bit) {
                log_error(pcep, "SRV6-RRO:SID is not present");
                return -1;
            } else {
                memcpy(&srv6_rro->sid, data+srv6_read, 16);
            }
            srv6_read += 16;

            switch (srv6_rro->nai_type) {
                case PCEP_SR_RRO_NAI_TYPE_ABSENT:
                    break;
                case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
                    memcpy(&srv6_rro->NAI_data.ipv6_node_id.address,
                           data+srv6_read, 16);
                    srv6_read += 16;
                    break;
                case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
                    memcpy(&srv6_rro->NAI_data.ipv6_adjacency.local,
                           data+srv6_read, 16);
                    srv6_read += 16;
                    memcpy(&srv6_rro->NAI_data.ipv6_adjacency.remote,
                           data+srv6_read, 16);
                    srv6_read += 16;
                    break;
                case PCEP_SR_RRO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                    memcpy(&srv6_rro->NAI_data.ipv6_linklocal_adj.local_ipv6_addr,
                           data+srv6_read, 16);
                    srv6_read += 16;
                    srv6_rro->NAI_data.ipv6_linklocal_adj.local_interface_id =
                        ntoh_uint32_t(data+srv6_read);
                    srv6_read += 4;
                    memcpy(&srv6_rro->NAI_data.ipv6_linklocal_adj.remote_ipv6_addr,
                           data+srv6_read, 16);
                    srv6_read += 16;
                    srv6_rro->NAI_data.ipv6_linklocal_adj.remote_interface_id =
                        ntoh_uint32_t(data+srv6_read);
                    srv6_read += 4;
                    break;
                default:
                    srv6_rro->nai_type = PCEP_SR_RRO_NAI_TYPE_INVALID;
                    log_error(pcep, "Invalid subobject:SRV6-RRO, NAI type %d",
                            srv6_rro->nai_type);
                    break;
            }

            if (srv6_rro->T_bit) {
                srv6_rro->sid_structure.lb_length = data[srv6_read];
                srv6_read += 1;
                srv6_rro->sid_structure.ln_length = data[srv6_read];
                srv6_read += 1;
                srv6_rro->sid_structure.fun_length = data[srv6_read];
                srv6_read += 1;
                srv6_rro->sid_structure.arg_length = data[srv6_read];
                srv6_read += 1;
            }
        }
        else {
        switch (obj->subs[obj->subcount].type) {
        case PCEP_RRO_SUB_IPV4:
            if (sub_len != 8) {
                log_error(pcep, "Invalid sub-object length: %d for IPv4",
                          sub_len);
                return -1;
            }
            memcpy(&obj->subs[obj->subcount].data.ipv4_address.address,
                   data+suboffset+2, 4);
	    obj->subs[obj->subcount].data.ipv4_address.flags = 
		(data[suboffset+7]);
            obj->subs[obj->subcount].data.ipv4_address.lprot_available =
                (data[suboffset+7] & 0x01);
            obj->subs[obj->subcount].data.ipv4_address.lprot_inuse =
                (data[suboffset+7] & 0x02);
            break;
        case PCEP_RRO_SUB_IPV6:
            if (sub_len != 20) {
                log_error(pcep, "Invalid sub-object length: %d for IPv6",
                          sub_len);
                return -1;
            }
            memcpy(&obj->subs[obj->subcount].data.ipv6_address.address,
                   data+suboffset+2, 16);
	    obj->subs[obj->subcount].data.ipv6_address.flags = 
		(data[suboffset+19]);
            obj->subs[obj->subcount].data.ipv6_address.lprot_available =
                (data[suboffset+19] & 0x01);
            obj->subs[obj->subcount].data.ipv6_address.lprot_inuse =
                (data[suboffset+19] & 0x02);
            break;
       case PCEP_RRO_SUB_LABEL:
            if (sub_len != 8) {
                log_error(pcep, "Invalid sub-object length: %d for Label",
                          sub_len);
                return -1;
            }
            obj->subs[obj->subcount].data.label.upstream = (data[suboffset+2]
                                                            & 0x80);
            obj->subs[obj->subcount].data.label.global_label =
                    (data[suboffset+2] & 0x01);
            obj->subs[obj->subcount].data.label.ctype = data[suboffset+3];
            obj->subs[obj->subcount].data.label.label=
                ntoh_uint32_t(data+suboffset+4);
            break;
       case PCEP_RRO_SUB_UNNUMBERED_IID:
            if (sub_len != 12) {
                log_error(pcep, "Invalid sub-object length: %d for Unnumbered "
                          "Interface ID", sub_len);
                return -1;
            }
            obj->subs[obj->subcount].data.unnumbered_iid.router_id=
                ntoh_uint32_t(data+suboffset+4);
            obj->subs[obj->subcount].data.unnumbered_iid.interface_id=
                ntoh_uint32_t(data+suboffset+8);
            break;
        case PCEP_RRO_SUB_SR:
            {
                struct pcep_obj_rro_sub_sr *sr_rro = NULL;
                if (sub_len < 8) {
                    log_error(pcep, "Invalid sub-object length: %d for SR-RRO",
                              sub_len);
                    return -1;
                }
                sr_rro = &obj->subs[obj->subcount].data.sr_rro;
                sr_rro->nai_type = ((data[suboffset+2] >> 4) & 0x0F);
                sr_rro->F_bit = ((data[suboffset+3] >> 3) & 0x1);
                sr_rro->S_bit = ((data[suboffset+3] >> 2) & 0x1);
                sr_rro->C_bit = ((data[suboffset+3] >> 1) & 0x1);
                sr_rro->M_bit = (data[suboffset+3] & 0x1);
    
                if (sr_rro->M_bit) {
                    sr_rro->sid = (ntoh_uint32_t(data+suboffset+4) >> 12);
                }
                else {
                    sr_rro->sid = ntoh_uint32_t(data+suboffset+4);
                }
    
                if (sr_rro->S_bit && sr_rro->F_bit) {
                    /* need to add error type */
                    log_error(pcep, "Invalid subobject:SR-RRO");
                    return -1;
                }
                if (!sr_rro->S_bit && !sr_rro->F_bit) {
                    sr_rro->sid = ntoh_uint32_t(data+suboffset+4);
                    switch (sr_rro->nai_type) {
                        case PCEP_SR_RRO_NAI_TYPE_ABSENT:
                            break;
                       case PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID:
                            memcpy(&sr_rro->NAI_data.ipv4_node_id.address,
                                   data+suboffset+8, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
                            memcpy(&sr_rro->NAI_data.ipv6_node_id.address,
                                   data+suboffset+8, 16);
                            break;
#endif
                        case PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ:
                            memcpy(&sr_rro->NAI_data.ipv4_adjacency.local,
                                   data+suboffset+8, 4);
                            memcpy(&sr_rro->NAI_data.ipv4_adjacency.remote,
                                   data+suboffset+12, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
                            memcpy(&sr_rro->NAI_data.ipv6_adjacency.local,
                                   data+suboffset+8, 16);
                            memcpy(&sr_rro->NAI_data.ipv6_adjacency.remote,
                                   data+suboffset+24, 16);
                            break;
#endif
#ifdef PCEP_SR_UNNUMBERED
                        case PCEP_SR_RRO_NAI_TYPE_UNNUMBERED:
                            sr_rro->NAI_data.unnum_adj.local_node_id =
                                            ntoh_uint32_t(data+suboffset+8);
                            sr_rro->NAI_data.unnum_adj.local_interface_id =
                                            ntoh_uint32_t(data+suboffset+12);
                            sr_rro->NAI_data.unnum_adj.remote_node_id =
                                            ntoh_uint32_t(data+suboffset+16);
                            sr_rro->NAI_data.unnum_adj.remote_interface_id =
                                            ntoh_uint32_t(data+suboffset+20);
                            break;
#endif
                        default:
                            break;
                    }
                } else if (sr_rro->S_bit && !sr_rro->F_bit) {
                    switch (sr_rro->nai_type) {
                        case PCEP_SR_RRO_NAI_TYPE_ABSENT:
                            break;
                       case PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID:
                            memcpy(&sr_rro->NAI_data.ipv4_node_id.address,
                                   data+suboffset+4, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
                            memcpy(&sr_rro->NAI_data.ipv6_node_id.address,
                                   data+suboffset+4, 16);
                            break;
#endif
                        case PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ:
                            memcpy(&sr_rro->NAI_data.ipv4_adjacency.local,
                                   data+suboffset+4, 4);
                            memcpy(&sr_rro->NAI_data.ipv4_adjacency.remote,
                                   data+suboffset+8, 4);
                            break;
#ifdef PCEP_SR_IPV6
                        case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
                            memcpy(&sr_rro->NAI_data.ipv6_adjacency.local,
                                   data+suboffset+4, 16);
                            memcpy(&sr_rro->NAI_data.ipv6_adjacency.remote,
                                   data+suboffset+20, 16);
                            break;
#endif
#ifdef PCEP_SR_UNNUMBERED
                        case PCEP_SR_RRO_NAI_TYPE_UNNUMBERED:
                            sr_rro->NAI_data.unnum_adj.local_node_id =
                                            ntoh_uint32_t(data+suboffset+4);
                            sr_rro->NAI_data.unnum_adj.local_interface_id =
                                            ntoh_uint32_t(data+suboffset+8);
                            sr_rro->NAI_data.unnum_adj.remote_node_id =
                                            ntoh_uint32_t(data+suboffset+12);
                            sr_rro->NAI_data.unnum_adj.remote_interface_id =
                                            ntoh_uint32_t(data+suboffset+16);
                            break;
#endif
                        default:
                            break;
                    }  
                } else {
                    sr_rro->sid = ntoh_uint32_t(data+suboffset+4);
                }
                break;
            }
        default:
            log_error(pcep, "Invalid subobject type: %d", obj->subs[obj->subcount].type);
            break;
        }
    }
        datalen-=sub_len;   // substract sub length from data length
        suboffset+=sub_len; // and add it to offset for next object
        obj->subcount++;
        read += sub_len;
    }
    return read;
}

/**
 * Parse a svec object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size, -1 in case of error
 */
static int
parse_obj_svec (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                uint16_t datalen)
{
    struct pcep_obj_svec *obj = ptr;
    int read = 0;

    if (datalen % PADDING) {
        log_error(pcep, "SVEC object datalen: %d is not padded", datalen);
        return -1;
    }
    obj->link = data[3] & 0x01;
    obj->node = data[3] & 0x02;
    obj->SRLG = data[3] & 0x04;
    obj->id_count = 0;
    datalen -= OBJ_HEADER_LEN;
    data += OBJ_HEADER_LEN;
    while (datalen) {
        if (datalen < 4) {
            log_error(pcep, "Incomplete SVEC object. Object len: %d, min 4",
                      datalen);
            return -1;
        }
        obj->req_ids[obj->id_count] = ntoh_uint32_t(data);
        obj->id_count++;
        data += 4;
        datalen -= 4;
        read += 4;
    }
    return read;
}

/**
 * Parse a label object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_label (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                 uint16_t datalen UNUSED)
{
    struct pcep_obj_label *obj = ptr;
    obj->label = ntoh_uint32_t(data);
    return 4;
}

/**
 * Parse a SRP object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_srp (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
			   uint16_t datalen UNUSED)
{
	struct pcep_obj_srp *obj = ptr;
	obj->remove = ntoh_uint32_t(data) & 0x01;
	obj->srp_id = ntoh_uint32_t(data + 4);
	return 8;
}

/**
 * Parse a association_non_rfc object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_association_non_rfc (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
		       uint16_t datalen UNUSED)
{
    struct pcep_obj_association_non_rfc *obj = ptr;

    obj->type      = ((data[0] >> 4) & 0x0F);

    obj->generic_flags =  (((data[0] & 0x0F) << 6) | ((data[1] >> 2) & 0x3F));
    obj->flag_remove = ((data[1] >> 1) & 0x1);
    obj->type_specific_flags = (((data[1] & 0x1) << 14) | (data[2] << 6) |
			       ((data[3] >> 2) & 0x3F));
    obj->flag_standby = ((data[3] >> 1) & 0x1);
    obj->flag_protection = (data[3] & 0x1);
    obj->association_group_id = ((data[4] << 24) | (data[5] << 16) |
				 (data[6] << 8) | data[7]);
    return 8;
}

/**
 * Parse a associatio object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_association (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
		       uint16_t datalen UNUSED)
{
    struct pcep_obj_association *obj = ptr;
    uint8_t read = 0;
    uint16_t flags;

    obj->reserved = ntoh_uint16_t(data);
    read += 2;

    flags = ntoh_uint16_t(data + read);
    obj->flag_remove = (flags & 0x1);
    read += 2;

    obj->association_type = ntoh_uint16_t(data + read);
    read += 2;

    obj->association_id = ntoh_uint16_t(data + read);
    read += 2;

    memcpy(&obj->ipv4_association_source, data + read, 4);
    read += 4;

    obj->path_protection = false; //Default value
    obj->extended_assoc_id = false; //Default value
    obj->sr_candidate_path_identifier = false; //Default value
    obj->sr_preference = false; //Default value
    obj->disjoint_config = false;
    obj->disjoint_status = false;

    return 12;
}

/**
 * Parse a association-ipv6 object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_association_ipv6 (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
               uint16_t datalen UNUSED)
{
    struct pcep_obj_association_ipv6 *obj = ptr;
    uint8_t read = 0;
    uint16_t flags;

    obj->reserved = ntoh_uint16_t(data);
    read += 2;

    flags = ntoh_uint16_t(data + read);
    obj->flag_remove = (flags & 0x1);
    read += 2;

    obj->association_type = ntoh_uint16_t(data + read);
    read += 2;

    obj->association_id = ntoh_uint16_t(data + read);
    read += 2;

    memcpy(&obj->ipv6_association_source, data + read, 16);
    read += 16;

    obj->extended_assoc_id = false; //Default value
    obj->sr_candidate_path_identifier = false; //Default value
    obj->sr_preference = false; //Default value

    obj->disjoint_config = false;
    obj->disjoint_status = false;

    return 24;
}

/**
 * Parse a vendor object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_vendor (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
		       uint16_t datalen)
{
    struct pcep_obj_vendor*	obj;
    uint16_t read = 0;
    uint16_t suboffset = 0;
    int	tlv_type;
    uint16_t sub_len = 0;

    obj = ptr;
    obj->size = 0;
    obj->enterprise = ntoh_uint32_t(data);
    read = 4;
    suboffset = 4;

    if (JNPR_ENTERPRISE_NUMBER != obj->enterprise) {
	log_error(pcep, "unrecognized vendor tlv, vendor(%d)", obj->enterprise);
        // If Unrecognized vendor tlv, then need to return the object length
        return datalen;
    }

    while ((datalen - read) > 0) {
        if ((datalen - read) < 6) {
            log_error(pcep, "Incomplete vendor tlv. Object len: %d, min 6",
                    (datalen - read));
            return -1;
        }

        tlv_type = ntoh_uint16_t(&data[suboffset]);
        suboffset +=2;
        sub_len = ntoh_uint16_t(&data[suboffset]);
        suboffset +=2;
        obj->info[obj->size].enterprise = ntoh_uint32_t(&data[suboffset]);
        suboffset +=4;

        switch (tlv_type) {
        case TLV_VENDOR_LOCAL_CSPF:
            /**
             * Doing TLV length check here as TLV type for TLV_VENDOR_LOCAL_CSPF
             * is same TLV_SR_CANDIDATE_PATH_IDENTIFIER. So, cannot do length
             * check in "tlv_ops" as we don't know if reeived TLV corresponds to
             * TLV_VENDOR_LOCAL_CSPF or TLV_SR_CANDIDATE_PATH_IDENTIFIER.
             *
             * TLV "TLV_VENDOR_LOCAL_CSPF" is designed by us for Juniper-Juniper(NS/DV) use only,
             * where as TLV "TLV_SR_CANDIDATE_PATH_IDENTIFIER" is standardised TLV
             */
            if (TLV_VENDOR_LOCAL_CSPF_FIXED_LEN != sub_len) {
                log_error(pcep, "Invalid length for vendor CSPF tlv. Received len: %d",
                        sub_len);
                return -1;
            }
            obj->info[obj->size].type = PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF;
            obj->info[obj->size].u.pvi_local_cspf = data[suboffset];
            obj->size++;
            break;
        case TLV_VENDOR_LSP_ROUTE_PREFERENCE:
            if (TLV_VENDOR_ROUTE_PREFERENCE_FIXED_LEN != sub_len) {
                log_error(pcep, "Invalid length for vendor Route Preference tlv. Received len: %d",
                        sub_len);
                return -1;
            }
            obj->info[obj->size].type = PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE;
            obj->info[obj->size].u.route_preference = ntoh_uint32_t(&data[suboffset]);
            obj->size++;
            break;
        default:
            break;
        }

        /*  TLV header len = 4, tlv_len = sub_len*/
        read = read + 4 + sub_len + ((sub_len % PADDING) ? (PADDING - (sub_len % PADDING)) : 0);
        suboffset = read;
    }

    return read;
}

static int
parse_obj_path_attribute (struct pcep   *pcep UNUSED,
                          void          *ptr,
                          const uint8_t *data,
                          uint16_t       datalen UNUSED)
{
    struct     pcep_obj_path_attribute *obj = ptr;
    uint32_t   read = 0;

    /** First 4 bytes for Flags - specifically opstate */
    if ((ntoh_uint32_t(data + read)) & 0x8) {
        log_error(pcep, "Received unacceptable reverse path information in path attribute object. "
                  "Junos PCC sent PCE that it is not processing reverse paths and opposite direction path");
        return -1; 
    }
    obj->op_state = (ntoh_uint32_t(data + read)) & 0x07;
    read += 4;

    /** Next 4 bytes for path-id */
    obj->path_id = ntoh_uint32_t(data + read);
    read += 4;

    /* Default path_attribute weight value */
    obj->weight = 1;

    /*
     * Default path type is primary. Secondary paths sent
     * from controller is not supported
     */
    obj->secondary_path = false;

    return read;
}

/**
 * Append the path_attribute tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_path_attribute (struct pcep *pcep UNUSED,
                           void        *ptr UNUSED,
                           const struct pcep_tlv * const tlv)
{
    struct pcep_obj_path_attribute *obj = ptr;

    if (tlv->type == pathattribute_color_tlv_type) {
        log_error(pcep, " Current Junos version does not support "
                  "MULTIPATH_COLOR_TLV. Ignoring processing of the TLV");
        return false;
    }
    switch (tlv->type) {
        case TLV_MULTIPATH_WEIGHT:
            obj->weight = ntoh_uint32_t(tlv->data);
            return false;
        case TLV_MULTIPATH_BACKUP:
            log_error(pcep, " Current Junos version does not support "
                          "MULTIPATH_BACKUP_TLV. Ignoring processing of the TLV");
            return false;
        default:
            return false;
    }
}

/**
 * Parse a flowspec object
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return the object size
 */
static int
parse_obj_flowspec (struct pcep *pcep UNUSED, void *ptr, const uint8_t *data,
                    uint16_t datalen)
{
    struct pcep_obj_flowspec *obj = ptr;
    uint8_t flags = 0;
    uint32_t read = 0;

    /** First 4 bytes for FS-ID */
    obj->fs_id = ntoh_uint32_t(data + read);
    read += 4;

    /** Next 2 bytes for AFI */
    obj->AFI = ntoh_uint16_t(data + read);    
    read += 2;

    /** Next 1 byte is reserved */
    read += 1;

    /** Next 1 byte is for Flags: |------|L|R| */
    flags = data[read];
    read += 1;

    /** Read Remove bit */
    obj->remove = flags & 0x1;

    /** Longest Prefix Match bit */
    obj->lpm = (flags >> 1) & 0x1;

    /* if FS is removed then no need to read rest of object */
    if (obj->remove) {
        return datalen;
    }

    return read;
}

/**
 * Append the lsp tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_lsp (struct pcep *pcep UNUSED, void *ptr UNUSED,
                const struct pcep_tlv * const tlv)
{
    struct pcep_obj_lsp *obj = ptr;

    switch (tlv->type) {
    case TLV_LSP_SYMBOLIC_NAME:
        obj->symbolic_name_tlv = true;
        memcpy(obj->symbolic_name, tlv->data,
               (tlv->length < MAX_SYMB_NAME_SIZE) ? tlv->length : MAX_SYMB_NAME_SIZE);
        obj->symbolic_name[(tlv->length < MAX_SYMB_NAME_SIZE) ? tlv->length : MAX_SYMB_NAME_SIZE - 1] = '\0';
        return false;
    case TLV_TE_PATH_BINDING:
        log_error(pcep, "Path binding TLV is not supported in messages from PCE");
        return true;
    default:
        return false;
    }
}

 /**
  * Append the lspa tlv
  *
  * @param[in] pcep Library handle
  * @param[in] ptr Object pointer
  * @param[in] tlv TLV
  * @return true in case of error
  */
static bool
append_tlv_lspa (struct pcep *pcep UNUSED, void *ptr,
                 const struct pcep_tlv * const tlv)
{
    struct pcep_obj_lspa *obj = ptr;
    switch (tlv->type) {
        /* PCE Initiated Bypass : begin */
        /* TLV_LSP_SYMBOLIC_NAME is not part of LSPA object */
        case TLV_BYPASS:
        {
            obj->bypass_tlv = TRUE;
            obj->node_prot = tlv->data[3] & 0x01;
            obj->local_prot_in_use = tlv->data[3] & 0x02;            
            memcpy(&obj->bypadd_ipv4_addr, &tlv->data[4], 4);
            obj->subsc_mul = ntoh_float(&tlv->data[8]);
            return false;
        }
        /* PCE Initiated Bypass : end */    
        default:
            return false;
    }
}

/**
 * Append the nopath tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_nopath (struct pcep *pcep UNUSED, void *ptr UNUSED,
                   const struct pcep_tlv * const tlv)
{
    struct pcep_obj_nopath *obj = ptr;
    switch (tlv->type) {
    case TLV_NO_PATH_VECTOR:
        obj->pce_unavailable = tlv->data[0] & 0x01;
        obj->unknown_destination = tlv->data[0] & 0x02;
        obj->unknown_source = tlv->data[0] & 0x04;
        return false;
    default:
        return false;
    }
}

/**
 * Append the notification tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_notification (struct pcep *pcep UNUSED, void *ptr,
                         const struct pcep_tlv * const tlv)
{
    struct pcep_obj_notification *obj = ptr;
    switch (tlv->type) {
    case TLV_OVERLOADED_DURATION:
        obj->overloaded_duration = ntoh_uint32_t(tlv->data);
        return false;
    default:
        return false;
    }
}

/**
 * Append the open tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_open (struct pcep *pcep UNUSED, void *ptr,
                 const struct pcep_tlv * const tlv)
{
    struct pcep_obj_open *obj = ptr;
    switch (tlv->type) {
    case TLV_STATEFUL_PCE_CAPABILITY:
         
        obj->stateful = true;
        obj->p2mp_lsp_report_capability   = tlv->data[3] & 0x40; // Bit 25 in [0-31]
        obj->p2mp_lsp_update_capability   = tlv->data[3] & 0x80; // Bit 24 in [0-31]
        obj->p2mp_lsp_init_capability     = tlv->data[2] & 0x01; // Bit 23 in [0-31]
        obj->active   = tlv->data[3] & 0x01; // Update bit
        obj->lsp_provisioning   = tlv->data[3] & 0x04; //p2p instatiaction
        return false;
    case TLV_SR_PCE_CAPABILITY:
        /* If TLV_PATH_SETUP_TYPE_CAPABILITY is received ignore this tlv*/
        if (!obj->path_setup_type_capability) {
        obj->spring_capability = true;
        obj->msd = tlv->data[3];
        return false;
        }
    case TLV_PCE_FLOWSPEC_CAPABILITY:
        obj->pce_flowspec_capability = true;
        return false;
    case TLV_ASSOCIATION_TYPE_LIST:
    for (uint8_t read = 0; read < tlv->length; read += 2) {
        uint16_t data = ntoh_uint16_t(tlv->data + read);
        if (ASSOCIATION_TYPE_PATH_PROTECTION == data) {
            obj->path_protection_association = true;
        } else if (ASSOCIATION_TYPE_DISJOINT == data) {
            obj->disjoint_assoc_capability = true;
        } else if (ASSOCIATION_TYPE_SRPAG == data) {
            obj->srpag_association = true;
        }
    }
        return false;
    case TLV_PATH_SETUP_TYPE_CAPABILITY:
        obj->path_setup_type_capability = true;
        obj->spring_capability = false;
        uint16_t sub_tlv_type; 
        uint16_t sub_tlv_len;
        int tlv_bytes_read = 0;
        uint8_t n_pst = tlv->data[3];

        tlv_bytes_read = 4; //Reserved + n_pst

        /* Check for PSTs received */
        while (tlv_bytes_read < (4 + n_pst)) {

            if (srcap_pst_type == tlv->data[tlv_bytes_read]) {
                obj->is_sr_pst_present = true;
            } else if (srv6_pst_type == tlv->data[tlv_bytes_read]) {
                obj->is_srv6_pst_present = true;
            }

            tlv_bytes_read += 1;
        }

        uint8_t padlen = (n_pst%4) ? 4 - (n_pst%4):0;
        tlv_bytes_read += padlen;

        while (tlv_bytes_read < tlv->length) {
            if (tlv->length - tlv_bytes_read < TLV_HEADER_LEN) {
                log_error(pcep, "Incomplete object : malformed TLV");
                return true;
            }
            /** 2 bytes for Sub TLV Type */
            sub_tlv_type = ntoh_uint16_t(tlv->data + tlv_bytes_read);
            tlv_bytes_read += 2;

            /** 2 bytes for Sub Spec TLV Length */
            sub_tlv_len = ntoh_uint16_t(tlv->data + tlv_bytes_read);
            tlv_bytes_read += 2;

            if (tlv->length - tlv_bytes_read < sub_tlv_len) {
                log_error(pcep, "Incomplete object : malformed TLV");
                return true;
            }

            if (TLV_SR_PCE_CAPABILITY == sub_tlv_type) {
                if (obj->is_sr_pst_present) {
                    obj->spring_capability = true;
                    /** 1 bytes for MSD */
                    obj->msd = tlv->data[tlv_bytes_read + 3]; /*first 3 bytes reserved + flags */
                } else {
                    log_error(pcep, "Ignoring SR-PCE-CAPABILITY sub-TLV as SR PST is not received");
                }
                tlv_bytes_read += 4;
            } else if (srv6_pce_capability_sub_tlv_type == sub_tlv_type) {
                if (obj->is_srv6_pst_present) {
                    obj->srv6_capability = true;
                    /**
                     *    draft-ietf-pce-segment-routing-ipv6-09:
                     *    The N flag, X flag and (MSD-Type,MSD-Value) pair inside the SRv6-PCE-
                     *    CAPABILITY sub-TLV are meaningful only in the Open message sent from
                     *    a PCC to a PCE.  As such, a PCE MUST set the flags to zero and not
                     *    include any (MSD-Type,MSD-Value) pair in the SRv6-PCE-CAPABILITY sub-
                     *    TLV in an outbound message to a PCC.  Similarly, a PCC MUST ignore
                     *    N,X flag and any (MSD-Type,MSD-Value) pair received from a PCE.
                     **/
                } else {
                    log_error(pcep, "Ignoring SRv6-PCE-CAPABILITY sub-TLV as SRv6 PST"
                                            " is not received");
                }
                tlv_bytes_read += sub_tlv_len;
            } else {
                /* NOT SUPPORTED TLV, IGNORE*/
                tlv_bytes_read += sub_tlv_len;
            }

            padlen = (sub_tlv_len%4) ? 4 - (sub_tlv_len%4):0;
            tlv_bytes_read += padlen;
        }
        return false;
    case TLV_MULTIPATH_CAPABILITY:
        obj->multipath_capability = true;
        obj->max_segment_list = ntoh_uint16_t(tlv->data);
        return false;
    case TLV_VERSION_INFO:
        obj->major_version = sw_version.sw_major;
	    obj->minor_version = sw_version.sw_minor;
        return false;
    default:
        return false;
    }
}

/**
 * Append the rp tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_rp (struct pcep *pcep UNUSED, void *ptr,
               const struct pcep_tlv * const tlv)
{
    struct pcep_obj_rp *obj = ptr;
    obj->lsp_setup_type   = tlv->data[3];
    return false;
}

/**
 * Append the srp tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_srp (struct pcep *pcep UNUSED, void *ptr,
                const struct pcep_tlv * const tlv)
{
    struct pcep_obj_srp *obj = ptr;
    obj->lsp_setup_type   = tlv->data[3];
    return false;
}

/**
 * Append the error tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_error (struct pcep *pcep UNUSED, void *ptr UNUSED,
                  const struct pcep_tlv * const tlv)
{
    struct pcep_obj_error *obj = ptr;
    switch (tlv->type) {
        case TLV_REQ_MISSING:
            obj->missing_request_id = ntoh_uint32_t(tlv->data);
            return false;
        default:
            return false;
    }
}

/**
 * Append association optional TLVs
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool

append_tlv_association (struct pcep *pcep UNUSED, void *ptr,
                        const struct pcep_tlv * const tlv)
{
    struct pcep_obj_association *obj = ptr;
    uint32_t read = 0, disjoint_flags = 0;
    int16_t i = 0;

    if (TLV_PATH_PROTECTION_ASSOCIATION == tlv->type) {
        if (tlv->length != 4) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "path protection association TLV");
            return true;
        }
        obj->path_protection= true;
        obj->path_protection_tlv.protection_type = (tlv->data[0] >> 2) & 0x3F;
        obj->path_protection_tlv.unassigned_flags = 0;
        obj->path_protection_tlv.flag_secondary = ((tlv->data[3] >> 1) & 0x1);
        obj->path_protection_tlv.flag_protection = tlv->data[3] & 0x1;

    } else if(TLV_EXTENDED_ASSOCIATION_ID == tlv->type) {
        obj->extended_assoc_id = true;
        obj->extended_assoc_id_tlv.extended_assoc_id = 0;
        obj->extended_assoc_id_tlv.is_srpag_endpoint_ipv6 = false;

        /*
         * As per draft-ietf-pce-segment-routing-policy-cp-05,
         * Extended Association ID TLV encodes the Color and Endpoint of the
         * SR Policy in SRPAG association.
         *
         * If association type is not SRPAG, complete TLV is decoded as extended id
         * If association type is SRPAG, color and endpoint is decoded from TLV
         */
        if (obj->association_type != ASSOCIATION_TYPE_SRPAG) {
            uint8_t data[MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE];
            obj->extended_assoc_id_tlv.process_as_srpag_tlv = false;

            if (tlv->length > MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE) {
                log_error(pcep, "Incomplete tlv : "
                    "Extended association ID should not exceed 4 bytes");
                return true;
            }

            memset(data, 0, MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE);
            for (int16_t len = tlv->length - 1; len >= 0; len--) {
                data[MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE - (++i)] = tlv->data[len];
            }
            obj->extended_assoc_id_tlv.extended_assoc_id = ntoh_uint32_t(data);
        } else {
            if (tlv->length != TLV_EXTENDED_ASSOC_ID_IPV4_SRPAG_FIXED_LEN) {
                log_error(pcep, "Incomplete tlv : "
                    "Extended association ID for SRPAG is not 8 bytes. Received length is %d",
                    tlv->length);
                return true;
            }
            obj->extended_assoc_id_tlv.process_as_srpag_tlv = true;
            obj->extended_assoc_id_tlv.srpag_color = ntoh_uint32_t(tlv->data + read);
            read += 4;
            memcpy(&obj->extended_assoc_id_tlv.srpag_endpoint.v4, tlv->data + read, 4);
            read += 4;
        }
    } else if (TLV_SR_CANDIDATE_PATH_IDENTIFIER == tlv->type) {
        if (tlv->length != TLV_SR_CANDIDATE_PATH_IDENTIFIER_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "SR CANDIDATE PATH IDENTIFIER TLV");
            return true;
        }
        obj->sr_candidate_path_identifier = true;
        obj->sr_candidate_path_identifier_tlv.proto_origin_ = (pcep_sr_cpath_proto_origin_t)(tlv->data[0]);
        read += 4;
        obj->sr_candidate_path_identifier_tlv.originator_asn = ntoh_uint32_t(tlv->data + read);
        read += 4;
        read += 12; /* Skip higher 96 bits of originator ip */

        /**
         * Originator address is represented as 128 bit value, where IPv4 address
         * are encoded in lowest 32 bits
         */
        memcpy(&obj->sr_candidate_path_identifier_tlv.originator_address.v4, tlv->data + read, 4);
        read += 4;
        obj->sr_candidate_path_identifier_tlv.discriminator = ntoh_uint32_t(tlv->data + read);
        read += 4;
    } else if (TLV_SR_PREFERENCE == tlv->type) {
        if (tlv->length != TLV_SR_PREFERENCE_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "SR PREFERENCE TLV");
            return true;
        }
        obj->sr_preference = true;
        obj->sr_preference_tlv.preference = ntoh_uint32_t(tlv->data);
    } else if (TLV_DISJOINT_STATUS == tlv->type) {
        if (tlv->length != TLV_DISJOINT_STATUS_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "Disjoint Status TLV");
            return true;
        }
        disjoint_flags = ntoh_uint32_t(tlv->data);
        if (disjoint_flags & 0x1) {
            obj->disjoint_status_tlv.link_disjoint = true;
        } else {
            obj->disjoint_status_tlv.link_disjoint = false;
        }
        if (disjoint_flags & 0x2) {
            obj->disjoint_status_tlv.node_disjoint = true;
        } else {
            obj->disjoint_status_tlv.node_disjoint = false;
        }
        if (disjoint_flags & 0x4) {
            obj->disjoint_status_tlv.srlg_disjoint = true;
        } else {
            obj->disjoint_status_tlv.srlg_disjoint = false;
        }
        if (disjoint_flags & 0x8) {
            obj->disjoint_status_tlv.shortest_path_flag = true;
        } else {
            obj->disjoint_status_tlv.shortest_path_flag = false;
        }
        if (disjoint_flags & 0x10) {
            obj->disjoint_status_tlv.stictness_flag = true;
        } else {
            obj->disjoint_status_tlv.stictness_flag = false;
        }
        obj->disjoint_status = true;
    } else if (TLV_DISJOINT_CONFIGURATION == tlv->type) {
        if (tlv->length != TLV_DISJOINT_CONFIGURATION_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "Disjoint configuration TLV");
            return true;
        }
        disjoint_flags = ntoh_uint32_t(tlv->data);
        if (disjoint_flags & 0x1) {
            obj->disjoint_config_tlv.link_disjoint = true;
        } else {
            obj->disjoint_config_tlv.link_disjoint = false;
        }
        if (disjoint_flags & 0x2) {
            obj->disjoint_config_tlv.node_disjoint = true;
        } else {
            obj->disjoint_config_tlv.node_disjoint = false;
        }
        if (disjoint_flags & 0x4) {
            obj->disjoint_config_tlv.srlg_disjoint = true;
        } else {
            obj->disjoint_config_tlv.srlg_disjoint = false;
        }
        if (disjoint_flags & 0x8) {
            obj->disjoint_config_tlv.shortest_path_flag = true;
        } else {
            obj->disjoint_config_tlv.shortest_path_flag = false;
        }
        if (disjoint_flags & 0x10) {
            obj->disjoint_config_tlv.stictness_flag = true;
        } else {
            obj->disjoint_config_tlv.stictness_flag = false;
        }
        obj->disjoint_config = true;
    } else {
        log_error(pcep, "Unsupported TLV: %d", tlv->type);
    }
    return false;
}

/**
 * Append association optional TLVs
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_association_ipv6 (struct pcep *pcep UNUSED, void *ptr,
                          const struct pcep_tlv * const tlv)
{
    struct pcep_obj_association_ipv6 *obj = ptr;
    uint32_t read = 0, disjoint_flags = 0;

    if(TLV_EXTENDED_ASSOCIATION_ID == tlv->type) {
        uint8_t data[TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN];

        if (tlv->length != TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : "
                "Extended association ID for IPv6 SRPAG is not 20 bytes. Received size is %d",
                tlv->length);
            return true;
        }

        memset(data, 0, TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN);
        obj->extended_assoc_id = true;
        obj->extended_assoc_id_tlv.extended_assoc_id = 0;
        obj->extended_assoc_id_tlv.process_as_srpag_tlv = true;
        obj->extended_assoc_id_tlv.is_srpag_endpoint_ipv6 = true;


        obj->extended_assoc_id_tlv.srpag_color = ntoh_uint32_t(tlv->data + read);
        read += 4;
        memcpy(&obj->extended_assoc_id_tlv.srpag_endpoint.v6, tlv->data + read, 16);
        read += 16;
    } else if (TLV_SR_CANDIDATE_PATH_IDENTIFIER == tlv->type) {
        if (tlv->length != TLV_SR_CANDIDATE_PATH_IDENTIFIER_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                "SR CANDIDATE PATH IDENTIFIER TLV");
            return true;
        }
        obj->sr_candidate_path_identifier = true;
        obj->sr_candidate_path_identifier_tlv.proto_origin_ = (pcep_sr_cpath_proto_origin_t)(tlv->data[0]);
        read += 4;
        obj->sr_candidate_path_identifier_tlv.originator_asn = ntoh_uint32_t(tlv->data + read);
        read += 4;
        memcpy(&obj->sr_candidate_path_identifier_tlv.originator_address.v6, tlv->data + read, 16);
        read += 16;
        obj->sr_candidate_path_identifier_tlv.discriminator = ntoh_uint32_t(tlv->data + read);
        read += 4;
    } else if (TLV_SR_PREFERENCE == tlv->type) {
        if (tlv->length != TLV_SR_PREFERENCE_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                "SR PREFERENCE TLV");
            return true;
        }
        obj->sr_preference = true;
        obj->sr_preference_tlv.preference = ntoh_uint32_t(tlv->data);
    } else if (TLV_DISJOINT_STATUS == tlv->type) {
        if (tlv->length != TLV_DISJOINT_STATUS_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "Disjoint Status TLV");
            return true;
        }
        disjoint_flags = ntoh_uint32_t(tlv->data);
        if (disjoint_flags & 0x1) {
            obj->disjoint_status_tlv.link_disjoint = true;
        } else {
            obj->disjoint_status_tlv.link_disjoint = false;
        }
        if (disjoint_flags & 0x2) {
            obj->disjoint_status_tlv.node_disjoint = true;
        } else {
            obj->disjoint_status_tlv.node_disjoint = false;
        }
        if (disjoint_flags & 0x4) {
            obj->disjoint_status_tlv.srlg_disjoint = true;
        } else {
            obj->disjoint_status_tlv.srlg_disjoint = false;
        }
        if (disjoint_flags & 0x8) {
            obj->disjoint_status_tlv.shortest_path_flag = true;
        } else {
            obj->disjoint_status_tlv.shortest_path_flag = false;
        }
        if (disjoint_flags & 0x10) {
            obj->disjoint_status_tlv.stictness_flag = true;
        } else {
            obj->disjoint_status_tlv.stictness_flag = false;
        }
        obj->disjoint_status = true;
    } else if (TLV_DISJOINT_CONFIGURATION == tlv->type) {
        if (tlv->length != TLV_DISJOINT_CONFIGURATION_FIXED_LEN) {
            log_error(pcep, "Incomplete tlv : malformed "
                      "Disjoint configuration TLV");
            return true;
        }
        disjoint_flags = ntoh_uint32_t(tlv->data);
        if (disjoint_flags & 0x1) {
            obj->disjoint_config_tlv.link_disjoint = true;
        } else {
            obj->disjoint_config_tlv.link_disjoint = false;
        }
        if (disjoint_flags & 0x2) {
            obj->disjoint_config_tlv.node_disjoint = true;
        } else {
            obj->disjoint_config_tlv.node_disjoint = false;
        }
        if (disjoint_flags & 0x4) {
            obj->disjoint_config_tlv.srlg_disjoint = true;
        } else {
            obj->disjoint_config_tlv.srlg_disjoint = false;
        }
        if (disjoint_flags & 0x8) {
            obj->disjoint_config_tlv.shortest_path_flag = true;
        } else {
            obj->disjoint_config_tlv.shortest_path_flag = false;
        }
        if (disjoint_flags & 0x10) {
            obj->disjoint_config_tlv.stictness_flag = true;
        } else {
            obj->disjoint_config_tlv.stictness_flag = false;
        }
        obj->disjoint_config = true;
    } else {
        log_error(pcep, "Unsupported TLV: %d", tlv->type);
    }
    return false;
}

/**
 * Append the flowspec filter tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 */
static bool
append_tlv_flowspec (struct pcep *pcep UNUSED, void *ptr,
                     const struct pcep_tlv * const tlv)
{
    struct pcep_obj_flowspec *obj = ptr;
    uint16_t tlv_bytes_read = 0;
    int fs_tlv, fs_tlv_len;
    uint32_t read = 0;
    uint16_t tmp_uint16;
    uint32_t tmp_uint32;
    uint8_t  prefix_cnt = 0;

    switch (tlv->type) {
        case TLV_FLOWSPEC_FLOWFILTER:
            while (tlv_bytes_read < tlv->length) {
                if (tlv->length - tlv_bytes_read < TLV_HEADER_LEN) {
                    log_error(pcep, "Incomplete object : malformed TLV");
                    return true;    
                }

                /** 2 bytes for FlowSpec Spec TLV Type */
                fs_tlv = ntoh_uint16_t(tlv->data + read);
                read += 2;

                /** 2 bytes for FlowSpec Spec TLV Length */
                fs_tlv_len = ntoh_uint16_t(tlv->data + read);
                read += 2;

                tlv_bytes_read += TLV_HEADER_LEN;

                if (tlv->length - tlv_bytes_read < fs_tlv_len) {
                    log_error(pcep, "Incomplete object : malformed TLV");
                    return true;    
                }

                switch (fs_tlv) {
                    case TLV_FLOWSPEC_MULTICAST:
                        if (TLV_FLOWSPEC_MULTICAST_FIXED_LEN != fs_tlv_len) {
                            log_error(pcep, "Incomplete object : malformed Sub-TLV");
                            return true;
                        }

                        /** First 2 bytes for Multicast TLV */
                        /* TBD: need to check if there are two 1 byte flags or one 2 bytes flag*/
                        tmp_uint16 = ntoh_uint16_t(tlv->data + read);
                        obj->flow_filter.fs_mc.flags = tmp_uint16;
                        read += 2;

                        /** 1 bytes for Multicast TLV SRC Mask */
                        obj->flow_filter.fs_mc.src_len = tlv->data[read];
                        read += 1;

                        /** 1 bytes for Multicast TLV GRP Mask */
                        obj->flow_filter.fs_mc.mgp_len = tlv->data[read];
                        read += 1;

                        /**
                         * PCCD stores ip address in database in Network order format
                         * Further PCCD-RPD Communication also happens in Network order format
                         */
                        /** 4 bytes for Multicast TLV SRC Address */
                        memcpy(&obj->flow_filter.fs_mc.source_prefix, tlv->data + read, 4);
                        read += 4;

                        /** 4 bytes for Multicast TLV Group Address */
                        memcpy(&obj->flow_filter.fs_mc.multi_group_prefix, tlv->data + read, 4);
                        read += 4;

                        tlv_bytes_read += fs_tlv_len;
                        obj->flow_filter.filter_tlv_recv |= FS_SUBTLV_MC_RCV_BIT;
                        break;
                    case TLV_FLOWSPEC_ROUTE_DISTINGUISER:
                        if (TLV_FLOWSPEC_RD_FIXED_LEN != fs_tlv_len) {
                            log_error(pcep, "Incomplete object : malformed TLV");
                            return true;
                        }

                        /** 4 bytes for RD TLV upper part */
                        tmp_uint32 = ntoh_uint32_t(tlv->data + read);
                        obj->flow_filter.fs_rd.rd_upper = tmp_uint32;
                        read += 4;

                        /** 4 bytes for RD TLV lower part */
                        tmp_uint32 = ntoh_uint32_t(tlv->data + read);
                        obj->flow_filter.fs_rd.rd_lower = tmp_uint32;
                        read += 4;

                        tlv_bytes_read += fs_tlv_len;
                        obj->flow_filter.filter_tlv_recv |= FS_SUBTLV_RD_RCV_BIT;
                        break;
                    case TLV_FLOWSPEC_DEST_PREFIX:
                        if (obj->AFI != FS_AFI_IPV4) {
                            log_error(pcep, "AFI: %u is not supported yet", obj->AFI);
                            return true;
                        }

                        if (TLV_FLOWSPEC_DEST_PREFIX_V4_FIXED_LEN != fs_tlv_len) {
                            log_error(pcep, "Incomplete object : malformed Destination Prefix TLV");
                            return true;
                        }

                        if (prefix_cnt >= MAX_PREFIX_SUPPORTED_PER_FLOWSPEC) {
                            log_error(pcep, "Received more than maximum of %u prefix supported per Flowspec object",
                                      MAX_PREFIX_SUPPORTED_PER_FLOWSPEC);
                            return true;
                        }

                        obj->flow_filter.fs_dst_pfx[prefix_cnt].mask = tlv->data[read];
                        if (obj->flow_filter.fs_dst_pfx[prefix_cnt].mask > 32) {
                            log_error(pcep, "Invalid mask length for prefix in Flowspec object");
                            return true;
                        }
                        read += 1;

                        if (obj->AFI == FS_AFI_IPV4) {
                            tmp_uint32 = ntoh_uint32_t(tlv->data + read);
                            obj->flow_filter.fs_dst_pfx[prefix_cnt].prefix.v4.s_addr =
                                tmp_uint32;
                            read += 4;
                        }

                        prefix_cnt++;

                        read += 3; // Padding

                        tlv_bytes_read += fs_tlv_len;
                        obj->flow_filter.filter_tlv_recv |= FS_SUBTLV_DP_RCV_BIT;
                        break;
                    default:
                        /* NOT SUPPORTED TLV, DROP*/
                        tlv_bytes_read += fs_tlv_len;
                        read += fs_tlv_len;
                        log_error(pcep, "Unsupported TLV, dropped: %d", fs_tlv);
                        return true;
                }
            }

            if (obj->flow_filter.filter_tlv_recv & FS_SUBTLV_DP_RCV_BIT) {
                obj->flow_filter.fs_dst_pfx_cnt = prefix_cnt;
            }
            obj->fs_tlv_recv |= FS_TLV_FLOW_FILTER_RCV_BIT;
            return false;
        case TLV_NODE_IDENTIFIER:
            {
                if (tlv->length == 0) {
                    log_error(pcep, "Incomplete object : malformed Speaker ID TLV");
                    return true;
                }

                if (tlv->length > MAX_SPEAKER_ID_LEN) {
                    log_error(pcep, "Speaker Id is too long, trimming it to 64 bytes");
                }

                snprintf(obj->speaker_id, sizeof(obj->speaker_id), "%s",
                         tlv->data + read);

                obj->fs_tlv_recv |= FS_TLV_SPEAKER_ID_RCV_BIT;
            }
            return false;
        default:
            log_error(pcep, "Unsupported TLV, dropped: %d", tlv->type);
            return true;
    }

    return false;
}


/**
 * Append the error tlv
 *
 * @param[in] pcep Library handle
 * @param[in] ptr Object pointer
 * @param[in] tlv TLV
 * @return true in case of error
 *
 * This function is not called as vendor TLVs are processed within vendor object itself
 */
static bool
append_tlv_vendor (struct pcep *pcep UNUSED, void *ptr UNUSED,
                   const struct pcep_tlv * const tlv)
{
    struct pcep_obj_vendor *obj = ptr;
    switch (tlv->type) {
        case TLV_VENDOR_LSP_QUALIFIER:
            obj->info[obj->size].type = PCEP_VENDOR_INFO_TYPE_LSP;
            obj->info[obj->size].enterprise =ntoh_uint32_t(tlv->data); ;
            obj->info[obj->size].u.lsp_type = ntoh_uint32_t(tlv->data+4);
            obj->size++;
            return false;
        case TLV_VENDOR_LSP_BW:
            obj->info[obj->size].type = PCEP_VENDOR_INFO_TYPE_BW;
            obj->info[obj->size].enterprise =ntoh_uint32_t(tlv->data); ;
            obj->info[obj->size].u.bps = ntoh_float(tlv->data+4);
            obj->size++;
            return false;
        default:
            return false;
    }
}

struct obj_ops {
    /**
     * Body parsing function
     */
    int        (*body)(struct pcep *pcep, void *ptr, const uint8_t *data,
                       uint16_t datalen);
    /**
     * Required object length, if non-zero
     */
    uint16_t   fixlen;
    /**
     * Minimum object length, not including common header
     */
    uint16_t   minlen;
    /**
     * TLV handling function
     */
    bool       (*tlv)(struct pcep *pcep, void *ptr,
                      const struct pcep_tlv * const tlv);
    /**
     * Symbolic object name
     */
    const char *name;
};

static const struct obj_ops object_ops[] = {
    [PCEP_OBJ_BANDWIDTH_REOPTIM] = {
        .name   = "Requested BANDWIDTH",
        .fixlen = 4,
        .body   = parse_obj_bandwidth,
    },
    [PCEP_OBJ_BANDWIDTH_REQUEST] = {
        .name   = "Existing LSP BANDWIDTH",
        .fixlen = 4,
        .body   = parse_obj_bandwidth,
    },
    [PCEP_OBJ_CLOSE] = {
        .name   = "CLOSE",
        .minlen = 4,
        .body   = parse_obj_close,
    },
    [PCEP_OBJ_ENDPOINTS_IPV4] = {
        .name   = "IPv4 END-POINTS",
        .fixlen = 8,
        .body   = parse_obj_endpoints_ipv4,
    },
    [PCEP_OBJ_ENDPOINTS_IPV6] = {
        .name   = "IPv6 END-POINTS",
        .fixlen = 32,
        .body   = parse_obj_endpoints_ipv6,
    },
    [PCEP_OBJ_P2MP_ENDPOINTS_IPV4] = {
        .name   = "IPv4 P2MP END-POINTS",            
        .minlen = 12,
        .body   = parse_obj_p2mp_endpoints_ipv4,
    },
    [PCEP_OBJ_ERO] = {
        .name   = "ERO",
        .body   = parse_obj_ero,
    },
    [PCEP_OBJ_IRO] = {
        .name   = "IRO",
        .minlen = 8,
        .body   = parse_obj_ero, // parsed like an ero
    },
    [PCEP_OBJ_LOADBALANCING] = {
        .name   = "LOAD-BALANCING",
        .fixlen = 8,
        .body   = parse_obj_loadbalancing,
    },
    [PCEP_OBJ_LSP] = {
        .name   = "LSP",
        .minlen = 4,
        .body   = parse_obj_lsp,
        .tlv    = append_tlv_lsp,
    },
    [PCEP_OBJ_LSPA] = {
        .name   = "LSPA",
        .minlen = 16,
        .body   = parse_obj_lspa,
        .tlv    = append_tlv_lspa,
    },
    [PCEP_OBJ_METRIC] = {
        .name   = "METRIC",
        .fixlen = 8,
        .body   = parse_obj_metric,
    },
    [PCEP_OBJ_NOPATH] = {
        .name   = "NO-PATH",
        .minlen = 4,
        .body   = parse_obj_nopath,
        .tlv    = append_tlv_nopath,
    },
    [PCEP_OBJ_NOTIFICATION] = {
        .name   = "NOTIFICATION",
        .minlen = 4,
        .body   = parse_obj_notification,
        .tlv    = append_tlv_notification,
    },
    [PCEP_OBJ_OPEN] = {
        .name   = "OPEN",
        .minlen = 4,
        .body   = parse_obj_open,
        .tlv    = append_tlv_open,
    },
    [PCEP_OBJ_PCEPERROR] = {
        .name   = "PCEP-ERROR",
        .minlen = 4,
        .body   = parse_obj_error,
        .tlv    = append_tlv_error,
    },
    [PCEP_OBJ_RP] = {
        .name   = "RP",
        .minlen = 8,
        .body   = parse_obj_rp,
        .tlv    = append_tlv_rp,
    },
    [PCEP_OBJ_RRO] = {
        .name   = "RRO",
        .minlen = 12,
        .body   = parse_obj_rro,
    },
    [PCEP_OBJ_SVEC] = {
        .name   = "SVEC",
        .minlen = 8,
        .body   = parse_obj_svec,
    },
    [PCEP_OBJ_LABEL] = {
        .name   = "LABEL",
        .fixlen = 8,
        .body   = parse_obj_label,
    },
	[PCEP_OBJ_SRP] = {
		.name  = "SRP",
		.minlen = 8,
		.body = parse_obj_srp,
        .tlv  = append_tlv_srp,
	},	
    [PCEP_OBJ_ASSOCIATION_nonRFC] = {
        .name   = "ASSOCIATION",
        .fixlen = 8,
        .body   = parse_obj_association_non_rfc,
    },
    [PCEP_OBJ_ASSOCIATION_nonIANA] = {
        .name   = "ASSOCIATION",
        .fixlen = 8,
        .body   = parse_obj_association_non_rfc,
    },
    [PCEP_OBJ_ASSOCIATION] = {
        .name   = "ASSOCIATION",
        .minlen = 12,
        .body   = parse_obj_association,
        .tlv    = append_tlv_association,
    },
    [PCEP_OBJ_ASSOCIATION_IPV6] = {
        .name   = "ASSOCIATION-IPV6",
        .minlen = 24,
        .body   = parse_obj_association_ipv6,
        .tlv    = append_tlv_association_ipv6,
    },
    [PCEP_OBJ_FLOWSPEC] = {
        .name   = "FLOWSPEC",
        .minlen = 8,
        .body   = parse_obj_flowspec,
        .tlv    = append_tlv_flowspec,  
    },
    [PCEP_OBJ_VENDOR] = {
        .name   = "VENDOR",
        .minlen = 8,
        .body   = parse_obj_vendor,
        .tlv    = append_tlv_vendor,
    },
    [PCEP_OBJ_PATH_ATTRIBUTE] = {
        .name   = "PATH-ATTRIBUTE",
        .minlen = 8,
        .body   = parse_obj_path_attribute,
        .tlv    = append_tlv_path_attribute,
    },
};

/**
 * Retrieve the object length from the object header
 *
 * @param[in] data Object header
 * @return the object length
 */
uint16_t
pcep_obj_length (const uint8_t data[OBJ_HEADER_LEN])
{
    return ntoh_uint16_t(data + 2);
}

static void
pcep_obj_trace_ero(struct pcep_conn *conn, bool out,
                   const struct pcep_obj_ero *o)
{
    unsigned trc_flag_tlv = out ? PCEP_TRC_OUT_TLVS : PCEP_TRC_IN_TLVS;
    struct pcep *pcep = get_pcep(conn);
    unsigned i = 0;
    for (; i < o->subcount; i++) {
        const struct pcep_obj_ero_sub *sub = &o->subs[i];

        if (sub->type == srv6_ero_subobject_type) {
            char addr[INET6_ADDRSTRLEN] = "";
            inet_ntop(AF_INET6, &sub->data.srv6_ero.sid, addr,
                      sizeof(addr));

            trace(conn, trc_flag_tlv, "SRV6 ERO SUB-OBJECT: loose: %d, "
                    "nai_type: %d, sid: %s, endpoint behavior: %d, Flags:v: %d, t: %d, f: %d, s: %d, ",
                    sub->loose, sub->data.srv6_ero.nai_type,
                    addr, sub->data.srv6_ero.endpoint_behavior ,sub->data.srv6_ero.V_bit,
                    sub->data.srv6_ero.T_bit, sub->data.srv6_ero.F_bit,
                    sub->data.srv6_ero.S_bit);

            if (sub->data.srv6_ero.T_bit) {
                trace(conn, trc_flag_tlv, "SRV6 ERO SUB-OBJECT sid structure: Lb length: %d, "
                        "Ln length: %d, Fun Length: %d, Arg Length: %d",
                        sub->data.srv6_ero.sid_structure.lb_length,
                        sub->data.srv6_ero.sid_structure.ln_length,
                        sub->data.srv6_ero.sid_structure.fun_length,
                        sub->data.srv6_ero.sid_structure.arg_length);
            }
        } else {
            switch (sub->type) {
            case PCEP_ERO_SUB_IPV4:
                trace(conn, trc_flag_tlv, "IPV4 PREFIX SUB-OBJECT: loose: %d, "
                      "address: %s, prefix: %u", sub->loose,
                      inet_ntoa(sub->data.ipv4_prefix.address),
                      sub->data.ipv4_prefix.prefix_length);
                break;
            case PCEP_ERO_SUB_IPV6: {
                char addr[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, &sub->data.ipv6_prefix.address, addr,
                          sizeof(addr));
                trace(conn, trc_flag_tlv, "IPV6 PREFIX SUB-OBJECT: loose: %d, "
                      "address: %s, prefix: %u", sub->loose, addr,
                      sub->data.ipv6_prefix.prefix_length);
                break;
            }
            case PCEP_ERO_SUB_LABEL:
                trace(conn, trc_flag_tlv, "LABEL SUB-OBJECT: loose: %d, "
                      "upstream: %d, ctype: %u, label: %"PRIu32,
                      sub->loose, sub->data.label.upstream,
                      sub->data.label.ctype, sub->data.label.label);
                break;
            case PCEP_ERO_SUB_UNNUMBERED_IID: {
                struct in_addr addr;
                memcpy(&addr, &sub->data.unnumbered_iid.router_id, sizeof(addr));

                trace(conn, trc_flag_tlv, "UNNUMBERED IID SUB-OBJECT: "
                      "loose: %d, router_id: %s, interface_id: %"PRIu32,
                      sub->loose, inet_ntoa(addr), sub->data.unnumbered_iid.interface_id);
                break;
            }
            case PCEP_ERO_SUB_AUTONOMOUS:
                trace(conn, trc_flag_tlv, "AUTONOMOUS SUB-OBJECT: loose: %d, "
                      "system number: %u", sub->loose,
                      sub->data.autonomous.system_number);
                break;
            case PCEP_ERO_SUB_SR:
                trace(conn, trc_flag_tlv, "SPRING SUB-OBJECT: loose: %d, "
                        "nai_type: %d, sid: %" PRIu32, sub->loose, sub->data.sr_ero.nai_type,
                        sub->data.sr_ero.sid);
                break;
            default:
                log_error(pcep, "Invalid subobject: %d", sub->type);
            }
        }
    }
}

static void
pcep_obj_trace_rro(struct pcep_conn *conn, bool out,
                   const struct pcep_obj_rro *o)
{
    unsigned trc_flag_tlv = out ? PCEP_TRC_OUT_TLVS : PCEP_TRC_IN_TLVS;
    unsigned i = 0;
    for (; i < o->subcount; i++) {
        const struct pcep_obj_rro_sub *sub = &o->subs[i];
        if (sub->type == srv6_rro_subobject_type) {
            char addr[INET6_ADDRSTRLEN] = "";
            inet_ntop(AF_INET6, &sub->data.srv6_rro.sid, addr,
                      sizeof(addr));

            trace(conn, trc_flag_tlv, "SRV6 RRO SUB-OBJECT: loose: %d, "
                    "nai_type: %d, sid: %s, endpoint behavior: %d, Flags:v: %d, t: %d, f: %d, s: %d, ",
                    sub->loose, sub->data.srv6_rro.nai_type,
                    addr, sub->data.srv6_rro.endpoint_behavior ,sub->data.srv6_rro.V_bit,
                    sub->data.srv6_rro.T_bit, sub->data.srv6_rro.F_bit,
                    sub->data.srv6_rro.S_bit);

            if (sub->data.srv6_rro.T_bit) {
                trace(conn, trc_flag_tlv, "SRV6 RRO SUB-OBJECT sid structure: Lb length: %d, "
                        "Ln length: %d, Fun Length: %d, Arg Length: %d",
                        sub->data.srv6_rro.sid_structure.lb_length,
                        sub->data.srv6_rro.sid_structure.ln_length,
                        sub->data.srv6_rro.sid_structure.fun_length,
                        sub->data.srv6_rro.sid_structure.arg_length);
            }

        } else {
            switch (sub->type) {
            case PCEP_RRO_SUB_IPV4:
                trace(conn, trc_flag_tlv, "IPV4 SUB-OBJECT: loose: %d, "
                        "address: %s, local protection available: %d, local "
                        "protection in use: %d", sub->loose,
                        inet_ntoa(sub->data.ipv4_address.address),
                        sub->data.ipv4_address.lprot_available,
                        sub->data.ipv4_address.lprot_inuse);
                break;
            case PCEP_RRO_SUB_IPV6: {
                char addr[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, &sub->data.ipv6_address.address, addr,
                        sizeof(addr));
                trace(conn, trc_flag_tlv, "IPV6 SUB-OBJECT: loose: %d, "
                        "address: %s, local protection available: %d, local "
                        "protection in use: %d", sub->loose,
                        addr, sub->data.ipv6_address.lprot_available,
                        sub->data.ipv6_address.lprot_inuse);
                break;
            }
            case PCEP_RRO_SUB_LABEL:
                trace(conn, trc_flag_tlv, "LABEL SUB-OBJECT: loose: %d, "
                        "upstream: %d, ctype: %u, label: %"PRIu32", global_label: %d",
                        sub->loose, sub->data.label.upstream,
                        sub->data.label.ctype, sub->data.label.label,
                        sub->data.label.global_label);
                break;
            case PCEP_RRO_SUB_UNNUMBERED_IID: {
                struct in_addr addr;
                memcpy(&addr, &sub->data.unnumbered_iid.router_id, sizeof(addr));

                trace(conn, trc_flag_tlv, "UNNUMBERED IID SUB-OBJECT: "
                        "loose: %d, router_id: %s, interface_id: %"PRIu32,
                        sub->loose, inet_ntoa(addr), sub->data.unnumbered_iid.interface_id);
                break;
            }
            case PCEP_RRO_SUB_SR:
                trace(conn, trc_flag_tlv, "SPRING SUB-OBJECT: loose: %d, "
                        "nai_type: %d, sid: %" PRIu32, sub->loose, sub->data.sr_rro.nai_type,
                        sub->data.sr_rro.sid);
                break;
            default:
                trace(conn, trc_flag_tlv, "Invalid subobject type: %d", sub->type);
                break;
            }
        }
    }
}

/**
 * Trace the P2mp-endpoint-ipv4 addresses
 */
static void
pcep_obj_trace_p2mp_endpoint_ipv4(struct pcep_conn *conn, bool out,
                   const struct pcep_obj_p2mp_endpoints_ipv4 *o)
{
    char buf[500];
    unsigned i = 0;
    unsigned trc_flag = out ? PCEP_TRC_OUT_OBJS : PCEP_TRC_IN_OBJS;
    char srcstr[INET_ADDRSTRLEN];
    strlcpy(srcstr, inet_ntoa(o->source), sizeof(srcstr));
    snprintf(buf, sizeof(buf), "P2MP Endpoint type %d, "
          "src addr: %s P2MP endpoint dest addr:", o->leaftype, srcstr);

    for (; i < o->subcount; i++) {
        char dststr[INET_ADDRSTRLEN];
        strlcpy(dststr, inet_ntoa(o->destinations[i]), sizeof(dststr));
        snprintf(buf+strlen(buf), (sizeof(buf) - strlen(buf)) , " %s", dststr );
    }
    trace(conn, trc_flag," %s", buf);

}

/**
 * Traces information from (c) obj
 * @param conn[in] pcep connection pointer from pcep_connect
 * @param out[in] true parsing outgoing traffic, false if incoming
 * @param obj[in] initialised pcep object
 */
static void
pcep_obj_trace(struct pcep_conn *conn, bool out, const struct pcep_object *obj)
{
    const int trc_flag = out ? PCEP_TRC_OUT_OBJS : PCEP_TRC_IN_OBJS;
    const int trc_flag_tlv = out ? PCEP_TRC_OUT_TLVS : PCEP_TRC_IN_TLVS;
    switch(obj->type) {
    case PCEP_OBJ_OPEN: {
        const struct pcep_obj_open *o = &obj->u.open;
        trace(conn, trc_flag, "Open object: version: %d, deadtimer: %u, "
              "keepalive: %u, session ID: %u", o->version, o->deadtimer,
              o->keepalive, o->session_id);
        if (out && o->stateful) {
            /* The stateful bool is set when the object is being sent out. On
             * incomming messages, the stateful TLV has not been parsed yet,
             * therefore stateful bool is not initialized yet. */
	    // Include-DB-version flag is hard-coded to zero, not supported */
            trace(conn, trc_flag_tlv, "TLV Stateful PCE Capability: Update "
                  "Capability %d, Include DB version: %d, LSP Instantiation: %d",
                  o->active, 0, o->lsp_provisioning);
            if (o->p2mp_lsp_report_capability) {
                trace(conn, trc_flag_tlv, "TLV LSP p2mp report: %d",
                      o->p2mp_lsp_report_capability);
            }
            if (o->p2mp_lsp_update_capability) {
                trace(conn, trc_flag_tlv, "TLV LSP p2mp update: %d",
                      o->p2mp_lsp_update_capability);
            }
            if (o->p2mp_lsp_init_capability) {
                trace(conn, trc_flag_tlv, "TLV LSP p2mp init: %d",
                      o->p2mp_lsp_init_capability);
            }
            if (o->spring_capability) {
                trace(conn, trc_flag_tlv, "TLV Maximum SID depth: %d",
                      o->msd);
            }
            if (o->srv6_capability) {
                trace(conn, trc_flag_tlv, "SRv6 Capability present");
            }
            if (o->path_setup_type_capability) {
                trace(conn, trc_flag_tlv, "TLV Maximum SID depth: %d",
                      o->msd);
            }
            if (o->pce_flowspec_capability) {
                trace(conn, trc_flag_tlv, "TLV PCE FlowSpec Capability,"
                        "PCE is FlowSpec capable");
            }
            if (o->path_protection_association) {
                trace(conn, trc_flag_tlv, "TLV Association type list,"
                        "association type is path protection association");
            }
            if (o->srpag_association) {
                trace(conn, trc_flag_tlv, "TLV Association type list,"
                        "association type is srpag association");
            }
            if (o->multipath_capability) {
                trace(conn, trc_flag_tlv, "TLV Multipath Capability,"
                        " PCE is multipath capable");
            }
            if (o->disjoint_assoc_capability) {
                trace(conn, trc_flag_tlv, "TLV Association type list,"
                        "association type is Disjoint association");
            }
        }
        break;
    }
    case PCEP_OBJ_RP: {
        const struct pcep_obj_rp *o = &obj->u.rp;
        trace(conn, trc_flag, "RP object: bidirectional: %d, "
                "loose: %d, priority: %d, reoptimization: %d, "
                "lsp_setup_type: %d, request ID: %" PRIu32, 
                o->bidirectional, o->loose, o->priority,
                o->reoptimization, o->lsp_setup_type, o->request_id);
        break;
    }
    case PCEP_OBJ_NOPATH: {
        const struct pcep_obj_nopath *o = &obj->u.nopath;
        trace(conn, trc_flag, "NOPATH object: issue: %u, constraints: %d",
              o->issue, o->constraints);
        break;
    }
    case PCEP_OBJ_ENDPOINTS_IPV4: {
        const struct pcep_obj_endpoints_ipv4 *o = &obj->u.endpoints_ipv4;
        char srcstr[INET_ADDRSTRLEN];
        char dststr[INET_ADDRSTRLEN];
        strlcpy(srcstr, inet_ntoa(o->source), sizeof(srcstr));
        strlcpy(dststr, inet_ntoa(o->destination), sizeof(dststr));
        trace(conn, trc_flag, "END-POINTS IPv4 object: source: %s"
                ", destination: %s", srcstr, dststr);
        break;
    }
    case PCEP_OBJ_ENDPOINTS_IPV6: {
        const struct pcep_obj_endpoints_ipv6 *o = &obj->u.endpoints_ipv6;
        char srcstr[INET6_ADDRSTRLEN] = "";
        char dststr[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &o->source, srcstr, sizeof(srcstr));
        inet_ntop(AF_INET6, &o->destination, dststr, sizeof(dststr));
        trace(conn, trc_flag, "END-POINTS IPv6 object: source: %s"
                ", destination: %s", srcstr, dststr);
        break;
    }
    case PCEP_OBJ_P2MP_ENDPOINTS_IPV4: {
        const struct pcep_obj_p2mp_endpoints_ipv4 *o = &obj->u.p2mp_endpoints_ipv4;
        pcep_obj_trace_p2mp_endpoint_ipv4(conn, trc_flag, o);
        break;
    }
    case PCEP_OBJ_BANDWIDTH_REQUEST: {
        const struct pcep_obj_bandwidth *o = &obj->u.bandwidth;
        trace(conn, trc_flag, "BANDWIDTH REQUEST object: bytes per"
                " second: %f", o->bps);
        break;
    }
    case PCEP_OBJ_BANDWIDTH_REOPTIM: {
        const struct pcep_obj_bandwidth *o = &obj->u.bandwidth;
        trace(conn, trc_flag, "BANDWIDTH REOPTIMIZATION object: "
                "bytes per second: %f", o->bps);
        break;
    }
    case PCEP_OBJ_METRIC: {
        const struct pcep_obj_metric *o = &obj->u.metric;
        trace(conn, trc_flag, "METRIC object: value: %f, type: %u"
                ", computed: %d, bound: %d", o->value, o->type, o->computed,
                o->bound);
        break;
    }
    case PCEP_OBJ_PATH_ATTRIBUTE: {
        const struct pcep_obj_path_attribute *o = &obj->u.path_attr;
        trace(conn, trc_flag, " PATH-ATTRIBUTE object: path_id: %u"
              ", weight: %u, op_state: %u Secondary_path: %u", o->path_id, o->weight,
              o->op_state, o->secondary_path);
        break;
    }
    case PCEP_OBJ_ERO: {
        const struct pcep_obj_ero *o = &obj->u.ero;
        trace(conn, trc_flag, "ERO object: subobjects: %u",
              o->subcount);
        pcep_obj_trace_ero(conn, trc_flag_tlv, o);
        break;
    }
    case PCEP_OBJ_RRO: {
        const struct pcep_obj_rro *o = &obj->u.rro;
        trace(conn, trc_flag, "RRO object: subobjects: %u",
              o->subcount);
        pcep_obj_trace_rro(conn, trc_flag_tlv, o);
        break;
    }
    case PCEP_OBJ_LSP: {
        const struct pcep_obj_lsp *o = &obj->u.lsp;
        trace(conn, trc_flag, "LSP object: plsp ID: %"PRIu32", "
              "remove: %d, operational: %d, last_update: %d, delegated: %d"
              " administrative: %d is_p2mp %d, PCE Created: %d, Fragmented: %d, "
              "propagate max_segmentlist %u max_segment_list %d",
              o->plsp_id, o->remove, o->operational, o->last_update,
              o->delegated, o->administrative, o->p2mp_branch, o->pce_created, o->fragment,
              o->propagate_max_segment_list, o->max_segment_list);
        if (out && o->symbolic_name[0] != '\0') {
            trace(conn, trc_flag_tlv, "TLV LSP Symbolic name '%s'",
                  o->symbolic_name);
        }
        if (out && o->errspec_len != 0) {
	    // LSP-UPDATE-ERROR-CODE will be sent as well when ERRSPEC present
	    // in this cas it will be LSP_SETUP_FAILED_OUTSIDE_NODE
	    trace(conn, trc_flag_tlv, "TLV LSP Update Error Code: %d",
                  LSP_ERR_CODE_RSVP_SIGNAL_ERROR);
            // IPv4 RSVP ERROR-SPEC
            if (o->errspec_len == TLV_IPV4_RSVP_ERROR_SPEC_FIXED_LEN) {
                char ip_addr[INET_ADDRSTRLEN] = "";
                const uint8_t *ohdr = NULL;
                const uint8_t *data = NULL;

                if (!inet_ntop(AF_INET, o->errspec + OBJ_HEADER_LEN, ip_addr,
                               INET_ADDRSTRLEN)) {
                    strlcpy(ip_addr, "<unknown>", sizeof(ip_addr));
                }
                ohdr = o->errspec;
                data = o->errspec + OBJ_HEADER_LEN + 4;
                trace(conn, trc_flag_tlv,
                      "TLV IPv4 RSVP Error Spec: "
                      "Length: %d, Class: %d, C-Type: %d, Node: %s, "
                      "In Place: %d, Not Guilty: %d, "
                      "Error Code: %u, Error Value: %u",
                      ntoh_uint16_t(ohdr), ohdr[1], ohdr[2], ip_addr,
                      (*data & 0x01) ? 1 : 0, (*data & 0x02) ? 1 : 0, 
                      data[1], ntoh_uint16_t(&data[2]));
            }
            // IPv6 RSVP ERROR-SPEC
            if (o->errspec_len == TLV_IPV6_RSVP_ERROR_SPEC_FIXED_LEN) {
                char ip_addr[INET6_ADDRSTRLEN] = "";
                const uint8_t *ohdr = NULL;
                const uint8_t *data = NULL;

                if (!inet_ntop(AF_INET6, o->errspec + OBJ_HEADER_LEN, ip_addr,
                               INET_ADDRSTRLEN)) {
                    strlcpy(ip_addr, "<unknown>", sizeof(ip_addr));
                }
                ohdr = o->errspec;
                data = o->errspec + OBJ_HEADER_LEN + 16;
                trace(conn, trc_flag_tlv,
                      "TLV IPv4 RSVP Error Spec: "
                      "Length: %d, Class: %d, C-Type: %d, Node: %s, "
                      "In Place: %d, Not Guilty: %d, "
                      "Error Code: %u, Error Value: %u",
                      ntoh_uint16_t(ohdr), ohdr[1], ohdr[2], ip_addr,
                      (*data & 0x01) ? 1 : 0, (*data & 0x02) ? 1 : 0, 
                      data[1], ntoh_uint16_t(&data[2]));
            }
        }
        if (o->lsp_identifiers_len) {
            if (TLV_IPV4_LSP_IDENTIFIERS_FIXED_LEN == o->lsp_identifiers_len) {
                char sender_ip_addr[INET_ADDRSTRLEN]="";
                char extended_ip_addr[INET_ADDRSTRLEN]="";
                char endpoint_ip_addr[INET_ADDRSTRLEN]="";
                if (!inet_ntop(AF_INET, o->lsp_identifiers, sender_ip_addr,
                               INET_ADDRSTRLEN)) {
                    strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
                }
                if (!inet_ntop(AF_INET, o->lsp_identifiers + 8, extended_ip_addr,
                               INET_ADDRSTRLEN)) {
                    strlcpy(extended_ip_addr, "<unknown>", sizeof(extended_ip_addr));
                }
                if (!inet_ntop(AF_INET, o->lsp_identifiers + 12, endpoint_ip_addr,
                               INET_ADDRSTRLEN)) {
                    strlcpy(endpoint_ip_addr, "<unknown>", sizeof(endpoint_ip_addr));
                }
                trace(conn, trc_flag_tlv, "TLV IPV4-LSP-ID: sender:%s, "
                      "lsp id:%d, tunnel id:%d, extended:%s, endpoint:%s",
                      sender_ip_addr,
                      ntoh_uint16_t(&(o->lsp_identifiers[4])),
                      ntoh_uint16_t(&(o->lsp_identifiers[6])),
                      extended_ip_addr, endpoint_ip_addr);
            } else if (TLV_IPV6_LSP_IDENTIFIERS_FIXED_LEN == o->lsp_identifiers_len) {
                char sender_ip_addr[INET6_ADDRSTRLEN] = "";
                char extended_ip_addr[INET6_ADDRSTRLEN] = "";
                char endpoint_ip_addr[INET6_ADDRSTRLEN] = "";

                if (!inet_ntop(AF_INET6, o->lsp_identifiers, sender_ip_addr,
                               INET6_ADDRSTRLEN)) {
                    strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
                }
                if (!inet_ntop(AF_INET6, o->lsp_identifiers + 20, extended_ip_addr,
                               INET6_ADDRSTRLEN)) {
                    strlcpy(extended_ip_addr, "<unknown>", sizeof(extended_ip_addr));
                }
                if (!inet_ntop(AF_INET6, o->lsp_identifiers + 36, endpoint_ip_addr,
                               INET6_ADDRSTRLEN)) {
                    strlcpy(endpoint_ip_addr, "<unknown>", sizeof(endpoint_ip_addr));
                }
                trace(conn, trc_flag_tlv, "TLV IPV6-LSP-ID: sender:%s, "
                      "lsp id:%d, tunnel id:%d, extended:%s, endpoint:%s",
                      sender_ip_addr,
                      ntoh_uint16_t(&(o->lsp_identifiers[16])),
                      ntoh_uint16_t(&(o->lsp_identifiers[18])),
                      extended_ip_addr, endpoint_ip_addr);
              }
        }

        for (int count = 0; count < MAX_PATH_BINDING_TLVS; count++) {
            if (o->path_binding[count].mpls_label_binding_value) {
                if ((0 != o->path_binding[count].binding_type) && (1 != o->path_binding[count].binding_type)) {
                    trace(conn, trc_flag_tlv, "TLV TE-BINDING-VALUE: "
                          "unsupported binding type: %u",o->path_binding[count].binding_type);
                    break;
                }

                trace(conn, trc_flag_tlv, "TLV TE-BINDING-VALUE: "
                      "binding type: %u, binding value: %u, flag r: %u",o->path_binding[count].binding_type,
                      o->path_binding[count].binding_type ? o->path_binding[count].mpls_label_binding_value :
                      (o->path_binding[count].mpls_label_binding_value >> 12), o->path_binding[count].flag_r);
            }
        }

        break;
    }
    case PCEP_OBJ_LSPA: {
        const struct pcep_obj_lspa *o = &obj->u.lspa;
        trace(conn, trc_flag, "LSPA object: exclude any: %"PRIu32
              ", include any: %"PRIu32", include all: %"PRIu32", setup priority"
              ": %u, holddown priority: %u, local protection: %d",
              o->pol_exclude_any, o->pol_include_any, o->pol_include_all,
	      o->setup_prio, o->hold_prio, o->local_prot);
        if (out && o->symbolic_name[0] != '\0') {
            trace(conn, trc_flag_tlv, "TLV LSPA Symbolic name '%s'",
                  o->symbolic_name);
        }
		if (o->bypass_tlv) {            
            char nexthop_ip_addr[INET_ADDRSTRLEN]="";
            strlcpy(nexthop_ip_addr, inet_ntoa(o->bypadd_ipv4_addr), 
                    sizeof(nexthop_ip_addr));
            trace(conn, trc_flag_tlv, "TLV BYPASS-VALUE: "
                  "nexthop: %s, protection type: %u"
                  "protecion in use: %u, subscription rate: %f",
                  nexthop_ip_addr, o->node_prot, o->local_prot_in_use,
                  o->subsc_mul);
		}
        break;
    }
    case PCEP_OBJ_IRO: {
        const struct pcep_obj_iro *o = &obj->u.iro;
        trace(conn, trc_flag, "IRO object: subobjects: %u",
              o->subcount);
        pcep_obj_trace_ero(conn, trc_flag_tlv, (const struct pcep_obj_ero*) o);
        break;
    }
    case PCEP_OBJ_SVEC: {
        #define MAX_REQS_PER_LINE   4
        #define CHARS_IN_UINT32     10

        const struct pcep_obj_svec *o = &obj->u.svec;
        unsigned i = 0;
        /* line minimum buf space: MAX_REQS_PER_LINE * "XXXXXXXXXX " */
        char line[MAX_REQS_PER_LINE * (CHARS_IN_UINT32 + 1)] = "";
        char *p = line; /* Point to the start of the line buf */

        trace(conn, trc_flag, "SVEC object: requests: %u, link "
              "diverse: %d, node diverse: %d, SRLG diverse: %d",
              o->id_count, o->link, o->node, o->SRLG);

        for (; i < o->id_count; i++) {
            int written = snprintf(p, CHARS_IN_UINT32 + 1, "%"PRIu32" ",
                                   o->req_ids[i]);
            if (written > CHARS_IN_UINT32 +1) {
                log_error(get_pcep(conn), "snprintf reported truncated output -"
                          " written %u, max %u", written, CHARS_IN_UINT32 + 1);
                abort();
            }
            p += written;
            if (i !=0 && !(i % MAX_REQS_PER_LINE)) {
                /* Overwrite the last space with '\0' */
                *(p-1) = '\0';
                trace(conn, trc_flag, line);
                p = line;
                *p = '\0';
            }
        }
        if (line[0] != '\0') {
            /* There is something in the line buffer, trace it. */
            *(p-1) = '\0';
            trace(conn, trc_flag, line);
        }
        break;
#undef MAX_REQS_PER_LINE
#undef CHARS_IN_UINT32
    }
    case PCEP_OBJ_NOTIFICATION: {
        const struct pcep_obj_notification *o = &obj->u.notification;
        trace(conn, trc_flag, "NOTIFICATION object: type: %u, value: %u",
              o->type, o->value);
        if (out && o->overloaded_duration != 0) {
            trace(conn, trc_flag_tlv, "TLV OVERLOADED-DURATION: %u",
                  o->overloaded_duration);
        }
        break;
    }
    case PCEP_OBJ_PCEPERROR: {
        const struct pcep_obj_error *o = &obj->u.error;
        trace(conn, trc_flag, "ERROR object: type: %u, value: "
                "%u", o->type, o->value);
        if (out && o->missing_request_id) {
            trace(conn, trc_flag_tlv, "TLV Missing Request ID: %lu",
                  o->missing_request_id);
        }
        break;
    }
    case PCEP_OBJ_LOADBALANCING: {
        const struct pcep_obj_loadbalancing *o = &obj->u.loadbalancing;
        trace(conn, trc_flag, "LOAD-BALANCING object: "
                "min-bandwidth: %f, max_lsp: %u", o->min_bandwidth, o->max_lsp);
        break;
    }
    case PCEP_OBJ_CLOSE: {
        const struct pcep_obj_close *o = &obj->u.close;
        trace(conn, trc_flag, "CLOSE object: close reason: %u",
              o->reason);
        break;
    }
    case PCEP_OBJ_LABEL: {
        const struct pcep_obj_label *o = &obj->u.label;
        trace(conn, trc_flag, "LABEL object: label: %lu",
              o->label);
        break;
    }
    case PCEP_OBJ_SRP: {
        const struct pcep_obj_srp *srp = &obj->u.srp;
        trace(conn, trc_flag, "SRP object: remove: %d srp_id: %u"
              " lsp_setup_type: %d", srp->remove, srp->srp_id,
              srp->lsp_setup_type);
        break;
    }
    case PCEP_OBJ_ASSOCIATION_nonRFC:
    case PCEP_OBJ_ASSOCIATION_nonIANA: {
        const struct pcep_obj_association_non_rfc *association = &obj->u.association_non_rfc;
        trace(conn, trc_flag, "association object: type: %d, remove: %d "
              "standby:: %d, protection: %d, association group id: %u",
              association->type, association->flag_remove,
              association->flag_standby, association->flag_protection,
              association->association_group_id);
        break;
    }
    case PCEP_OBJ_ASSOCIATION: {
        const struct pcep_obj_association *association = &obj->u.association;
        char assoc_source_ip_addr[INET_ADDRSTRLEN]="";
        strlcpy(assoc_source_ip_addr, inet_ntoa(association->ipv4_association_source),
                    sizeof(assoc_source_ip_addr));
        trace(conn, trc_flag, "association object: remove: %u ,association type: %u, "
              "association id: %u, association source ip: %s",
              association->flag_remove, association->association_type,
              association->association_id, assoc_source_ip_addr);
        break;
    }
    case PCEP_OBJ_ASSOCIATION_IPV6: {
        const struct pcep_obj_association_ipv6 *association_ipv6 = &obj->u.association_ipv6;
        char assoc_source_ip_addr[INET6_ADDRSTRLEN] = "";
        inet_ntop(AF_INET6, &association_ipv6->ipv6_association_source, assoc_source_ip_addr,
                sizeof(assoc_source_ip_addr));
        trace(conn, trc_flag, "association object: remove: %u ,association type: %u, "
              "association id: %u, association source ip: %s",
              association_ipv6->flag_remove, association_ipv6->association_type,
              association_ipv6->association_id, assoc_source_ip_addr);
        break;
    }
    case PCEP_OBJ_VENDOR: {
	const struct pcep_obj_vendor *ven = &obj->u.vendor;
	trace(conn, trc_flag, "vendor object: size:%d, enterprise:%d",
          ven->size, ven->enterprise);
    for (unsigned int i = 0; i < ven->size ; i++) {
        switch (ven->info[i].type) {
            case PCEP_VENDOR_INFO_TYPE_LSP:
                trace(conn, trc_flag_tlv, "TLV_VENDOR_LSP_QUALIFIER: "
                      "vendor:%d, lsp-qualifier:%d",
                      ven->info[i].enterprise, ven->info[i].u.lsp_type);
                break;
            case PCEP_VENDOR_INFO_TYPE_BW:
                trace(conn, trc_flag_tlv, "TLV_VENDOR_LSP_BW: "
                      "vendor:%d, bw(float):%f",
                      ven->info[i].enterprise, ven->info[i].u.bps);
                break;
            case PCEP_VENDOR_INFO_TYPE_P2MP_TREE_NAME:
                if (ven->info[i].u.p2mp_tree_name[0] != '\0') {
                    trace(conn, trc_flag_tlv, "TLV_VENDOR_P2MP_TREE_NAME: "
                          "vendor:%d, p2mp_tree_name:%s",
                          ven->info[i].enterprise, ven->info[i].u.p2mp_tree_name);
                }
                break;
            case PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF:
		trace(conn, trc_flag_tlv, "TLV_VENDOR_LOCAL_CSPF: "
			"vendor:%d, local_cspf(%d)",
			ven->info[i].enterprise, ven->info[i].u.pvi_local_cspf);
		break;
            case PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE:
                trace(conn, trc_flag_tlv, "TLV_VENDOR_ROUTE_PREFERENCE: "
                      "vendor:%d, route preference:%u",
                      ven->info[i].enterprise, ven->info[i].u.route_preference);
                break;
         case PCEP_VENDOR_INFO_TYPE_UNKNOWN:
                trace(conn, trc_flag_tlv, "PCEP_VENDOR_INFO_TYPE unknown");
        }

	}
	break;
    }
    case PCEP_OBJ_S2LS:
    case PCEP_OBJ_S2LS_nonIANA: {
        const struct pcep_obj_s2ls *o = &obj->u.s2ls;
        trace(conn, trc_flag, "s2ls oper state: %d",
              o->lsp_oper_state);
        break;
    }
    case PCEP_OBJ_FLOWSPEC: {
        const struct pcep_obj_flowspec *o = &obj->u.flowspec;

        trace(conn, trc_flag, "FlowSpec object FS-ID: %u for AFI %d [%s %s], recv TLV: %x",
                              o->fs_id, o->AFI,
                              o->lpm ? "LPM" : "",
                              o->remove ? "Removed" : "Added/Updated",
                              o->fs_tlv_recv);
        break;
    }

    default:
        trace(conn, trc_flag, "Unknown PCEP message: %d",
              obj->type);
        break;
    }
}

static void
pcep_tlv_trace(struct pcep_conn *conn, const struct pcep_tlv *tlv)
{
    if (true == is_pcep_tlv_cli_configurable(tlv->type)) {
        /**
         * Add configurable tlv-types here
         */
        if (pathattribute_color_tlv_type == tlv->type) {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV PATH ATTRIBUTE COLOR: "
                  "Color: %u ", ntoh_uint32_t(&tlv->data[0]));
        } else {
            trace(conn, PCEP_TRC_IN_TLVS, "Unknown configurable TLV type %u", tlv->type);
        }
    } else if (tlv->type < sizeof(tlv_ops)/sizeof(*tlv_ops)) {
        switch(tlv->type) {
        case TLV_NO_PATH_VECTOR:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV No Path Vector: PCE currently un"
                  "available: %d, Unknown destination: %d, Unknown source: %d",
                  (tlv->data[0] & 0x01) ? 1 : 0, (tlv->data[0] & 0x02) ? 1 : 0,
                  (tlv->data[0] & 0x04) ? 1 : 0);
            break;
        case TLV_OVERLOADED_DURATION:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Overloaded Duration: %f",
                  ntoh_float(tlv->data));
            break;
        case TLV_REQ_MISSING:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Missing Request ID: %u",
                  ntoh_uint32_t(tlv->data));
            break;
        case TLV_STATEFUL_PCE_CAPABILITY:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Stateful PCE Capability: Update "
                  "Capability: %d, Include DB Version: %d, LSP Instantiation: %d",
                  (tlv->data[3] & 0x01) ? 1 : 0, ((tlv->data[3] & 0x02) ? 1 : 0),
                  ((tlv->data[3] & 0x04) ? 1 : 0));
            break;
        case TLV_LSP_SYMBOLIC_NAME: {
            char buf[tlv->length + 1];
            memcpy(buf, tlv->data, sizeof(buf));
            buf[tlv->length] = '\0';
            trace(conn, PCEP_TRC_IN_TLVS, "TLV LSP Symbolic Name: '%s'", buf);
            break;
        }
        case TLV_IPV4_LSP_IDENTIFIERS: {
            /* We assume, there is IPV4 address in the extended tunnel ID */
            char sender_ip_addr[INET_ADDRSTRLEN];
            char extend_ip_addr[INET_ADDRSTRLEN];
            if (!inet_ntop(AF_INET, &tlv->data[0], sender_ip_addr,
                           INET_ADDRSTRLEN)) {
                strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
            }
            if (!inet_ntop(AF_INET, &tlv->data[8], extend_ip_addr,
                           INET_ADDRSTRLEN)) {
                strlcpy(extend_ip_addr, "<unknown>", sizeof(extend_ip_addr));
            }
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv4 LSP Identifiers: "
                  "Tunnel Sender Address: %s, LSP ID: 0x%X, "
                  "Tunnel ID: 0x%X, Extended Tunnel ID: %s",
                  sender_ip_addr,
                  ntoh_uint16_t(&tlv->data[4]), ntoh_uint16_t(&tlv->data[6]),
                  extend_ip_addr);
            break;
        }
        case TLV_IPV6_LSP_IDENTIFIERS: {
            /* We assume, there is IPV6 address in the extended tunnel ID */
            char sender_ip_addr[INET6_ADDRSTRLEN];
            char extend_ip_addr[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, &tlv->data[0], sender_ip_addr,
                           INET6_ADDRSTRLEN)) {
                strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
            }
            if (!inet_ntop(AF_INET6, &tlv->data[20], extend_ip_addr,
                           INET6_ADDRSTRLEN)) {
                strlcpy(extend_ip_addr, "<unknown>", sizeof(extend_ip_addr));
            }
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv6 LSP Identifiers: LSP ID: "
                  "Tunnel Sender Address: %s, LSP ID: 0x%X, "
                  "Tunnel ID: 0x%X, Extended Tunnel ID: %s",
                  sender_ip_addr,
                  ntoh_uint16_t(&tlv->data[16]), ntoh_uint16_t(&tlv->data[18]),
                  extend_ip_addr);
            break;
        }
        case TLV_IPV4_P2MP_LSP_IDENTIFIERS_IANA:
        case TLV_IPV4_P2MP_LSP_IDENTIFIERS_nonIANA: {
            char sender_ip_addr[INET_ADDRSTRLEN];
            char extend_ip_addr[INET_ADDRSTRLEN];
	    /*
	    ** If TLV with type 52 comes then it will be considered as p2mp_ipv4_lsp_id
	    ** irrespective of iana compliance configured or not
	    ** This needs to be changed when IANA defines 52 TLV type
	    */

            if (!inet_ntop(AF_INET, &tlv->data[0], sender_ip_addr,
                           INET_ADDRSTRLEN)) {
                strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
            }
            if (!inet_ntop(AF_INET, &tlv->data[8], extend_ip_addr,
                           INET_ADDRSTRLEN)) {
                strlcpy(extend_ip_addr, "<unknown>", sizeof(extend_ip_addr));
            }
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv4 P2MP LSP Identifiers: "
                  "Tunnel Sender Address: %s, LSP ID: 0x%X, "
                  "Tunnel ID: 0x%X, Extended Tunnel ID: %s",
                  sender_ip_addr,
                  ntoh_uint16_t(&tlv->data[4]), ntoh_uint16_t(&tlv->data[6]),
                  extend_ip_addr);
            break;
        }
        case TLV_IPV6_P2MP_LSP_IDENTIFIERS: {
            /* We assume, there is IPV6 address in the extended tunnel ID */
            char sender_ip_addr[INET6_ADDRSTRLEN];
            char extend_ip_addr[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, &tlv->data[0], sender_ip_addr,
                           INET6_ADDRSTRLEN)) {
                strlcpy(sender_ip_addr, "<unknown>", sizeof(sender_ip_addr));
            }
            if (!inet_ntop(AF_INET6, &tlv->data[20], extend_ip_addr,
                           INET6_ADDRSTRLEN)) {
                strlcpy(extend_ip_addr, "<unknown>", sizeof(extend_ip_addr));
            }
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv6 P2MP LSP Identifiers: LSP ID: "
                  "Tunnel Sender Address: %s, LSP ID: 0x%X, "
                  "Tunnel ID: 0x%X, Extended Tunnel ID: %s",
                  sender_ip_addr,
                  ntoh_uint16_t(&tlv->data[16]), ntoh_uint16_t(&tlv->data[18]),
                  extend_ip_addr);
            break;
        }
        case TLV_IPV4_RSVP_ERROR_SPEC: {
            char ip_addr[INET_ADDRSTRLEN] = "";
            const uint8_t *data = NULL;

            if (!inet_ntop(AF_INET, tlv->data, ip_addr, INET_ADDRSTRLEN)) {
                strlcpy(ip_addr, "<unknown>", sizeof(ip_addr));
            }
            data = tlv->data + 4;
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv4 RSVP Error Spec: Node: %s, "
                  "In Place: %d, Not Guilty: %d, Error Code: %u, Error Value: %u",
                  ip_addr, (*data & 0x01) ? 1 : 0, (*data & 0x02) ? 1 : 0, 
		  data[1], ntoh_uint16_t(&data[2]));
            break;
        }
        case TLV_IPV6_RSVP_ERROR_SPEC: {
            char ip_addr[INET6_ADDRSTRLEN] = "";
            const uint8_t *data = NULL;

            if (!inet_ntop(AF_INET6, tlv->data, ip_addr, INET_ADDRSTRLEN)) {
                strlcpy(ip_addr, "<unknown>", sizeof(ip_addr));
            }
            data = tlv->data + 16;
            trace(conn, PCEP_TRC_IN_TLVS, "TLV IPv6 RSVP Error Spec: Node: %s, "
                  "InPlace: %d, NotGuilty: %d, Error Code: %u, Error Value: %u",
                  ip_addr, (*data & 0x01) ? 1 : 0, (*data & 0x02) ? 1 : 0,
                  data[1], ntoh_uint16_t(&data[2]));
            break;
        }
        case TLV_LSP_UPDATE_ERROR_CODE: {
	    trace(conn, PCEP_TRC_IN_TLVS, "TLV LSP Update Error Code: %u",
		  ntoh_uint32_t(tlv->data));
            break;
        }
        case TLV_LSP_DB_VERSION: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV LSP DB Version: %llu",
                  ntoh_uint64_t(tlv->data));
            break;
        }
        case TLV_NODE_IDENTIFIER: {
            char buf[tlv->length + 1];
            memcpy(buf, tlv->data, sizeof(buf));
            buf[tlv->length] = '\0';
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Node Indentifier: '%s'", buf);
            break;
        }
        case TLV_VENDOR_LSP_QUALIFIER: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Vendor LSP qualifier: "
                  "enterprise:%d, type:%d",
                  ntoh_uint32_t(tlv->data), ntoh_uint32_t(tlv->data+4));
            break;
        }
        case TLV_VENDOR_LSP_BW: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Vendor LSP bw: "
                  "enterprise:%d, bw:%d",
                  ntoh_uint32_t(tlv->data), ntoh_uint32_t(tlv->data+4));
            break;
        }
        case TLV_VENDOR_P2MP_TREE_NAME: {
            char buf[tlv->length + 1];
            memcpy(buf, tlv->data, sizeof(buf));
            buf[tlv->length] = '\0';
            trace(conn, PCEP_TRC_IN_TLVS, "TLV P2MP tree Name: '%s'", buf);

            break;
        }
        case TLV_VENDOR_LSP_ROUTE_PREFERENCE: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Vendor Route Preference: "
                  "enterprise:%d, route preference:%u",
                  ntoh_uint32_t(tlv->data), ntoh_uint32_t(tlv->data+4));
            break;
        }
        case TLV_SR_PCE_CAPABILITY: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV SPRING pce Capability: %d",
                  ntoh_uint32_t(&tlv->data[0]));
            break;
        }
        case TLV_PATH_SETUP_TYPE_CAPABILITY: {

            uint16_t tlv_bytes_read = 0;
            uint8_t msd;
            int8_t n_pst = 0;

            trace(conn, PCEP_TRC_IN_TLVS, "TLV PATH SETUP TYPE Capability: %d",
                  ntoh_uint32_t(&tlv->data[0]));


            n_pst = tlv->data[3];
            tlv_bytes_read = 4; //Reserved + n_pst

            while (tlv_bytes_read < (4 + n_pst)) {
                if (srv6_pst_type == tlv->data[tlv_bytes_read]) {
                    trace(conn, PCEP_TRC_IN_TLVS, "SRv6 PST is received");
                }
                tlv_bytes_read += 1;
            }

            uint8_t padlen = (n_pst%4) ? 4 - (n_pst%4):0;
            tlv_bytes_read += padlen;

            trace(conn, PCEP_TRC_IN_TLVS, "PST SUB-TLVs:");

            while (tlv_bytes_read < tlv->length) {
                /** 2 bytes for Sub TLV Type */
                int sub_tlv_type = ntoh_uint16_t(tlv->data + tlv_bytes_read);
                tlv_bytes_read += 2;

                /** 2 bytes for Sub TLV Length */
                int sub_tlv_len = ntoh_uint16_t(tlv->data + tlv_bytes_read);
                tlv_bytes_read += 2;
                trace(conn, PCEP_TRC_IN_TLVS, " sub_tlv_type: %d, sub_tlv_len %d",sub_tlv_type,sub_tlv_len);

                if (TLV_SR_PCE_CAPABILITY == sub_tlv_type) {
                    /** 1 bytes for MSD */
                    msd = tlv->data[tlv_bytes_read + 3]; /*first 3 bytes reserved + flags */
                    tlv_bytes_read += 4;

                    trace(conn, PCEP_TRC_IN_TLVS,"SR PCE CAP sub-TLV: MSD : %u",msd);
                } else if (srv6_pce_capability_sub_tlv_type == sub_tlv_type) {
                    tlv_bytes_read += sub_tlv_len;
                    trace(conn, PCEP_TRC_IN_TLVS,"SRv6 PCE CAP sub-TLV is received");
                } else {
                        /* NOT SUPPORTED TLV, IGNORE*/
                        tlv_bytes_read += sub_tlv_len;
                }

                uint8_t sub_tlv_padlen = (sub_tlv_len%4) ? 4 - (sub_tlv_len%4):0;
                tlv_bytes_read +=  sub_tlv_padlen;
            }

            break;
        }

        case TLV_PATH_SETUP_TYPE: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV path setup setup: %d",
                  ntoh_uint32_t(&tlv->data[0]));
            break;
        }
        case TLV_TE_PATH_BINDING: {
            struct pcep *pcep = get_pcep(conn);

            if ((tlv->length != TLV_PATH_BINDING_BT_0_LEN) && (tlv->length != TLV_PATH_BINDING_BT_1_LEN) &&
                    (tlv->length != TLV_PATH_BINDING_BT_2_LEN) && (tlv->length != TLV_PATH_BINDING_BT_3_LEN)) {
                log_error(pcep, "Invalid TLV length : %u for TE-PATH-BINDING TLV", tlv->length);
                break;
            }

            uint8_t bt = tlv->data[0];
            uint8_t flags = tlv->data[1];
            bool flag_r = ((flags >> 7) & 0x1);
            u_int32_t bv = 0;

            if (0 == bt) {
                bv = ntoh_uint32_t(&tlv->data[4]);
                bv = (bv >> 12);
            } else if (1 == bt) {
                bv = ntoh_uint32_t(&tlv->data[4]);
            } else {
                trace(conn, PCEP_TRC_IN_TLVS,
                      "TLV TE-PATH-BINDING: binding type: %u is not supported", bt);
                break;
            }

            trace(conn, PCEP_TRC_IN_TLVS,
                  "TLV TE-PATH-BINDING: binding type: %u, binding value: %u, flag r: %u", bt, bv, flag_r);
            break;
        }
        /* PCE Initiated Bypass : begin */
        case TLV_BYPASS: {
            char bypass_ip_addr[INET_ADDRSTRLEN];
            float subsc_mul;
            if (!inet_ntop(AF_INET, &tlv->data[4], bypass_ip_addr,
                           INET_ADDRSTRLEN)) {
                strlcpy(bypass_ip_addr, "<unknown>", sizeof(bypass_ip_addr));
            }  
            subsc_mul = ntoh_float(&tlv->data[8]);
                
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Bypass: "
                  "Node Protection: %d, Local Protection In Use: %d, "
                  "Bypass Ipv4 Address: %s, Subscription Multiplier: %f",
                  (tlv->data[3] & 0x01) ? 1 : 0, ((tlv->data[3] & 0x02) ? 1 : 0),
                  bypass_ip_addr, subsc_mul);
            break;
        }
        /* PCE Initiated Bypass : end */

        case TLV_PCE_FLOWSPEC_CAPABILITY: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Flow Spec pce Capability, Value : %d",
                  ntoh_uint16_t(&tlv->data[0]));
            break;
        }
        case TLV_FLOWSPEC_FLOWFILTER: {
            char buffer[PCEP_TRACE_BUFFER_SIZE];
            char *buf = buffer;
            uint32_t length = 0,read = 0, upper, lower;
            uint16_t tlv_bytes_read = 0, tmp_uint16, rd_type;
            uint8_t src_len, mgp_len, prefix_len;
            struct in_addr src_ina, mc_ina, ina;
            bool src_w, grp_w;
            bool print_once = true;

            length+= snprintf(buf + length, sizeof(buffer) -length, "FlowFilter TLVs:");

            while (tlv_bytes_read < tlv->length) {
                /** 2 bytes for FlowSpec Spec TLV Type */
                int fs_tlv = ntoh_uint16_t(tlv->data + read);
                read += 2;

                /** 2 bytes for FlowSpec Spec TLV Length */
                int fs_tlv_len = ntoh_uint16_t(tlv->data + read);
                read += 2;

                tlv_bytes_read += TLV_HEADER_LEN;
                switch (fs_tlv) {
                    case TLV_FLOWSPEC_MULTICAST:

                        /** First 2 bytes for Multicast TLV */
                        tmp_uint16 = ntoh_uint16_t(tlv->data + read);
                        read += 2;

                        src_w = ((tmp_uint16 >> 9) & 1);
                        grp_w = ((tmp_uint16 >> 2) & 1);

                        /** 1 bytes for Multicast TLV SRC Mask */
                        src_len = tlv->data[read];
                        read += 1;

                        /** 1 bytes for Multicast TLV GRP Mask */
                        mgp_len = tlv->data[read];
                        read += 1;

                        /** 4 bytes for Multicast TLV SRC Address */
                        memcpy(&src_ina.s_addr, tlv->data + read, 4);
                        read += 4;

                        /** 4 bytes for Multicast TLV Group Address */
                        memcpy(&mc_ina.s_addr, tlv->data + read, 4);
                        read += 4;

                        length+= snprintf(buf + length, sizeof(buffer) -length, " IPv4 MC : [ ");
                        if (src_w) {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " source: wildcard");
                        } else {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " source: %s/%u", 
                                            inet_ntoa(src_ina), src_len);
                        }

                        if (grp_w) {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " group: wildcard");
                        } else {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " group: %s/%u", 
                                        inet_ntoa(mc_ina), mgp_len);
                        }
                        length+= snprintf(buf + length, sizeof(buffer) -length, " ] ");
                        tlv_bytes_read += fs_tlv_len;
                        break;
                    case TLV_FLOWSPEC_ROUTE_DISTINGUISER:            
                        /** 4 bytes for RD TLV upper part */
                        upper = ntoh_uint32_t(tlv->data + read);
                        read += 4;

                        /** 4 bytes for RD TLV lower part */
                        lower = ntoh_uint32_t(tlv->data + read);
                        read += 4;

                        rd_type = upper >> 16;
                        length+= snprintf(buf + length, sizeof(buffer) -length, " RD : [ ");
                        if (rd_type == 0) {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " route_distinguisher: %u:%u", 
                                                            (upper & 0x0000ffff), lower);
                        } else if (rd_type == 1) {
                            ina.s_addr = ((upper << 16) | (lower >> 16));
                            length+= snprintf(buf + length, sizeof(buffer) -length, " route_distinguisher: %s:%u", 
                                                        inet_ntoa(ina), (lower & 0x0000ffff));
                        } else if (rd_type == 2) {
                            length+= snprintf(buf + length, sizeof(buffer) -length, " route_distinguisher: %uL:%u", 
                                            ((upper << 16) | (lower >> 16)), (lower & 0x0000ffff));
                        }
                        length+= snprintf(buf + length, sizeof(buffer) -length, " ] ");
                        tlv_bytes_read += fs_tlv_len;
                        break;
                    case TLV_FLOWSPEC_DEST_PREFIX:
                        prefix_len = tlv->data[read];
                        read += 1;

                        if (print_once) {
                            length+= snprintf(buf + length, sizeof(buffer) -length,
                                            " Destination Prefix:");
                            print_once = false;
                        }

                        length += snprintf(buf + length, sizeof(buffer) -length, " [ ");

                        ina.s_addr = ntoh_uint32_t(tlv->data + read);

                        length+= snprintf(buf + length, sizeof(buffer) -length,
                                    "%s/%u",
                                    inet_ntoa(ina), prefix_len);

                        read += (4+3); // 4 byte prefix and 3 bytes padding

                        length += snprintf(buf + length, sizeof(buffer) -length, " ]");
                        tlv_bytes_read += fs_tlv_len;
                        break;
                    default:
                        /* NOT SUPPORTED TLV, IGNORE*/
                        tlv_bytes_read += fs_tlv_len;
                        read += fs_tlv_len;
                }
            }

            trace(conn, PCEP_TRC_IN_TLVS, "%s", buf);
            break;
        }
        case TLV_PATH_PROTECTION_ASSOCIATION: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Path protection association "
                "protection type: %u, secondary: %u, protection: %u",
                ((tlv->data[0] >> 2) & 0x3F), (((tlv->data[3] >> 1) & 0x1)? 1: 0),
                ((tlv->data[3] & 0x1)? 1: 0));
            break;
        }
        case TLV_EXTENDED_ASSOCIATION_ID: {
            uint8_t data[MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE];
            uint32_t extended_assoc_id = 0;
            int16_t i = 0;

            struct pcep *pcep = get_pcep(conn);
            if (tlv->length == TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN) {
                char end_point_ipv6[INET6_ADDRSTRLEN] = "";
                inet_ntop(AF_INET6, &tlv->data[4], end_point_ipv6,
                        sizeof(end_point_ipv6));
                trace(conn, PCEP_TRC_IN_TLVS, "TLV Extended association ID for IPv6 SRPAG: "
                      "color: %u, end point: %s",
                      ntoh_uint32_t(&tlv->data[0]), end_point_ipv6);
            } else if (tlv->length == TLV_EXTENDED_ASSOC_ID_IPV4_SRPAG_FIXED_LEN) {
                char end_point[INET_ADDRSTRLEN];
                if (!inet_ntop(AF_INET, &tlv->data[4], end_point,
                               INET_ADDRSTRLEN)) {
                    strlcpy(end_point, "<unknown>", sizeof(end_point));
                }
                trace(conn, PCEP_TRC_IN_TLVS, "TLV Extended association ID for SRPAG: "
                      "color: %u, end point: %s",
                      ntoh_uint32_t(&tlv->data[0]), end_point);
            } else {
                if (tlv->length > 4) {
                    log_error(pcep, "Incomplete TLV length : "
                            "Extended association ID should not exceed 4 bytes");
                    break;
                }

                memset(data, 0, MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE);
                for (int16_t len = tlv->length - 1; len >= 0; len--) {
                    data[MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE - (++i)] = tlv->data[len];
                }
                extended_assoc_id = ntoh_uint32_t(data);
                trace(conn, PCEP_TRC_IN_TLVS, "TLV Extended association ID "
                        "extended association id: %u", extended_assoc_id);
            }
            break;
        }
        case TLV_ASSOCIATION_TYPE_LIST: {
            for (uint16_t len = 0; len < tlv->length; len+=2) {
                uint16_t data = (((tlv->data[len] << 8) & 0xFF00) | (tlv->data[len+1] & 0xFF));
                if (data == ASSOCIATION_TYPE_PATH_PROTECTION ) {
                    trace(conn, PCEP_TRC_IN_TLVS, "TLV Association type list:"
                        "Path protection association type is received");
                } else if (data == ASSOCIATION_TYPE_SRPAG){
                    trace(conn, PCEP_TRC_IN_TLVS, "TLV Association type list:"
                        "SRPAG association type is received");
                } else if (data == ASSOCIATION_TYPE_DISJOINT){
                    trace(conn, PCEP_TRC_IN_TLVS, "TLV Association type list:"
                        "Disjoint association type is received");
                } else {
                    trace(conn, PCEP_TRC_IN_TLVS, "TLV Association type list:"
                        "unknown type: %u is received", data);
                }
            }
            break;
        }
        case TLV_SR_CANDIDATE_PATH_IDENTIFIER: {
            char origiator_address[INET6_ADDRSTRLEN];

            if(!inet_ntop(AF_INET6, &tlv->data[8], origiator_address,
                    sizeof(origiator_address))) {
                if (!inet_ntop(AF_INET, &tlv->data[20], origiator_address,
                                           INET_ADDRSTRLEN)) {
                    strlcpy(origiator_address, "<unknown>", sizeof(origiator_address));
                }
            }
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Candidate path Identifier: "
                  "proto origin: %u, originator asn: %u, originator address: %s"
                  " discriminator: %u",
                  tlv->data[0], ntoh_uint32_t(&tlv->data[4]), origiator_address,
                  ntoh_uint32_t(&tlv->data[24]));
            break;
        }
        case TLV_SR_PREFERENCE: {
            trace(conn, PCEP_TRC_IN_TLVS, "TLV SR Preference: "
                  "preference: %u", ntoh_uint32_t(&tlv->data[0]));
            break;
        }
        case TLV_MULTIPATH_CAPABILITY: 
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Multipath Capability: "
                  "max_multi_paths:%u flags: %u", (ntoh_uint16_t(tlv->data) & 0xFFFF),
                  (ntoh_uint32_t(tlv->data) & 0xFFFF));
            break;
        case TLV_VERSION_INFO:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Version Info: major_version %u | minor_version %u",
                  sw_version.sw_major,sw_version.sw_minor);
            break;
        case TLV_DISJOINT_CONFIGURATION:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Disjoint Configuration - flags:u",
                  ntoh_uint32_t(&tlv->data[0]));
            break;
        case TLV_DISJOINT_STATUS:
            trace(conn, PCEP_TRC_IN_TLVS, "TLV Disjoint Status - flags:u",
                  ntoh_uint32_t(&tlv->data[0]));
            break;
        default:
            trace(conn, PCEP_TRC_IN_TLVS, "Unsupported TLV type %u", tlv->type);
            break;
        } /* switch */

    } else {
        trace(conn, PCEP_TRC_IN_TLVS, "Unknown TLV type %u", tlv->type);
    }
}

/**
 * Parse an object
 *
 * @param[in] conn Connection handle
 * @param[out] obj Result structure for the object
 * @param[in] data Data to parse
 * @param[in] datalen Data length
 * @return true if the object could not be fully parsed (malformed, unknown)
 */
bool
pcep_obj_parse (struct pcep_conn *conn, struct pcep_object *obj,
                const uint8_t *data, uint16_t datalen)
{
    struct pcep *pcep = get_pcep(conn);
    uint8_t c, t;
    unsigned objlen;
    int parsed_data;
    const struct obj_ops *oops = NULL;
    
    /* Minimum length as per RFC5440, 7.2: Common Object Header */
    if (datalen < OBJ_HEADER_LEN) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        log_error(pcep, "Incomplete object header (datalen=%u)", datalen);
        return true;
    }

    c = data[0];
    if (( PCEP_OBJCLASS_ASSOCIATION == c ) && 
        ( ASSOC_OBJ_RFC_COMPLAINT != assoc_obj_complaince )) {
        c = PCEP_OBJCLASS_ASSOCIATION_nonRFC;
    }

    t = data[1] >> 4;
    /* supported range for classes */
    if (( c < PCEP_OBJCLASS_OPEN || c > PCEP_MAX_OBJ_CLASS )
            && ( c != PCEP_OBJCLASS_ASSOCIATION_VAL )
            && ( c != PCEP_OBJCLASS_FLOWSPEC )) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_UO, PCEP_ERR_VAL_OBJECT_CLASS);
        log_error(pcep, "Invalid object (class=%u type=%u)", c, t);
        return true;
    }

    /* supported range for types */
    if ( t < 1 || t > PCEP_MAX_OBJ_TYPE ) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_UO, PCEP_ERR_VAL_OBJECT_TYPE);
        log_error(pcep, "Invalid object (class=%u type=%u)", c, t);
        return true;
    }

    obj->type = PCEP_OBJECTID(c, t);
    obj->procrule = (data[1] & 0x2) >> 1;
    obj->ignore   =  data[1] & 0x1;

    objlen = pcep_obj_length(data);
    if (objlen < OBJ_HEADER_LEN || objlen > MAX_OBJ_LEN || objlen % PADDING) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        log_error(pcep, "Invalid object (length=%u)", objlen);
        return true;
    }
    if (datalen < objlen) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        log_error(pcep, "Incomplete object (length=%u datalen=%u)", objlen,
                  datalen);
        return true;
    }

    oops = object_ops + obj->type;
    if (obj->type >= sizeof(object_ops)/sizeof(*object_ops)
        || oops->body == NULL) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_UO, PCEP_ERR_VAL_OBJECT_TYPE);
        log_error(pcep, "Unhandled object (class=%u type=%u)", c, t);
        return true;
    }

    if (oops->fixlen && oops->fixlen != objlen - OBJ_HEADER_LEN) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        log_error(pcep, "Invalid %s object (length=%u)", oops->name, objlen);
        return true;
    }
    if (oops->minlen > objlen - OBJ_HEADER_LEN) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        log_error(pcep, "Incomplete %s object (length=%u)", oops->name, objlen);
        return true;
    }

    /* Move data pointer forward for common header's 4 bytes */
    data += OBJ_HEADER_LEN;
    /* Set remaining datalen to object len - common obj. header */
    datalen = objlen - OBJ_HEADER_LEN;
    parsed_data = oops->body(pcep, &obj->u, data, datalen);
    if (parsed_data < 0)
        return true;
    data += parsed_data;
    datalen -= parsed_data;
    pcep_obj_trace(conn, false, obj);

    if (oops->tlv && datalen) {
        assert(oops->fixlen == 0);
        assert(oops->minlen != 0);
        while (datalen) {
            const struct pcep_tlv tlv = {
                .type   = ntoh_uint16_t(data),
                .length = ntoh_uint16_t(data + 2),
                .data   = data + TLV_HEADER_LEN,
            };

            if (datalen < TLV_HEADER_LEN) {
                if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
                    pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS,
                                    PCEP_ERR_VAL_GENERIC);
                log_error(pcep, "Incomplete TLV header (datalen=%u)", datalen);
                return true;
            }

            datalen -= TLV_HEADER_LEN;
            if (datalen < tlv.length) {
                if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
                    pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS,
                                    PCEP_ERR_VAL_GENERIC);
                log_error(pcep, "Incomplete TLV (length=%u datalen=%u type=%u)",
                          tlv.length, datalen, tlv.type);
                return true;
            }

            pcep_tlv_trace(conn, &tlv);
            if ((tlv.type < sizeof(tlv_ops)/sizeof(*tlv_ops)) ||
                (is_pcep_tlv_cli_configurable(tlv.type))) {
                const struct pcep_tlv_ops *tops = get_pcep_tlv_ops (tlv.type);
                if (tops->name) {
                    if (tops->fixlen && tops->fixlen != tlv.length) {
                        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
                            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS,
                                            PCEP_ERR_VAL_GENERIC);
                        log_error(pcep, "Invalid %s TLV (length=%u)",
                                  tops->name, tlv.length);
                        return true;
                    }

                    if (oops->tlv(pcep, &obj->u, &tlv)) {
                        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
                            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS,
                                            PCEP_ERR_VAL_GENERIC);
                        return true;
                    }
                }
            }

            data += tlv.length + TLV_HEADER_LEN;
            datalen -= tlv.length;

            /* Adjust for possible TLV padding */
            if (tlv.length % PADDING) {
                const unsigned e = PADDING - tlv.length % PADDING;
                datalen -= e;
                data += e;
            }
        }
    }
    return false;
}

/**
 * Retrieve the length of SPRING  ero subobject
 *
 * @param[in] SPRING ero subobject
 * @return the length of SPRING ero sub object
 */
size_t
pcep_obj_ero_sr_reqlen (const struct pcep_obj_ero_sub_sr sr_ero)
{
    size_t ret=0;
    switch (sr_ero.nai_type) {
        case PCEP_SR_ERO_NAI_TYPE_ABSENT:
            ret += 8;
            break;
        case PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
            if ((!sr_ero.S_bit) && (!sr_ero.F_bit)) {
                ret += 12;
            } else {
                ret += 8;
            }
            break;
	    //#ifdef PCEP_SR_IPV6
        case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
            if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                ret += 8;
            } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                ret += 20;
            } else {
                ret += 24;
            }
            break;
	    //#endif
        case PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ:
            if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                ret += 8;
            } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                ret += 12;
            } else {
                ret += 16;
            }
            break;
	    //#ifdef PCEP_SR_IPV6
        case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
            if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                ret += 8;
            } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                ret += 36;
            } else {
                ret += 40;
            }
            break;
	    //#endif
	    // #ifdef PCEP_SR_UNNUMBERED
        case PCEP_SR_ERO_NAI_TYPE_UNNUMBERED:
            if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                ret += 8;
            } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                ret += 20;
            } else {
                ret += 24;
            }
            break;
	    //#endif
        default:
            break;
    }
    return ret;
}

/**
 * Retrieve the length of SPRING  ero subobject
 *
 * @param[in] SPRING ero subobject
 * @return the length of SPRING ero sub object
 */
size_t
pcep_obj_ero_srv6_reqlen (const struct pcep_obj_ero_sub_srv6 srv6_ero)
{
    size_t ret=0;
    switch (srv6_ero.nai_type) {
        case PCEP_SR_ERO_NAI_TYPE_ABSENT:
            if (srv6_ero.T_bit) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_ABSENT_WITH_SID_STRUCTURE;
            } else {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_ABSENT_WITHOUT_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
            if ((!srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
            if ((!srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
            if ((!srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (!srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_ero.S_bit) && (srv6_ero.T_bit)) {
                ret += PCEP_SRV6_ERO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        default:
            break;
    }
    return ret;
}

/**
 * Retrieve the message object length for an ero object
 *
 * @param[in] ero ero object
 * @return the message object length
 */
static size_t
pcep_obj_ero_reqlen (const struct pcep_obj_ero *ero)
{
    size_t ret=0;
    uint8_t count=ero->subcount;
    struct pcep_obj_ero_sub_sr sr_ero;
    while (count--) {
        if (ero->subs[count].type == srv6_ero_subobject_type) {
            struct pcep_obj_ero_sub_srv6 srv6_ero;
            srv6_ero = ero->subs[count].data.srv6_ero;
            ret += pcep_obj_ero_srv6_reqlen(srv6_ero);

        } else {
            switch(ero->subs[count].type) {
              case PCEP_ERO_SUB_IPV4:
                ret+=8;
                break;
            case PCEP_ERO_SUB_IPV6:
                ret += 20;
                break;
            case PCEP_ERO_SUB_LABEL:
                  ret += 8;
                break;
            case PCEP_ERO_SUB_UNNUMBERED_IID:
                ret += 12;
                break;
            case PCEP_ERO_SUB_AUTONOMOUS:
                ret += 4;
                break;
            case PCEP_ERO_SUB_SR:
                sr_ero = ero->subs[count].data.sr_ero;
                ret += pcep_obj_ero_sr_reqlen(sr_ero);
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

/**
 * Retrieve the length of SPRING  rro subobject
 *
 * @param[in] SPRING rro subobject
 * @return the length of SPRING rro sub object
 */
size_t
pcep_obj_rro_sr_reqlen (const struct pcep_obj_rro_sub_sr sr_rro)
{
    size_t ret=0;
    switch (sr_rro.nai_type) {
        case PCEP_SR_RRO_NAI_TYPE_ABSENT:
            ret += 8;
            break;
        case PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID:
            if ((!sr_rro.S_bit) && (!sr_rro.F_bit)) {
                ret += 12;
            } else {
                ret += 8;
            }
            break;
#ifdef PCEP_SR_IPV6
        case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
            if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                ret += 8;
            } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                ret += 20;
            } else {
                ret += 24;
            }
            break;
#endif
        case PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ:
            if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                ret += 8;
            } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                ret += 12;
            } else {
                ret += 16;
            }
            break;
#ifdef PCEP_SR_IPV6
        case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
            if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                ret += 8;
            } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                ret += 36;
            } else {
                ret += 40;
            }
            break;
#endif
#ifdef PCEP_SR_UNNUMBERED
        case PCEP_SR_RRO_NAI_TYPE_UNNUMBERED:
            if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                ret += 8;
            } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                ret += 20;
            } else {
                ret += 24;
            }
            break;
#endif
        default:
            break;
    }
    return ret;
}

/**
 * Retrieve the length of SPRING  ero subobject
 *
 * @param[in] SPRING ero subobject
 * @return the length of SPRING ero sub object
 */
size_t
pcep_obj_rro_srv6_reqlen (const struct pcep_obj_rro_sub_srv6 srv6_rro)
{
    size_t ret=0;
    switch (srv6_rro.nai_type) {
        case PCEP_SR_RRO_NAI_TYPE_ABSENT:
            if (srv6_rro.T_bit) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_ABSENT_WITH_SID_STRUCTURE;
            } else {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_ABSENT_WITHOUT_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
            if ((!srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_NODE_ID_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
            if ((!srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_ADJ_ID_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        case PCEP_SR_RRO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
            if ((!srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITHOUT_SID_STRUCTURE;
            } else if ((!srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITH_SID_WITH_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (!srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITHOUT_SID_STRUCTURE;
            } else if ((srv6_rro.S_bit) && (srv6_rro.T_bit)) {
                ret += PCEP_SRV6_RRO_LEN_NAI_TYPE_IPV6_LINKLOCAL_ADJ_WITHOUT_SID_WITH_SID_STRUCTURE;
            }
            break;
        default:
            break;
    }
    return ret;
}

/**
 * Retrieve the message object length for a rro object
 *
 * @param[in] rro rro object
 * @return the message object length
 */
static size_t
pcep_obj_rro_reqlen (const struct pcep_obj_rro *rro)
{
    size_t ret=0;
    uint8_t count=rro->subcount;
    struct pcep_obj_rro_sub_sr sr_rro;
    while (count--) {
        if (rro->subs[count].type == srv6_rro_subobject_type) {
            struct pcep_obj_rro_sub_srv6 srv6_rro;
            srv6_rro = rro->subs[count].data.srv6_rro;
            ret += pcep_obj_rro_srv6_reqlen(srv6_rro);
        } else {
            switch(rro->subs[count].type) {
            case PCEP_RRO_SUB_IPV4:
                ret+=8;
                break;
            case PCEP_RRO_SUB_IPV6:
                ret += 20;
                break;
            case PCEP_RRO_SUB_LABEL:
                ret += 8;
                break;
            case PCEP_RRO_SUB_UNNUMBERED_IID:
                ret += 12;
                break;
            case PCEP_RRO_SUB_SR:
                sr_rro = rro->subs[count].data.sr_rro;
                ret += pcep_obj_rro_sr_reqlen(sr_rro);
                break;
            default:
                break;
            }
        }
    }
    return ret;
}

/**
 * Retrieve the message object length for an p2mp_endpoint ipv4 object
 *
 * @param[in] p2mp_endpoint ipv4 obj
 * @return the message object length
 */
static size_t
pcep_obj_p2mp_endpoints_ipv4_reqlen (const struct pcep_obj_p2mp_endpoints_ipv4 *endpoint)
{
    size_t ret=0;
    uint8_t count=endpoint->subcount;

    ret +=8; // type = 4 , source = 4
    ret += count*4;
    return ret;
}

/**
 * Retrieve the message object length for an p2mp_endpoint ipv6 object
 *
 * @param[in] p2mp_endpoint ipv6 obj
 * @return the message object length
 */
static size_t
pcep_obj_p2mp_endpoints_ipv6_reqlen (const struct pcep_obj_p2mp_endpoints_ipv6 *endpoint)
{
    size_t ret=0;
    uint8_t count=endpoint->subcount;

    ret += 20; // type =4, source = 16
    ret += count*16;
    return ret;
}

static uint16_t
tlv_assoc_type_list_data_len (bool path_protection_assoc,
                              bool srpag_assoc,
                              bool disjoint_assoc_capability)
{
    uint16_t data_len = 0;

    if (path_protection_assoc) {
        data_len += 2;
    }
    if (srpag_assoc) {
        data_len +=2;
    }
    if (disjoint_assoc_capability) {
        data_len +=2;
    }

    return data_len;
}



/**
 * Retrieve the message object length for an object
 *
 * @param[in] obj object
 * @return the message object length
 */
size_t
pcep_obj_reqlen (const struct pcep_object *obj)
{
    size_t ret = OBJ_HEADER_LEN; /* Header size */
    switch (obj->type) {
    case PCEP_OBJ_BANDWIDTH_REOPTIM:
    case PCEP_OBJ_BANDWIDTH_REQUEST:
    case PCEP_OBJ_CLOSE:
    case PCEP_OBJ_PCEPERROR: /*TLV only handled by PCE */
        return ret + 4;
    case PCEP_OBJ_ENDPOINTS_IPV4:
        return ret + 8;
    case PCEP_OBJ_ENDPOINTS_IPV6:
        return ret + 32;
    case PCEP_OBJ_P2MP_ENDPOINTS_IPV4:
      return  ret + pcep_obj_p2mp_endpoints_ipv4_reqlen(&obj->u.p2mp_endpoints_ipv4);
    case PCEP_OBJ_P2MP_ENDPOINTS_IPV6:
      return  ret + pcep_obj_p2mp_endpoints_ipv6_reqlen(&obj->u.p2mp_endpoints_ipv6);
    case PCEP_OBJ_LOADBALANCING:
        return ret + 8;
    case PCEP_OBJ_LSP:
        ret += 4;
        if (obj->u.lsp.symbolic_name[0]) {
            /* retrieve size of string (max MAX_SYMB_NAME_SIZE) without \0 */
            uint16_t idx;
            for (idx=0; idx < MAX_SYMB_NAME_SIZE; idx++) {
                if (!obj->u.lsp.symbolic_name[idx])
                    break;
            }
            if (idx > MAX_SYMB_NAME_SIZE)
                idx = MAX_SYMB_NAME_SIZE;
            ret += 4 + idx + ((idx%PADDING)?PADDING-(idx%PADDING):0);
        }
        if (obj->u.lsp.propagate_max_segment_list) {
            ret += 8;
        }
        if (obj->u.lsp.errspec_len)
            /*
             * When ERR-SPEC is present LSP-UPDATE-ERROR-CODE should
             * be there as well. 
             * Count 8 bytes for the entire LSP Update Error Code TLV
             * and 4 bytes for the type and length fields of ERROR-SPEC TLV
             */
            ret += 8 + 4 + obj->u.lsp.errspec_len;
	if (obj->u.lsp.lsp_identifiers_len) {
	    ret += 4 + obj->u.lsp.lsp_identifiers_len;
	}

        for (int count = 0; count < MAX_PATH_BINDING_TLVS; count++) {
            if (obj->u.lsp.path_binding[count].mpls_label_binding_value) {
                /*
                 * Type + Length = 4
                 * TLV Length + Padding   = 8
                 */
                ret += 4 + 8;
            }
        }

        return ret;
    case PCEP_OBJ_LSPA:
        ret += 16;
        if (obj->u.lspa.symbolic_name[0]) {
            /*
             * Retrieve size of string (max MAX_SYMB_NAME_SIZE) without \0
             */
            uint16_t idx;
            for (idx=0; idx < MAX_SYMB_NAME_SIZE; idx++) {
                if (!obj->u.lspa.symbolic_name[idx])
                    break;
            }
            if (idx > MAX_SYMB_NAME_SIZE)
                idx = MAX_SYMB_NAME_SIZE;
            ret += 16 + idx + ((idx%PADDING)?PADDING-(idx%PADDING):0);
        }
        if (obj->u.lspa.bypass_tlv) {
            ret += 4 + TLV_BYPASS_FIXED_LEN;
        }
        return ret;
    case PCEP_OBJ_METRIC:
        return ret + 8;
    case PCEP_OBJ_NOPATH: /* TLV only handled by PCE */
        return ret + 4;
    case PCEP_OBJ_NOTIFICATION:
        if (obj->u.notification.overloaded_duration)
            ret += 8;
        return ret + 4;
    case PCEP_OBJ_OPEN:
    {
        size_t assoc_type_list_data_len = tlv_assoc_type_list_data_len(
                                obj->u.open.path_protection_association,
                                obj->u.open.srpag_association,
                                obj->u.open.disjoint_assoc_capability);
        if (assoc_type_list_data_len != 0) {
            size_t padding_len = 0;
            ret += 4; /** Type + Length = 4 */
            ret += assoc_type_list_data_len;
            padding_len = ((assoc_type_list_data_len % 4) != 0) ?
                            (4 - (assoc_type_list_data_len % 4)) : 0;
            ret += padding_len;
        }
        if (obj->u.open.stateful)
            ret += 8;
        if (obj->u.open.spring_capability)
            ret += 8;
        if (obj->u.open.pce_flowspec_capability)
            /*
             * Type + Length = 4
             * TLV Length    = 4
             */
            ret += 8;
        /* Path Setup Type Capability Variable length */
        /** 4(Type:2 + length:2)+4(reserved:3 + npst:1)+4(pst:1 + padding:3) **/
        ret += 12;
        if (obj->u.open.spring_capability) {
            /** 4(Type:2+ length:2)+4(reserved:3 + npst:1)+4(pst:2 + padding:2)+ 8(SR segment capability tlv) **/
            ret += 8;
        }
        if (obj->u.open.srv6_capability) {
            /* SUB-TLV header(4) + reserved(2) + flags(2) + 4 MSD Type, Value pairs (4*2) */
            ret += 16;
        }
        if (obj->u.open.multipath_capability) {
            ret += 8;
        }
	/* Type + Length = 4 * TLV Length = 4*/
	ret += 8;

        return ret + 4;
    }
    case PCEP_OBJ_RP:
    return ret + 16;
    case PCEP_OBJ_PATH_ATTRIBUTE:
        /* Path ID Field */
        ret += 8;
        /* Weight */
        ret += 8;
        if (obj->u.path_attr.secondary_path) {
            ret += 8;
        }
        return ret;
    case PCEP_OBJ_ERO:
    return ret + pcep_obj_ero_reqlen(&obj->u.ero);
    case PCEP_OBJ_IRO:
    return ret + pcep_obj_ero_reqlen(&obj->u.ero);
    case PCEP_OBJ_RRO:
    return ret + pcep_obj_rro_reqlen(&obj->u.rro);
    case PCEP_OBJ_SVEC:
    return ret + 4 + obj->u.svec.id_count * 4;
    case PCEP_OBJ_LABEL:
        return ret + 4;
    case PCEP_OBJ_SRP:
        return ret + 16;
    case PCEP_OBJ_ASSOCIATION_nonRFC:
    case PCEP_OBJ_ASSOCIATION_nonIANA:
          return ret + 8;
    case PCEP_OBJ_ASSOCIATION:
        ret += 12;  /** Association object length */

        /** optional TLV length */
        if (obj->u.association.path_protection)
            ret += 8;
        if (obj->u.association.disjoint_config) {
            ret += 8;
        }
        if ((obj->u.association.association_type != ASSOCIATION_TYPE_SRPAG) &&
                (obj->u.association.extended_assoc_id))
            ret += 8;
        if ((obj->u.association.association_type == ASSOCIATION_TYPE_SRPAG) &&
                (obj->u.association.extended_assoc_id))
            ret += 12;
        if (obj->u.association.sr_candidate_path_identifier)
            ret += 32;
        if (obj->u.association.sr_preference)
            ret += 8;
          return ret;
    case PCEP_OBJ_ASSOCIATION_IPV6:
        ret += 24;  /** Association object length */

        /** optional TLV length */
        if (obj->u.association.disjoint_config) {
            ret += 8;
        }
        if (obj->u.association_ipv6.extended_assoc_id)
            ret += 24;
        if (obj->u.association_ipv6.sr_candidate_path_identifier)
            ret += 32;
        if (obj->u.association_ipv6.sr_preference)
            ret += 8;
          return ret;
    case PCEP_OBJ_VENDOR:
          ret += 4;            /* enterprise number */
          for (unsigned int i =0; i < obj->u.vendor.size; i++) {
              switch(obj->u.vendor.info[i].type) {
                  case PCEP_VENDOR_INFO_TYPE_LSP:
                      ret += 12; /* tlv header + enterprise number + flags */
                      break;
                  case PCEP_VENDOR_INFO_TYPE_BW:
                      ret += 12; /* tlv header + enterprise number + bw */
                      break;
                  case PCEP_VENDOR_INFO_TYPE_P2MP_TREE_NAME:
                    if (obj->u.vendor.info[i].u.p2mp_tree_name[0]) {
                        /* retrieve size of string (max MAX_SYMB_NAME_SIZE) without \0 */
                        uint16_t idx;
                        for (idx=0; idx < MAX_SYMB_NAME_SIZE; idx++) {
                            if (!obj->u.vendor.info[i].u.p2mp_tree_name[idx])
                                break;
                        }
                        if (idx > MAX_SYMB_NAME_SIZE)
                            idx = MAX_SYMB_NAME_SIZE;
                        ret += 8 + idx + ((idx%PADDING)?PADDING-(idx%PADDING):0);
                    }
                      break;
                  case PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF:
                      /* this is not encoded, hence no-op */
                      break;
                  case PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE:
                      ret += 12; /* tlv header + enterprise number + route_preference */
                      break;
                  case PCEP_VENDOR_INFO_TYPE_UNKNOWN:
                      break;
              }
          }
          return ret;
      case PCEP_OBJ_S2LS:
      case PCEP_OBJ_S2LS_nonIANA:
          return ret + 4;
      case PCEP_OBJ_FLOWSPEC:
          ret += 8; /* flow spec object fixed length */

          if (obj->u.flowspec.fs_tlv_recv & FS_TLV_SPEAKER_ID_RCV_BIT) {
              ret += TLV_HEADER_LEN; /* speaker id tlv header */

              uint16_t datalen= (uint16_t)strlen(obj->u.flowspec.speaker_id);
              size_t padlen = (datalen%4) ? (4 - (datalen%4)) : 0;

              ret += datalen + padlen;
          }

          /* If R bit is set then Flow-Filter TLVs are Optional */
          if (obj->u.flowspec.remove) {
              return ret;
          }

          if (obj->u.flowspec.fs_tlv_recv & FS_TLV_FLOW_FILTER_RCV_BIT) {

              ret += TLV_HEADER_LEN; /* flow filter tlv header */

              if (obj->u.flowspec.lpm) {
                  for(uint8_t i = 0; i < obj->u.flowspec.flow_filter.fs_dst_pfx_cnt;
                          i++) {

                      ret += TLV_HEADER_LEN; /* Destination Prefix TLV Header */

                      if (obj->u.flowspec.AFI == FS_AFI_IPV4) {
                          /* IPv4 Destination Prefix Data */
                          ret += TLV_FLOWSPEC_DEST_PREFIX_V4_FIXED_LEN;
                      } else if(obj->u.flowspec.AFI == FS_AFI_IPV6) {
                          /* IPv6 Destination Prefix Data */
                          ret += TLV_FLOWSPEC_DEST_PREFIX_V6_FIXED_LEN;
                      }
                  }
              } else {
                  ret += TLV_HEADER_LEN; /* flow filter RD tlv header */
                  ret += TLV_FLOWSPEC_RD_FIXED_LEN; /* RD TLV Data*/

                  if (obj->u.flowspec.flow_filter.filter_tlv_recv &
                                    FS_SUBTLV_MC_RCV_BIT) {
                      ret += TLV_HEADER_LEN; /* flow filter IPv4-Mcast tlv header */
                      ret += TLV_FLOWSPEC_MULTICAST_FIXED_LEN; /* IPv4-Mcast TLV Data*/
                  }
              }
          }
          return ret;
    }
    /* We should never get here */
    abort();
}

/**
 * Send the object header
 *
 * @param[in] conn Connection handle
 * @param[in] obj object id
 * @param[in] rule Rule flag
 * @param[in] ignore Ignore flag
 * @param[in] bodylen Body length
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_obj_header (struct pcep_conn *conn, uint16_t obj, bool rule, bool ignore,
                 uint16_t bodylen)
{
    uint8_t obj_class = PCEP_OBJCLASS(obj);
    uint8_t type = (uint8_t)(PCEP_OBJTYPE(obj) << 4);

    if ( PCEP_OBJCLASS_ASSOCIATION_nonRFC == obj_class ) {
        obj_class = PCEP_OBJCLASS_ASSOCIATION;
    }
    if (pcep_send_byte(conn, obj_class))
        return true;

    if (rule)
        type |= 0x02;
    if (ignore)
        type |= 0x01;
    if (pcep_send_byte(conn, type))
        return true;

    return pcep_send_short(conn, bodylen);
}

/**
 * Send the tlv header
 *
 * @param[in] conn Connection handle
 * @param[in] type tlv type
 * @param[in] datalen TLV data length
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_header (struct pcep_conn *conn, uint16_t type, uint16_t datalen)
{
    if (pcep_send_short(conn, type))
        return true;
    if (pcep_send_short(conn, datalen))
        return true;
    return false;
}

/**
 * Send the tlv stateful
 *
 * @param[in] conn Connection handle
 * @param[in] active active stateful flag
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 *
 * RFC 8623 Compliant
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Type=16         |            Length=4           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Flags                 |P|M|N|F|D|T|I|S|U|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static bool
send_tlv_stateful (struct pcep_conn *conn, bool active,  bool lsp_provisioning,
                   bool p2mp_lsp_report_capability, bool p2mp_lsp_update_capability,
                   bool p2mp_lsp_init_capability)
{
    uint32_t flags = 0;
    if (active) flags |= 0x01;
    if (lsp_provisioning) flags |= 0x04;
    if (p2mp_lsp_report_capability) flags |= 0x40;
    if (p2mp_lsp_update_capability) flags |= 0x80;
    if (p2mp_lsp_init_capability) flags |= 0x100;

    if (send_tlv_header(conn, TLV_STATEFUL_PCE_CAPABILITY, 4))
        return true;
    if (pcep_send_uint(conn, flags))
        return true;
    return false;
}

/**
 * Send the tlv sr capability
 *
 * @param[in] conn Connection handle
 * @param[in] msd maximum sid depth
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_sr_capability (struct pcep_conn *conn, uint32_t  msd)
{
    if (send_tlv_header(conn, TLV_SR_PCE_CAPABILITY, 4))
        return true;
    if (pcep_send_short(conn, 0))
        return true;
    if (pcep_send_byte(conn, 0))
        return true;
    if (pcep_send_byte(conn, (msd & 0xFF)))
        return true;
    return false;
}

static bool
send_tlv_pce_flowspec_capability (struct pcep_conn *conn)
{
    const uint8_t padding[3] = {0, 0, 0};

    if (send_tlv_header(conn, TLV_PCE_FLOWSPEC_CAPABILITY,
                        TLV_PCE_FLOWSPEC_CAPABILITY_LEN))
        return true;
    if (pcep_send_short(conn, 0))
        return true;
    /* send padding */
    if (pcep_conn_send(conn, &padding, 2))
        return true;
    return false;
}

static bool
send_tlv_pce_pst_capability (struct pcep_conn *conn, uint32_t  msd, bool spring_capability,
                             bool srv6_capability)
{
    const uint8_t padding[3] = {0, 0, 0};
    uint8_t n_pst = 1;
    uint16_t data_len = 5; /**default case rsvp  only**/

    if (spring_capability || srv6_capability) {
        uint8_t padlen = (data_len%4) ? (4 - (data_len%4)) : 0;
        data_len += padlen;

        if (spring_capability) {
            n_pst++;
            data_len += 8; /** For SR capability sub tlv **/
        }
        if (srv6_capability) {
            n_pst++;
            data_len += 16; /** For SRv6 capability sub tlv **/
        }
    }

    if (send_tlv_header(conn, TLV_PATH_SETUP_TYPE_CAPABILITY,
                        data_len))
        return true;
    if (pcep_send_short(conn, 0))
        return true;
    if (pcep_send_byte(conn, 0))
        return true;
    if (pcep_send_byte(conn, n_pst))
        return true;
        /* sending RSVP PST '0' */
    if (pcep_send_byte(conn, 0))
        return true;

    if (spring_capability) {
        /* sending SR PST '1' */
        if (pcep_send_byte(conn, srcap_pst_type))
            return true;
    }

    if (srv6_capability) {
        /* sending SRv6 PST */
        if (pcep_send_byte(conn, srv6_pst_type))
            return true;
    }

    /* send padding */
    uint8_t padlen = (n_pst%4) ? (4 - (n_pst%4)) : 0;
    if (pcep_conn_send(conn, &padding, padlen))
        return true;

    /* sending SR sub tlv*/
    if (spring_capability) {
        if (send_tlv_header(conn, SUB_TLV_SR_PCE_CAPABILITY, 4))
            return true;
        if (pcep_send_short(conn, 0))
            return true;
        if (pcep_send_byte(conn, 0))
            return true;
        if (pcep_send_byte(conn, (msd & 0xFF)))
            return true;
    }

    if (srv6_capability) {
        if (send_tlv_header(conn, srv6_pce_capability_sub_tlv_type, 12))
            return true;

        /** Send reserved, unassigned flags, flag N, flag X to 0
         * N: 0 ??? PCC is currently not capable of resolving NAI to a SID
         * X: 0 ??? PCC is imposing MSD limit
         */
        if (pcep_send_uint(conn, 0))
            return true;

        //Encode MSD-Types, values
        if (pcep_send_byte(conn, MAX_SL_MSD_TYPE))
            return true;
        if (pcep_send_byte(conn, MAX_SL_MSD_VALUE))
            return true;
        if (pcep_send_byte(conn, MAX_END_POP_MSD_TYPE))
            return true;
        if (pcep_send_byte(conn, MAX_END_POP_MSD_VALUE))
            return true;
        if (pcep_send_byte(conn, MAX_H_ENCAPS_MSD_TYPE))
            return true;
        if (pcep_send_byte(conn, maximum_srv6_segment_list_depth))
            return true;
        if (pcep_send_byte(conn, MAX_END_D_MSD_TYPE))
            return true;
        if (pcep_send_byte(conn, MAX_END_D_MSD_VALUE))
            return true;

    }

    trace(conn, PCEP_TRC_IN_TLVS, "send path setup type capability TLV, data_len = %d",
          data_len);

    return false;
}

/**
 * Send the tlv Speaker Entity Identifier
 *
 * @param[in] conn             Connection handle
 * @param[in] speaker_id       ptr to speaker id
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_speaker_entity_id (struct pcep_conn *conn, const uint8_t* speaker_id)
{
    bool res = false;
    const uint8_t padding[3] = {0, 0, 0};

    uint16_t datalen = (uint16_t)strlen(speaker_id);
    uint8_t padlen = (datalen%4) ? (4 - (datalen%4)) : 0;

    res = send_tlv_header(conn, TLV_NODE_IDENTIFIER, datalen);
    if (res)
        return true;

    res = pcep_conn_send(conn, speaker_id, datalen);
    if (res)
        return true;

    if (padlen) {
        if (pcep_conn_send(conn, padding, padlen))
            return true;
    }
    return false;
}


/**
 * Send the tlv setup type
 *
 * @param[in] conn Connection handle
 * @param[in] lsp_setup_type lsp setup type
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_lsp_setup_type (struct pcep_conn *conn, uint8_t  lsp_setup_type)
{
    if (send_tlv_header(conn, TLV_PATH_SETUP_TYPE, 4))
        return true;
    /* Send 3 reserved bytes */
    if (pcep_send_byte(conn, 0) | pcep_send_byte(conn, 0) | pcep_send_byte(conn, 0))
        return true;
    if (pcep_send_byte(conn, (lsp_setup_type & 0xFF)))
        return true;
   return false;
}

/** Send the tlv binding value
 * @param[in] conn Connection handle
 * @param[in] lsp_setup_type lsp setup type
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_lsp_binding_value(struct pcep_conn *conn,
                           uint8_t binding_type,
                           u_int32_t binding_value,
                           bool flag_r)
{
    uint8_t flags = 0;
    uint16_t length;

    if (0 == binding_type) {
        length = TLV_PATH_BINDING_BT_0_LEN;
    } else if (1 == binding_type) {
        length = TLV_PATH_BINDING_BT_1_LEN;
    } else {
        trace(conn, PCEP_TRC_IN_TLVS, "unsupported binding type: %d",
                binding_type);
        return false;
    }

    if (flag_r)
        flags = (uint8_t)((flags | 0x1) << 7);

    if (send_tlv_header(conn, TLV_TE_PATH_BINDING, length))
        return true;
    if (pcep_send_byte(conn, binding_type))
        return true;
    if (pcep_send_byte(conn, flags))
        return true;
    if (pcep_send_short(conn, 0)) //Reserved
        return true;
    if (pcep_send_uint(conn, binding_value)) //Binding value will be present in 1st 20 bits for BT=0
        return true;

    return false;
}

/* PCE Initiated Bypass : begin */
static bool 
send_tlv_bypass(struct pcep_conn *conn, bool node_prot,
                bool local_prot_in_use, const struct in_addr *byp_ip, float subsc_mul)
{
    const uint8_t padding[3] = {0, 0, 0};
    if (send_tlv_header(conn, TLV_BYPASS, TLV_BYPASS_FIXED_LEN))
        return true;
    if (pcep_conn_send(conn, &padding, 3))
        return true;
    /* send node prot, local prot in use bits */
    if (pcep_send_byte(conn, (node_prot ? 0x01 : 0) 
                              | (local_prot_in_use ? 0x02 : 0)))
        return true;
    if (pcep_conn_send(conn, byp_ip, 4))
        return true;
    if (pcep_send_float(conn, subsc_mul))
        return true;
    return false;
}
/* PCE Initiated Bypass : end */

/**
 * Send multipath capability TLV
 *
 * @param[in] conn Connection handle
 * @param[in] max_computed_segment_list - max segment list value
 * @return true if an error occured
 */
static bool
send_tlv_multipath_capability (struct pcep_conn *conn,
                               uint16_t          max_computed_segment_list)
{
    if (send_tlv_header(conn, TLV_MULTIPATH_CAPABILITY,
                        TLV_MULTIPATH_CAPABILITY_FIXED_LEN)) {
        return true;
    }
    if (pcep_send_short(conn, max_computed_segment_list)) {
        return true;
    }
    if (pcep_send_short(conn, PCEP_DEFAULT_MULTIPATH_FLAGS)) {
        return true;
    }
    return false;
}

/**
 * Junos Version info TLV
 *
 * @param[in] conn Connection handle
 * @return true if an error occured
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Type=655512          |            Length=4            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Major Version        |          Minor Version        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

static bool
send_tlv_version_info (struct pcep_conn *conn)
{
    if (send_tlv_header(conn, TLV_VERSION_INFO,
                        TLV_VERSION_INFO_FIXED_LEN)) {
        return true;
    }
    if (pcep_send_short(conn, sw_version.sw_major)) {
        return true;
    }
    if (pcep_send_short(conn, sw_version.sw_minor)) {
        return true;
    }
    return false;
}



/**
 * Send association type list TLV
 *
 * @param[in] conn Connection handle
 * @param[in] path_protection_assoc is path protection association supported
 * @param[in] srpag_assoc is SRPAG association supported
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_assoc_type_list (struct pcep_conn *conn, bool path_protection_assoc,
                          bool srpag_assoc, bool disjoint_assoc_capability)
{
    uint16_t data_len = 0;
    uint8_t buf[8] = {0,0,0,0,0,0,0,0};
    uint8_t itr = 0;
    size_t padding_len = 0;

    data_len = tlv_assoc_type_list_data_len(path_protection_assoc,
                                            srpag_assoc, disjoint_assoc_capability);
    if (data_len == 0) {
        return false;
    }
    padding_len = ((data_len % 4) != 0) ?
                     (4 - (data_len % 4)) : 0;
    if (send_tlv_header(conn, TLV_ASSOCIATION_TYPE_LIST, data_len))
        return true;

    data_len += padding_len;
    if (path_protection_assoc) {
        buf[itr++] = ((ASSOCIATION_TYPE_PATH_PROTECTION >> 8) & 0xFF);
        buf[itr++] = (ASSOCIATION_TYPE_PATH_PROTECTION & 0xFF);
    }

    if (srpag_assoc) {
        buf[itr++] = ((ASSOCIATION_TYPE_SRPAG >> 8) & 0xFF);
        buf[itr++] = (ASSOCIATION_TYPE_SRPAG & 0xFF);
    }

    if (disjoint_assoc_capability) {
        buf[itr++] = ((ASSOCIATION_TYPE_DISJOINT >> 8) & 0xFF);
        buf[itr++] = (ASSOCIATION_TYPE_DISJOINT & 0xFF);
    }
    if(pcep_conn_send(conn, &buf, data_len))
        return true;

    trace(conn, PCEP_TRC_IN_TLVS, "send assoc type list TLV, data_len = %d",
        data_len);

    return false;
}


/**
 * Send path protection association TLV
 *
 * @param[in] conn Connection handle
 * @param[in] path_protection_assoc is path protection association supported
 * @param[in] srpag_assoc is SRPAG association supported 
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_path_protection_assoc (struct pcep_conn *conn,
                const struct pcep_obj_assoc_path_protection_tlv *tlv)
{
    uint32_t buf = 0;
    if (send_tlv_header(conn, TLV_PATH_PROTECTION_ASSOCIATION,
                            TLV_PATH_PROTECTION_ASSOC_FIXED_LEN))
        return true;

    buf = (((tlv->protection_type << 26) & 0xFC000000) |
            ((tlv->unassigned_flags << 2) & 0x03FFFFFC) |
            ((tlv->flag_secondary << 1) & 0x2) |
            (tlv->flag_protection & 0x1));

    trace(conn, PCEP_TRC_IN_TLVS, "send path protection tlv:"
                "protection type: %u, unassigned flags: %x, "
                "secondary: %u, protection: %u",
                tlv->protection_type, tlv->unassigned_flags,
                tlv->flag_secondary, tlv->flag_protection);
    if(pcep_send_uint(conn, buf))
        return true;

    return false;
}

static bool
send_tlv_disjoint_assoc_conf_tlv (struct pcep_conn                                  *conn,
                                  const struct pcep_obj_disjoint_configuration_tlv  *tlv)
{
    uint32_t buf = 0;

    if (send_tlv_header(conn, TLV_DISJOINT_CONFIGURATION,
                        TLV_DISJOINT_CONFIGURATION_FIXED_LEN)) {
        return true;
    }

    if (tlv->link_disjoint) {
        buf = buf | 0x1;
    }
    if (tlv->node_disjoint) {
        buf = buf | 0x2;
    }
    if (tlv->srlg_disjoint) {
        buf = buf | 0x4;
    }
    if (tlv->shortest_path_flag) {
        buf = buf | 0x8;
    }
    if (tlv->stictness_flag) {
        buf = buf | 0x10;
    }

    trace(conn, PCEP_TRC_IN_TLVS, "sending disjoint config tlv:"
          "link: %u, node: %u, srlg: %u, shortest_path: %u, strictness: %u",
          tlv->link_disjoint, tlv->node_disjoint, tlv->srlg_disjoint,
          tlv->shortest_path_flag, tlv->stictness_flag);

    if (pcep_send_uint(conn, buf)) {
        return true;
    }

    return false;
}

/**
 * Send extended association ID TLV
 *
 * @param[in] conn Connection handle
 * @param[in] path_protection_assoc is path protection association supported
 * @param[in] srpag_assoc is SRPAG association supported
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_extended_assoc_id (struct pcep_conn *conn,
                const struct pcep_obj_asoc_extended_assoc_id_tlv *tlv)
{
    if (tlv->process_as_srpag_tlv) {
        if (tlv->is_srpag_endpoint_ipv6) {
            char srpag_end_point_ipv6[INET6_ADDRSTRLEN]="";

            if (send_tlv_header(conn, TLV_EXTENDED_ASSOCIATION_ID,
                                TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN))
                return true;

            inet_ntop(AF_INET6, &tlv->srpag_endpoint.v6, srpag_end_point_ipv6,
                    sizeof(srpag_end_point_ipv6));

            trace(conn, PCEP_TRC_IN_TLVS, "send extended assoc id tlv for IPv6 SRPAG:"
                    "color: %u, end point: %s",
                    tlv->srpag_color, srpag_end_point_ipv6);

            if (pcep_send_uint(conn, tlv->srpag_color)) {
                return true;
            }
            if (pcep_conn_send(conn, &tlv->srpag_endpoint.v6, 16)) {
                return true;
            }
        } else {
            char srpag_end_point[INET_ADDRSTRLEN]="";

            if (send_tlv_header(conn, TLV_EXTENDED_ASSOCIATION_ID,
                                TLV_EXTENDED_ASSOC_ID_IPV4_SRPAG_FIXED_LEN))
                return true;

            strlcpy(srpag_end_point, inet_ntoa(tlv->srpag_endpoint.v4),
                        sizeof(srpag_end_point));

            trace(conn, PCEP_TRC_IN_TLVS, "send extended assoc id tlv for SRPAG:"
                    "color: %u, end point: %s",
                    tlv->srpag_color, srpag_end_point);

            if (pcep_send_uint(conn, tlv->srpag_color)) {
                return true;
            }
            if (pcep_conn_send(conn, &tlv->srpag_endpoint.v4, 4)) {
                return true;
            }
        }
    } else {
        if (send_tlv_header(conn, TLV_EXTENDED_ASSOCIATION_ID,
                                MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE))
            return true;

        trace(conn, PCEP_TRC_IN_TLVS, "send extended assoc id tlv:"
                "extended assoc id: %u", tlv->extended_assoc_id);

        if (pcep_send_uint(conn, tlv->extended_assoc_id))
            return true;
    }

    return false;
}

/**
 * Send SR Candiate path identifier TLV
 *
 * @param[in] conn Connection handle
 * @param[in] SR Candiate path identifier TLV
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_sr_candidate_path_identifier (struct pcep_conn *conn,
                const struct pcep_obj_sr_candidate_path_identifier_tlv *tlv)
{
    uint32_t buf = 0;
    char originator_address[INET6_ADDRSTRLEN]="";

    if (send_tlv_header(conn, TLV_SR_CANDIDATE_PATH_IDENTIFIER,
                            TLV_SR_CANDIDATE_PATH_IDENTIFIER_FIXED_LEN))
        return true;

    if (tlv->is_originator_address_ipv6) {
        inet_ntop(AF_INET6, &tlv->originator_address.v6, originator_address,
                sizeof(originator_address));
    } else {
        strlcpy(originator_address, inet_ntoa(tlv->originator_address.v4),
                    sizeof(tlv->originator_address.v4));
    }

    trace(conn, PCEP_TRC_IN_TLVS, "send candidate path identifier tlv:"
            "proto origin: %u, originator ASN: %u"
            "originator address: %s, discriminator: %u",
            tlv->proto_origin_, tlv->originator_asn, 
            originator_address, tlv->discriminator);

    buf = ((tlv->proto_origin_) << 24);
    if (pcep_send_uint(conn, buf)) {
        return true;
    }
    if (pcep_send_uint(conn, tlv->originator_asn)) {
        return true;
    }
    if (tlv->is_originator_address_ipv6) {
        if (pcep_conn_send(conn, &tlv->originator_address.v6, 16)) {
            return true;
        }
    } else {
        /* Originator address is represented as 128 bit value, where IPv4 address
         * are encoded in lowest 32 bits */
        if (pcep_send_uint(conn, 0)) {
            return true;
        }
        if (pcep_send_uint(conn, 0)) {
            return true;
        }
        if (pcep_send_uint(conn, 0)) {
            return true;
        }
        if (pcep_conn_send(conn, &tlv->originator_address.v4, 4)) {
            return true;
        }
    }

    if (pcep_send_uint(conn, tlv->discriminator)) {
        return true;
    }

    return false;
}

/**
 * Send SR Preference TLV
 *
 * @param[in] conn Connection handle
 * @param[in] SR Preference TLV
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_tlv_sr_preference (struct pcep_conn *conn,
                const struct pcep_obj_sr_preference_tlv *tlv)
{
    if (send_tlv_header(conn, TLV_SR_PREFERENCE,
                            TLV_SR_PREFERENCE_FIXED_LEN))
        return true;

    trace(conn, PCEP_TRC_IN_TLVS, "send SR Preference tlv:"
            "preference: %u", tlv->preference);

    if (pcep_send_uint(conn, tlv->preference)) {
        return true;
    }

    return false;
}

/**
 * Send the ero sub
 *
 * @param[in] conn Connection handle
 * @param[in] obj ero sub object
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
pcep_send_ero_sub (struct pcep_conn *conn, const struct pcep_obj_ero_sub *obj)
{
    const uint8_t padding[3] = { 0, 0, 0 };
    uint8_t buf = 0;
    
    /* send loose and type */
    if (pcep_send_byte(conn, obj->type | (obj->loose?0x80:0)))
        return true;

    /* send type specific data */
    if (obj->type == srv6_ero_subobject_type) {
        struct pcep_obj_ero_sub_srv6 srv6_ero;
        srv6_ero = obj->data.srv6_ero;

        if (srv6_ero.S_bit && srv6_ero.F_bit) {
            /* Report error and bail out */
            return true;
        }

        /* send length */
        if (pcep_send_byte(conn, (uint8_t)(pcep_obj_ero_srv6_reqlen(srv6_ero)))) {
            return true;
        }

        /* Send nai type */
        if (pcep_send_byte(conn, (uint8_t)((srv6_ero.nai_type & 0x0F) << 4)))
            return true;

        buf = (uint8_t)((buf|srv6_ero.V_bit) << 1);
        buf = (uint8_t)((buf|srv6_ero.T_bit) << 1);
        buf = (uint8_t)((buf|srv6_ero.F_bit) << 1);
        buf =  buf|srv6_ero.S_bit;
        if (pcep_send_byte(conn, buf))
            return true;

        //Reserved is 0
        uint32_t write_uint = srv6_ero.endpoint_behavior;
        if(pcep_send_uint(conn, write_uint)) {
             return true;
         }

        /* Send Segment routing information based on NAI type */
        switch (srv6_ero.nai_type) {
            case PCEP_SR_ERO_NAI_TYPE_ABSENT:

                /* Send sid */
                if (pcep_conn_send(conn, &srv6_ero.sid, 16)) {
                    return true;
                }
                break;
            case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                if (!srv6_ero.S_bit) {
                    /* Send sid */
                    if (pcep_conn_send(conn, &srv6_ero.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_ero.NAI_data.ipv6_node_id.address, 16))
                    return true;
                break;

            case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
                if (!srv6_ero.S_bit) {
                    /* Send sid type information */
                    if (pcep_conn_send(conn, &srv6_ero.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_ero.NAI_data.ipv6_adjacency.local, 16))
                    return true;
                if (pcep_conn_send(conn, &srv6_ero.NAI_data.ipv6_adjacency.remote, 16))
                    return true;
                break;
            case PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                if (!srv6_ero.S_bit) {
                    /* Send sid type information */
                    if (pcep_conn_send(conn, &srv6_ero.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_ero.NAI_data.ipv6_linklocal_adj.local_ipv6_addr, 16))
                    return true;
                if (pcep_send_uint(conn, srv6_ero.NAI_data.ipv6_linklocal_adj.local_interface_id))
                    return true;
                if (pcep_conn_send(conn, &srv6_ero.NAI_data.ipv6_linklocal_adj.remote_ipv6_addr, 16))
                    return true;
                if (pcep_send_uint(conn, srv6_ero.NAI_data.ipv6_linklocal_adj.remote_interface_id))
                    return true;
                break;

            default:
                break;
        }

        if (srv6_ero.T_bit) {
            if(pcep_send_byte(conn, srv6_ero.sid_structure.lb_length))
                return true;
            if(pcep_send_byte(conn, srv6_ero.sid_structure.ln_length))
                return true;
            if(pcep_send_byte(conn, srv6_ero.sid_structure.fun_length))
                return true;
            if(pcep_send_byte(conn, srv6_ero.sid_structure.arg_length))
                return true;
            // Send Reserved + Flag
            if (pcep_send_uint(conn, 0))
                return true;
        }
    } else {
        struct pcep_obj_ero_sub_sr sr_ero;

        switch (obj->type) {
        case PCEP_ERO_SUB_IPV4:
            /* send length */
              if (pcep_send_byte(conn, 8))
                return true;
            if (pcep_conn_send(conn, &obj->data.ipv4_prefix.address, 4))
                return true;
            if (pcep_send_byte(conn, obj->data.ipv4_prefix.prefix_length))
                return true;
            /* send padding */
            if (pcep_conn_send(conn, &padding, 1))
                return true;
            break;
        case PCEP_ERO_SUB_IPV6:
            /* send length */
              if (pcep_send_byte(conn, 20))
                return true;
            if (pcep_conn_send(conn, &obj->data.ipv6_prefix.address, 16))
                return true;
            if (pcep_send_byte(conn, obj->data.ipv6_prefix.prefix_length))
                return true;
            /* send padding */
            if (pcep_conn_send(conn, &padding, 1))
                return true;
            break;
        case PCEP_ERO_SUB_LABEL:
            /* send length */
            if (pcep_send_byte(conn, 8))
                return true;
            /* send flags */
            if (pcep_send_byte(conn, obj->data.label.upstream?0x80:0))
                return true;
            if (pcep_send_byte(conn, obj->data.label.ctype))
                return true;
            if (pcep_send_uint(conn, obj->data.label.label))
                return true;
            /* no padding */
            break;
        case PCEP_ERO_SUB_UNNUMBERED_IID:
            /* send length */
            if (pcep_send_byte(conn, 12))
                return true;
            /* send padding */
            if (pcep_conn_send(conn, &padding, 2))
                return true;
            /* send ids */
            if (pcep_conn_send(conn, &obj->data.unnumbered_iid.router_id, 4))
                return true;
            if (pcep_send_uint(conn, obj->data.unnumbered_iid.interface_id))
                return true;
            /* no padding */
            break;
        case PCEP_ERO_SUB_AUTONOMOUS:
            /* send length */
            if (pcep_send_byte(conn, 4))
                return true;
            if (pcep_send_short(conn, obj->data.autonomous.system_number))
                return true;
            /* no padding */
            break;
        case PCEP_ERO_SUB_SR:
            sr_ero = obj->data.sr_ero;

            if (sr_ero.S_bit && sr_ero.F_bit) {
                /* Report error and bail out */
                return true;
            }
            /* Send Segment routing information based on NAI type */
            switch (sr_ero.nai_type) {
                case PCEP_SR_ERO_NAI_TYPE_ABSENT:
                    if (pcep_send_byte(conn, 8)) {
                        return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, (uint8_t)((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (uint8_t)((buf|sr_ero.F_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.S_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.C_bit) << 1);
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (pcep_send_uint(conn, sr_ero.sid)) {
                        return true;
                    }
                    break;
               case PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID:
                    /* send length */
                    if ((!sr_ero.S_bit) && (!sr_ero.F_bit)) {
                        if (pcep_send_byte(conn, 12))
                            return true;
                    } else {
                        if (pcep_send_byte(conn, 8))
                            return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, (uint8_t)((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (uint8_t)((buf|sr_ero.F_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.S_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.C_bit) << 1);
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (!sr_ero.S_bit) {
                        if (pcep_send_uint(conn, sr_ero.sid))
                            return true;
                    }
                    if (!sr_ero.F_bit) {
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv4_node_id.address, 4))
                            return true;
                    }
                    break;
#ifdef PCEP_SR_IPV6
                case PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID:
                    /* send length */
                    if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                        if (pcep_send_byte(conn, 8))
                            return true;
                    } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                        if (pcep_send_byte(conn, 20))
                            return true;
                    } else {
                        if (pcep_send_byte(conn, 24))
                            return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, ((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (buf|sr_ero.F_bit) << 1;
                    buf = (buf|sr_ero.S_bit) << 1;
                    buf = (buf|sr_ero.C_bit) << 1;
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (!sr_ero.S_bit) {
                        if (pcep_send_uint(conn, sr_ero.sid))
                            return true;
                    }
                    if (!sr_ero.F_bit) {
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv6_node_id.address, 16))
                            return true;
                    }
                    break;
#endif
                case PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ:
                     /* send length */
                    if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                        if (pcep_send_byte(conn, 8))
                            return true;
                    } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                        if (pcep_send_byte(conn, 12))
                            return true;
                    } else {
                        if (pcep_send_byte(conn, 16))
                            return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, (uint8_t)((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (uint8_t)((buf|sr_ero.F_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.S_bit) << 1);
                    buf = (uint8_t)((buf|sr_ero.C_bit) << 1);
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (!sr_ero.S_bit) {
                        if (pcep_send_uint(conn, sr_ero.sid))
                            return true;
                    }
                    if (!sr_ero.F_bit) {
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv4_adjacency.local, 4))
                            return true;
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv4_adjacency.remote, 4))
                            return true;
                    }
                    break;
#ifdef PCEP_SR_IPV6
                case PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ:
                    /* send length */
                    if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                        if (pcep_send_byte(conn, 8))
                            return true;
                    } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                        if (pcep_send_byte(conn, 36))
                            return true;
                    } else {
                        if (pcep_send_byte(conn, 40))
                            return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, ((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (buf|sr_ero.F_bit) << 1;
                    buf = (buf|sr_ero.S_bit) << 1;
                    buf = (buf|sr_ero.C_bit) << 1;
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (!sr_ero.S_bit) {
                        if (pcep_send_uint(conn, sr_ero.sid))
                            return true;
                    }
                    if (!sr_ero.F_bit) {
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv6_adjacency.local, 16))
                            return true;
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.ipv6_adjacency.remote, 16))
                            return true;
                    }
                    break;
#endif
#ifdef PCEP_SR_UNNUMBERED
                case PCEP_SR_ERO_NAI_TYPE_UNNUMBERED:
                    /* send length */
                    if ((!sr_ero.S_bit) && (sr_ero.F_bit)) {
                        if (pcep_send_byte(conn, 8))
                            return true;
                    } else if ((sr_ero.S_bit) && (!sr_ero.F_bit))  {
                        if (pcep_send_byte(conn, 20))
                            return true;
                    } else {
                        if (pcep_send_byte(conn, 24))
                            return true;
                    }
                    /* Send nai type */
                    if (pcep_send_byte(conn, ((sr_ero.nai_type & 0x0F) << 4)))
                        return true;

                    buf = (buf|sr_ero.F_bit) << 1;
                    buf = (buf|sr_ero.S_bit) << 1;
                    buf = (buf|sr_ero.C_bit) << 1;
                    buf =  buf|sr_ero.M_bit;
                    if (pcep_send_byte(conn, buf))
                        return true;
                    /* Send sid type information */
                    if (!sr_ero.S_bit) {
                        if (pcep_send_uint(conn, sr_ero.sid))
                            return true;
                    }
                    if (!sr_ero.F_bit) {
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.unnum_adj.local_node_id, 4))
                            return true;
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.unnum_adj.local_interface_id, 4))
                            return true;
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.unnum_adj.remote_node_id, 4))
                            return true;
                        if (pcep_conn_send(conn, &sr_ero.NAI_data.unnum_adj.remote_interface_id, 4))
                            return true;
                    }
                    break;
#endif
                default:
                    break;
            }
                break;
            default:
                break;
        }
    }
    return false;
}

/**
 * Send the rro sub
 *
 * @param[in] conn Connection handle
 * @param[in] obj rro sub object
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
pcep_send_rro_sub (struct pcep_conn *conn, const struct pcep_obj_rro_sub *obj)
{
    const uint8_t padding[3] = { 0, 0, 0 };
    uint8_t buf = 0;
    struct pcep_obj_rro_sub_sr sr_rro;
    /* send type */
    if (pcep_send_byte(conn, obj->type))
        return true;


    /* send type specific data */
    if (obj->type == srv6_rro_subobject_type) {
        struct pcep_obj_rro_sub_srv6 srv6_rro;
        srv6_rro = obj->data.srv6_rro;

        if (srv6_rro.S_bit && srv6_rro.F_bit) {
            /* Report error and bail out */
            return true;
        }

        /* send length */
        if (pcep_send_byte(conn, (uint8_t)(pcep_obj_rro_srv6_reqlen(srv6_rro)))) {
            return true;
        }
        /* Send nai type */
        if (pcep_send_byte(conn, (uint8_t)((srv6_rro.nai_type & 0x0F) << 4)))
            return true;

        buf = (uint8_t)((buf|srv6_rro.V_bit) << 1);
        buf = (uint8_t)((buf|srv6_rro.T_bit) << 1);
        buf = (uint8_t)((buf|srv6_rro.F_bit) << 1);
        buf =  buf|srv6_rro.S_bit;
        if (pcep_send_byte(conn, buf))
            return true;

        //Reserved is 0
        uint32_t write_uint = srv6_rro.endpoint_behavior;
        if(pcep_send_uint(conn, write_uint)) {
            return true;
        }

        /* Send Segment routing information based on NAI type */
        switch (srv6_rro.nai_type) {
            case PCEP_SR_RRO_NAI_TYPE_ABSENT:
                /* Send sid */
                if (pcep_conn_send(conn, &srv6_rro.sid, 16)) {
                    return true;
                }
                break;
            case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
                if (!srv6_rro.S_bit) {
                    /* Send sid */
                    if (pcep_conn_send(conn, &srv6_rro.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_rro.NAI_data.ipv6_node_id.address, 16))
                    return true;
                break;

            case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
                if (!srv6_rro.S_bit) {
                    /* Send sid */
                    if (pcep_conn_send(conn, &srv6_rro.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_rro.NAI_data.ipv6_adjacency.local, 16))
                    return true;
                if (pcep_conn_send(conn, &srv6_rro.NAI_data.ipv6_adjacency.remote, 16))
                    return true;
                break;
            case PCEP_SR_RRO_NAI_TYPE_IPV6_LINKLOCAL_ADJ:
                if (!srv6_rro.S_bit) {
                    /* Send sid */
                    if (pcep_conn_send(conn, &srv6_rro.sid, 16))
                        return true;
                }
                if (pcep_conn_send(conn, &srv6_rro.NAI_data.ipv6_linklocal_adj.local_ipv6_addr, 16))
                    return true;
                if (pcep_send_uint(conn, srv6_rro.NAI_data.ipv6_linklocal_adj.local_interface_id))
                    return true;
                if (pcep_conn_send(conn, &srv6_rro.NAI_data.ipv6_linklocal_adj.remote_ipv6_addr, 16))
                    return true;
                if (pcep_send_uint(conn, srv6_rro.NAI_data.ipv6_linklocal_adj.remote_interface_id))
                    return true;
                break;

            default:
                break;
        }

        if (srv6_rro.T_bit) {
            if(pcep_send_byte(conn, srv6_rro.sid_structure.lb_length))
                return true;
            if(pcep_send_byte(conn, srv6_rro.sid_structure.ln_length))
                return true;
            if(pcep_send_byte(conn, srv6_rro.sid_structure.fun_length))
                return true;
            if(pcep_send_byte(conn, srv6_rro.sid_structure.arg_length))
                return true;
            // Send Reserved + Flag
            if (pcep_send_uint(conn, 0))
                return true;
        }
    } else {
    /* send type specific data */
    switch (obj->type) {
    case PCEP_RRO_SUB_IPV4:
        /* send length */
        if (pcep_send_byte(conn, 8))
            return true;
        if (pcep_conn_send(conn, &obj->data.ipv4_address.address, 4))
            return true;
        if (pcep_send_byte(conn, 32))
            return true;
        /* send flags */
        if (pcep_send_byte(conn, (obj->data.ipv4_address.flags)))
            return true;
        break;
    case PCEP_RRO_SUB_IPV6:
        /* send length */
        if (pcep_send_byte(conn, 20))
            return true;
        if (pcep_conn_send(conn, &obj->data.ipv6_address.address, 16))
            return true;
        if (pcep_send_byte(conn, 128))
            return true;
        /* send flags */
        if (pcep_send_byte(conn, (obj->data.ipv6_address.flags)))
            return true;
        break;
    case PCEP_RRO_SUB_LABEL:
        /* send length */
        if (pcep_send_byte(conn, 8))
            return true;
        /* send flags */
        if (pcep_send_byte(conn, (obj->data.label.upstream?0x80:0) |
                           (obj->data.label.global_label?0x01:0)))
            return true;
        if (pcep_send_byte(conn, obj->data.label.ctype))
            return true;
        if (pcep_send_uint(conn, obj->data.label.label))
            return true;
        /* no padding */
        break;
    case PCEP_RRO_SUB_UNNUMBERED_IID:
        /* send length */
        if (pcep_send_byte(conn, 12))
            return true;
        /* send padding */
        if (pcep_conn_send(conn, &padding, 2))
            return true;
        /* send ids */
        if (pcep_conn_send(conn, &obj->data.unnumbered_iid.router_id, 4))
            return true;
        if (pcep_send_uint(conn, obj->data.unnumbered_iid.interface_id))
            return true;
        /* no padding */
        break;
    case PCEP_RRO_SUB_SR:
        sr_rro = obj->data.sr_rro;

        if (sr_rro.S_bit && sr_rro.F_bit) {
            /* Report error and bail out */
            return true;
        }
        /* Send Segment routing information based on SID type */
        switch (sr_rro.nai_type) {
            case PCEP_SR_ERO_NAI_TYPE_ABSENT:
                /* send length */
                if (pcep_send_byte(conn, 8))
                    return true;

                /* Send nai type */
                if (pcep_send_byte(conn, (uint8_t)((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                buf = (buf|sr_rro.C_bit) << 1;
                buf =  buf|sr_rro.M_bit;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (pcep_send_uint(conn, sr_rro.sid))
                    return true;
                
                break;
           case PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID:
                /* send length */
                if ((!sr_rro.S_bit) && (!sr_rro.F_bit)) {
                    if (pcep_send_byte(conn, 12))
                        return true;
                } else {
                    if (pcep_send_byte(conn, 8))
                        return true;
                }
                /* Send nai type */
                if (pcep_send_byte(conn, (uint8_t)((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                buf = (buf|sr_rro.C_bit) << 1;
                buf =  buf|sr_rro.M_bit;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (!sr_rro.S_bit) {
                    if (pcep_send_uint(conn, sr_rro.sid))
                        return true;
                }
                if (!sr_rro.F_bit) {
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv4_node_id.address, 4))
                        return true;
                }
                break;
#ifdef PCEP_SR_IPV6
            case PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID:
                /* send length */
                if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                    if (pcep_send_byte(conn, 8))
                        return true;
                } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                    if (pcep_send_byte(conn, 20))
                        return true;
                } else {
                    if (pcep_send_byte(conn, 24))
                        return true;
                }
                /* Send nai type */
                if (pcep_send_byte(conn, ((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (!sr_rro.S_bit) {
                    if (pcep_conn_send(conn, &sr_rro.sid, 4))
                        return true;
                }
                if (!sr_rro.F_bit) {
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv6_node_id.address, 16))
                        return true;
                }
                break;
#endif
            case PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ:
                 /* send length */
                if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                    if (pcep_send_byte(conn, 8))
                        return true;
                } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                    if (pcep_send_byte(conn, 12))
                        return true;
                } else {
                    if (pcep_send_byte(conn, 16))
                        return true;
                }  
                /* Send nai type */
                if (pcep_send_byte(conn, (uint8_t)((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                buf = (buf|sr_rro.C_bit) << 1;
                buf =  buf|sr_rro.M_bit;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (!sr_rro.S_bit) {
                    if (pcep_send_uint(conn, sr_rro.sid))
                        return true;
                }
                if (!sr_rro.F_bit) {
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv4_adjacency.local, 4))
                        return true;
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv4_adjacency.remote, 4))
                        return true;
                }  
                break;
#ifdef PCEP_SR_IPV6
            case PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ:
                /* send length */
                if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                    if (pcep_send_byte(conn, 8))
                        return true;
                } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                    if (pcep_send_byte(conn, 36))
                        return true;
                } else {
                    if (pcep_send_byte(conn, 40))
                        return true;
                }  
                /* Send nai type */
                if (pcep_send_byte(conn, ((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (!sr_rro.S_bit) {
                    if (pcep_conn_send(conn, &sr_rro.sid, 4))
                        return true;
                }
                if (!sr_rro.F_bit) {
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv6_adjacency.local, 16))
                        return true;
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.ipv6_adjacency.remote, 16))
                        return true;
                }  
                break;
#endif
#ifdef PCEP_SR_UNNUMBERED
            case PCEP_SR_RRO_NAI_TYPE_UNNUMBERED:
                /* send length */
                if ((!sr_rro.S_bit) && (sr_rro.F_bit)) {
                    if (pcep_send_byte(conn, 8))
                        return true;
                } else if ((sr_rro.S_bit) && (!sr_rro.F_bit))  {
                    if (pcep_send_byte(conn, 20))
                        return true;
                } else {
                    if (pcep_send_byte(conn, 24))
                        return true;
                }  
                /* Send nai type */
                if (pcep_send_byte(conn, ((sr_rro.nai_type & 0x0F) << 4)))
                    return true;

                buf = (buf|sr_rro.F_bit) << 1;
                buf = (buf|sr_rro.S_bit) << 1;
                if (pcep_send_byte(conn, buf))
                    return true;
                /* Send sid type information */
                if (!sr_rro.S_bit) {
                    if (pcep_conn_send(conn, &sr_rro.sid, 4))
                        return true;
                }  
                if (!sr_rro.F_bit) {
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.unnum_adj.local_node_id, 4))
                        return true;
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.unnum_adj.local_interface_id, 4))
                        return true;
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.unnum_adj.remote_node_id, 4))
                        return true;
                    if (pcep_conn_send(conn, &sr_rro.NAI_data.unnum_adj.remote_interface_id, 4))
                        return true;
                }
                break;
#endif
            default:
                break;
        }
            break;
        default:
            break;
    }
    }
    return false;
}

/**
 * Send the pcep object flowspec
 *
 * @param[in] conn Connection handle
 * @param[in] obj object type
 * @param[in] obj_body object body
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_pcep_obj_flowspec (struct pcep_conn *conn, const void *obj_body)
{
    const struct pcep_obj_flowspec *o = obj_body;
    uint16_t reserved = 0;
    uint32_t fs_id =  o->fs_id;
    bool res = false;
    uint16_t datalen = 0;
    uint8_t padding[3] = {0, 0, 0};

    res = pcep_send_uint(conn, fs_id);
    if (res)
        return true;

    res = pcep_send_short(conn, o->AFI);
    if (res)
        return true;

    reserved = (uint16_t)(reserved | (o->remove) | (o->lpm << 0x1));
    res = pcep_send_short(conn, reserved);
    if (res)
        return true;

    if (o->fs_tlv_recv & FS_TLV_SPEAKER_ID_RCV_BIT) {
        /* Send TLV Speaker Entity Identifier */
        send_tlv_speaker_entity_id(conn, o->speaker_id);
    }

    /* If R bit is set then Flow-Filter TLVs are Optional */
    if (o->remove)
        return false;

    if (!o->lpm) { // Multicast Flow type
        datalen += TLV_HEADER_LEN + TLV_FLOWSPEC_MULTICAST_FIXED_LEN;
        datalen += TLV_HEADER_LEN + TLV_FLOWSPEC_RD_FIXED_LEN;    

        /* Send FlowSpec Flow Filter TLV */ 
        res = send_tlv_header(conn, TLV_FLOWSPEC_FLOWFILTER, datalen);


        /* Send FlowSpec Multicast TLV */ 
        res = send_tlv_header(conn, TLV_FLOWSPEC_MULTICAST,
                              TLV_FLOWSPEC_MULTICAST_FIXED_LEN);
        if (res)
            return true;

        res = pcep_send_short(conn, o->flow_filter.fs_mc.flags);
        if (res)
            return true;

        res = pcep_send_byte(conn, o->flow_filter.fs_mc.src_len);
        if (res)
            return true;

        res = pcep_send_byte(conn, o->flow_filter.fs_mc.mgp_len);
        if (res)
            return true;

        res = pcep_conn_send(conn, &o->flow_filter.fs_mc.source_prefix, 4);
        if (res)
            return true;

        res = pcep_conn_send(conn, &o->flow_filter.fs_mc.multi_group_prefix, 4);
        if (res)
            return true;

        /* Send FlowSpec Route Distinguisher TLV */
        res = send_tlv_header(conn, TLV_FLOWSPEC_ROUTE_DISTINGUISER,
                              TLV_FLOWSPEC_RD_FIXED_LEN);
        if (res)
            return true;

        res = pcep_send_uint(conn, o->flow_filter.fs_rd.rd_upper);
        if (res)
            return true;

        res = pcep_send_uint(conn, o->flow_filter.fs_rd.rd_lower);
        if (res)
            return true;

    } else {
        if (o->flow_filter.fs_dst_pfx_cnt > MAX_PREFIX_SUPPORTED_PER_FLOWSPEC) {
            log_error(get_pcep(conn), "Maximum of %u Prefix supported per Flowspec object",
                                MAX_PREFIX_SUPPORTED_PER_FLOWSPEC);
            return true;
        }

        if (o->AFI == FS_AFI_IPV4) {
            datalen = o->flow_filter.fs_dst_pfx_cnt*
                        (TLV_HEADER_LEN + TLV_FLOWSPEC_DEST_PREFIX_V4_FIXED_LEN);
        } else if(o->AFI == FS_AFI_IPV6) {
            datalen = o->flow_filter.fs_dst_pfx_cnt*
                        (TLV_HEADER_LEN + TLV_FLOWSPEC_DEST_PREFIX_V6_FIXED_LEN);
        }

        /* Send FlowSpec Flow Filter TLV */
        res = send_tlv_header(conn, TLV_FLOWSPEC_FLOWFILTER, datalen);
        if (res)
            return true;

        for (uint8_t cnt = 0; cnt < o->flow_filter.fs_dst_pfx_cnt; cnt++) {
            /* Send FlowSpec Destination Prefix TLVs */
            if (o->AFI == FS_AFI_IPV4) {
                res = send_tlv_header(conn, TLV_FLOWSPEC_DEST_PREFIX,
                                      TLV_FLOWSPEC_DEST_PREFIX_V4_FIXED_LEN);
                if (res)
                    return true;

                res = pcep_send_byte(conn, o->flow_filter.fs_dst_pfx[cnt].mask);
                if (res)
                    return true;

                res = pcep_send_uint(conn,
                            o->flow_filter.fs_dst_pfx[cnt].prefix.v4.s_addr);
                if (res)
                    return true;

            } else if(o->AFI == FS_AFI_IPV6) {
                res = send_tlv_header(conn, TLV_FLOWSPEC_DEST_PREFIX,
                                      TLV_FLOWSPEC_DEST_PREFIX_V6_FIXED_LEN);
                if (res)
                    return true;

                res = pcep_send_byte(conn, o->flow_filter.fs_dst_pfx[cnt].mask);
                if (res)
                    return true;

                res = pcep_conn_send(conn, &o->flow_filter.fs_dst_pfx[cnt].prefix.v6, 16);
                if (res)
                    return true;
            }

            res = pcep_conn_send(conn, padding, 3);
            if (res)
                return true;

        }
    }

    return res;
}

/**
 * Send the object body
 *
 * @param[in] conn Connection handle
 * @param[in] obj object type
 * @param[in] obj_body object body
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
send_obj_body (struct pcep_conn *conn, uint16_t obj, const void *obj_body)
{
    switch (obj) {
    case PCEP_OBJ_BANDWIDTH_REOPTIM:
    case PCEP_OBJ_BANDWIDTH_REQUEST:
        {
            const struct pcep_obj_bandwidth *o = obj_body;
            return pcep_send_float(conn, o->bps);
        }
    case PCEP_OBJ_CLOSE:
        {
            const struct pcep_obj_close *o = obj_body;
            /* Reserved field: send 0 */
            if (pcep_send_short(conn, 0))
                return true;
            /* Flags field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            if (pcep_send_byte(conn, o->reason))
                return true;
            return false;
        }
    case PCEP_OBJ_ENDPOINTS_IPV4:
        {
            const struct pcep_obj_endpoints_ipv4 *o = obj_body;
            if (pcep_conn_send(conn, &o->source, 4))
                return true;
            if (pcep_conn_send(conn, &o->destination, 4))
                return true;
            return false;
        }
    case PCEP_OBJ_ENDPOINTS_IPV6:
        {
            const struct pcep_obj_endpoints_ipv6 *o = obj_body;
            if (pcep_conn_send(conn, &o->source, 16))
                return true;
            if (pcep_conn_send(conn, &o->destination, 16))
                return true;
            return false;
        }
    case PCEP_OBJ_P2MP_ENDPOINTS_IPV4:
        {
            const struct pcep_obj_p2mp_endpoints_ipv4 *o = obj_body;
            uint32_t flag =  o->leaftype ;
            uint8_t sub = 0;

            if (pcep_send_uint(conn, flag))
                return true;
            if (pcep_conn_send(conn, &o->source, 4))
                return true;
            while (sub < o->subcount) {
                if (pcep_conn_send(conn, &o->destinations[sub++], 4))
                    return true;
            }
            return false;
        }

    case PCEP_OBJ_P2MP_ENDPOINTS_IPV6:
        {
            const struct pcep_obj_p2mp_endpoints_ipv6 *o = obj_body;
            uint32_t flag =  o->leaftype;
            uint8_t sub=0;

            if (pcep_send_uint(conn, flag))
                return true;
            if (pcep_conn_send(conn, &o->source, 16))
                return true;
            while (sub < o->subcount) {
                if (pcep_conn_send(conn, &o->destinations, 16))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_LOADBALANCING:
        {
            const struct pcep_obj_loadbalancing *o = obj_body;
            /* Reserved field: send 0 */
            if (pcep_send_short(conn, 0))
                return true;
            /* Flags field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            if (pcep_send_byte(conn, o->max_lsp))
                return true;
            if (pcep_send_float(conn, o->min_bandwidth))
                return true;
            return false;
        }
    case PCEP_OBJ_LSP:
        {
            const struct pcep_obj_lsp *o = obj_body;
            uint8_t buf = 0;
            if (pcep_send_byte(conn, o->plsp_id >> 12))
                return true;
            if (pcep_send_byte(conn, o->plsp_id >> 4))
                return true;

            buf = (uint8_t)((o->plsp_id & 0x0F) << 4);
            buf |= o->fragment << 1;
            buf |= o->p2mp_branch;
            if (pcep_send_byte(conn, buf))
                return true;
            /* Flag bits are assumed 0 */
            buf = 0;
            buf |= o->pce_created << 7;
            buf |= o->operational << 4;
            buf |= o->administrative << 3;
            buf |= o->remove       << 2;
            buf |= o->last_update  << 1;
            buf |= o->delegated;
            if (pcep_send_byte(conn, buf))
                return true;
            if (o->symbolic_name[0]) {
                uint16_t datalen = strlen(o->symbolic_name);
                uint8_t padlen = (datalen%4) ? 4 - (datalen%4):0;
                if (send_tlv_header(conn, TLV_LSP_SYMBOLIC_NAME, datalen))
                    return true;
                if (pcep_conn_send(conn, o->symbolic_name, datalen))
                    return true;
                if (padlen) {
                    uint8_t padding[3] = {0, 0, 0};
                    if (pcep_conn_send(conn, padding, padlen))
                        return true;
                }
            }
            if (o->errspec_len) {
                tlv_type_t tt;
                if (o->errspec_len == TLV_IPV4_RSVP_ERROR_SPEC_FIXED_LEN)
                    tt = TLV_IPV4_RSVP_ERROR_SPEC;
                else if (o->errspec_len == TLV_IPV6_RSVP_ERROR_SPEC_FIXED_LEN)
                    tt = TLV_IPV6_RSVP_ERROR_SPEC;
                else {
                    log_error(get_pcep(conn), "Passed ERROR_SPEC buffer length "
                              "invalid: %u", o->errspec_len);
                    return true;
                }

		/* 
                 * Add LSP-UPDATE-ERROR-CODE when ERR-SPEC is present
                 */
		if (send_tlv_header(conn, TLV_LSP_UPDATE_ERROR_CODE, 4))
		    return true;
		// send the error code for sending RSVP errspec
		if (pcep_send_uint(conn, LSP_ERR_CODE_RSVP_SIGNAL_ERROR))
		    return true;

                if (send_tlv_header(conn, tt, o->errspec_len))
                    return true;
                if (pcep_conn_send(conn, o->errspec, o->errspec_len))
                    return true;
            }

            if (o->lsp_identifiers_len) {
                tlv_type_t tt;
                if (o->lsp_identifiers_len == 16) {
                    if (o->p2mp_branch) {
                        tt = TLV_IPV4_P2MP_LSP_IDENTIFIERS;
                    } else {
                        tt = TLV_IPV4_LSP_IDENTIFIERS;
                    }
                }else if (o->lsp_identifiers_len == 52){
                    if (o->p2mp_branch) {
                        tt = TLV_IPV6_P2MP_LSP_IDENTIFIERS;
                    } else {
                        tt = TLV_IPV6_LSP_IDENTIFIERS;
                    }
                } else {
                    log_error(get_pcep(conn), "Passed LSP_IDENTIFIERS buffer length "
                              "invalid: %u", o->lsp_identifiers_len);
                    return true;
                }
                if (send_tlv_header(conn, tt, o->lsp_identifiers_len))
                    return true;
                if (pcep_conn_send(conn, o->lsp_identifiers, o->lsp_identifiers_len))
                    return true;
            }
            if (o->propagate_max_segment_list) {
                if (send_tlv_multipath_capability(conn, o->max_segment_list))
                    return true;
            }

            for (int count = 0; count < MAX_PATH_BINDING_TLVS; count++) {
                if (o->path_binding[count].mpls_label_binding_value) {
                    if (send_tlv_lsp_binding_value(conn, o->path_binding[count].binding_type,
                            o->path_binding[count].mpls_label_binding_value,
                            o->path_binding[count].flag_r)) {
                        return true;
                    }
                }
            }

            return false;
        }
    case PCEP_OBJ_LSPA:
        {
            const struct pcep_obj_lspa *o = obj_body;
            uint8_t buf = o->local_prot;
            if (pcep_send_uint(conn, o->pol_exclude_any))
                return true;
            if (pcep_send_uint(conn, o->pol_include_any))
                return true;
            if (pcep_send_uint(conn, o->pol_include_all))
                return true;
            if (pcep_send_byte(conn, o->setup_prio))
                return true;
            if (pcep_send_byte(conn, o->hold_prio))
                return true;
            if (pcep_send_byte(conn, buf))
                return true;
            /* Reserved field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            /* PCE Initiated Bypass : begin */            
            if (o->bypass_tlv) {
                if (send_tlv_bypass(conn, o->node_prot, o->local_prot_in_use,
                                    &(o->bypadd_ipv4_addr), o->subsc_mul))
                    return true;
            }
            /* PCE Initiated Bypass : end */
            return false;
        }
    case PCEP_OBJ_METRIC:
        {
            const struct pcep_obj_metric *o = obj_body;
            uint8_t buf = (o->computed << 1) | o->bound;
            /* Reserved field: send 0 */
            if (pcep_send_short(conn, 0))
                return true;
            if (pcep_send_byte(conn, buf))
                return true;
            if (pcep_send_byte(conn, o->type))
                return true;
            if (pcep_send_float(conn, o->value))
                return true;
            return false;
        }
    case PCEP_OBJ_NOPATH:
        {
            const struct pcep_obj_nopath *o = obj_body;
            uint8_t buf = o->constraints << 15;
            if (pcep_send_byte(conn, o->issue))
                return true;
            /* Constraints + flags byte */
            if (pcep_send_byte(conn, buf))
                return true;
            /* Flags byte: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            /* Reserved field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            return false;
        }
    case PCEP_OBJ_NOTIFICATION:
        {
            const struct pcep_obj_notification *o = obj_body;
            /* Reserved field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            /* Flags field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            if (pcep_send_byte(conn, o->type))
                return true;
            if (pcep_send_byte(conn, o->value))
                return true;
            if (o->overloaded_duration) {
                if (send_tlv_header(conn, TLV_OVERLOADED_DURATION, 4))
                    return true;
                if (pcep_send_uint(conn, o->overloaded_duration))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_OPEN:
        {
            const struct pcep_obj_open *o = obj_body;
            /* Version = 1, Flags = 0 */
            if (pcep_send_byte(conn, 0x20))
                return true;
            if (pcep_send_byte(conn, o->keepalive))
                return true;
            if (pcep_send_byte(conn, o->deadtimer))
                return true;
            if (pcep_send_byte(conn, o->session_id))
                return true;
            if (o->stateful && send_tlv_stateful(conn, o->active,
                                                 o->lsp_provisioning,
                                                 o->p2mp_lsp_report_capability,
                                                 o->p2mp_lsp_update_capability,
                                                 o->p2mp_lsp_init_capability))
                return true;
            if (send_tlv_pce_pst_capability(conn, o->msd, o->spring_capability, o->srv6_capability))
                return true;
            if (o->spring_capability && send_tlv_sr_capability(conn, o->msd))
                return true;
            if (o->pce_flowspec_capability && send_tlv_pce_flowspec_capability(conn))
                return true;
            if (send_tlv_assoc_type_list (conn, o->path_protection_association,
                                          o->srpag_association,
                                          o->disjoint_assoc_capability))
                return true;
            if (o->multipath_capability && 
                send_tlv_multipath_capability(conn, PCEP_MAX_COMPUTED_SEGMENT_LIST)) {
                return true;
            }
	    if (send_tlv_version_info(conn))
		return true;
            return false;
        }
    case PCEP_OBJ_PCEPERROR:
        {
            const struct pcep_obj_error *o = obj_body;
            /* Reserved field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            /* Flags field: send 0 */
            if (pcep_send_byte(conn, 0))
                return true;
            if (pcep_send_byte(conn, o->type))
                return true;
            if (pcep_send_byte(conn, o->value))
                return true;
            return false;
        }
    case PCEP_OBJ_RP:
        {
            const struct pcep_obj_rp *o = obj_body;
            uint8_t buf = (o->loose << 5) | (o->bidirectional << 4) |
                          (o->reoptimization << 3) | (o->priority);
            /* Send 3 empty flag bytes */
            if (pcep_send_byte(conn, 0) || pcep_send_byte(conn, 0)
                || pcep_send_byte(conn, 0))
                return true;
            if (pcep_send_byte(conn, buf))
                return true;
            if (pcep_send_uint(conn, o->request_id))
                return true;
            if (send_tlv_lsp_setup_type(conn, o->lsp_setup_type))
                return true;
            return false;
        }
    case PCEP_OBJ_PATH_ATTRIBUTE:
        {
            const struct pcep_obj_path_attribute *o = obj_body;
            if (pcep_send_uint(conn, o->op_state))
                return true;
            if (pcep_send_uint(conn, o->path_id))
                return true;
            if (send_tlv_header(conn, TLV_MULTIPATH_WEIGHT,
                                TLV_MULTIPATH_WEIGHT_FIXED_LEN))
                return true;
            if (pcep_send_uint(conn, o->weight)) {
                return true;
            }
            if (o->secondary_path) {
                if (send_tlv_header(conn, TLV_MULTIPATH_BACKUP,
                                    TLV_MULTIPATH_BACKUP_LEN)) {
                    return true;
                }
                if (pcep_send_short(conn, 0)) {
                    return true;
                }
                if (pcep_send_short(conn, PCEP_PATH_ATTRIBUTE_DEFAULT_BACKUP_FLAG)) {
                    return true;
                }
            }
            return false;
        }
    case PCEP_OBJ_ERO:
        {
            const struct pcep_obj_ero *o = obj_body;
            uint8_t sub=0;
            while (sub < o->subcount) {
                if (pcep_send_ero_sub(conn, &o->subs[sub++]))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_RRO:
        {
            const struct pcep_obj_rro *o = obj_body;
            uint8_t sub=0;
            while (sub < o->subcount) {
                if (pcep_send_rro_sub(conn, &o->subs[sub++]))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_IRO:
        {
            const struct pcep_obj_iro *o = obj_body;
            uint8_t sub=0;
            /* composed of ERO subs */
            while (sub < o->subcount) {
                if (pcep_send_ero_sub(conn, &o->subs[sub++]))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_SVEC:
        {
            const struct pcep_obj_svec *o = obj_body;
            uint8_t sub=0;
            for (sub = 0; sub < o->id_count ; sub++) {
                if (pcep_send_uint(conn, o->req_ids[sub]))
                    return true;
            }
            return false;
        }
    case PCEP_OBJ_LABEL:
        {
            const struct pcep_obj_label *o = obj_body;
            return pcep_send_uint(conn, o->label);
        }
    case PCEP_OBJ_SRP:
        {
            const struct pcep_obj_srp *srp = obj_body;
            uint32_t flag = srp->remove ? 0x01 : 0x0;
            if (pcep_send_uint(conn, flag)) {
                return true;
            }
            if (pcep_send_uint(conn, srp->srp_id)) {
                return true;
            }
            if (send_tlv_lsp_setup_type(conn, srp->lsp_setup_type)) {
                return true;
            }
            return false;
        }
    case PCEP_OBJ_ASSOCIATION_nonRFC:
    case PCEP_OBJ_ASSOCIATION_nonIANA:
	{
	    const struct pcep_obj_association_non_rfc *o = obj_body;
	    uint8_t buf = 0;

	    buf = (((o->type & 0x0F) << 4) | ((o->generic_flags >> 6) & 0x0F));
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = (((o->generic_flags & 0x3F) << 2)
		      | ((o->flag_remove & 0x1) << 1)
		      | ((o->type_specific_flags >> 14) & 0x1));
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = ((o->type_specific_flags >> 6) & 0xFF);
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = (((o->type_specific_flags & 0x3F) << 2)
		   | ((o->flag_standby & 0x1) << 1)
		   | (o->flag_protection & 0x1));
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = ((o->association_group_id >> 24) & 0xFF);
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = ((o->association_group_id >> 16) & 0xFF);
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = ((o->association_group_id >>  8) & 0xFF);
	    if (pcep_send_byte(conn, buf))
                return true;

	    buf = 0;
	    buf = ((o->association_group_id >>  0) & 0xFF);
	    if (pcep_send_byte(conn, buf))
                return true;

	    return false;
	}
    case PCEP_OBJ_ASSOCIATION:
    {
        const struct pcep_obj_association *o = obj_body;
        uint32_t buf = 0;
        buf = (o->flag_remove & 0x1); //Reserved and unused flags need to be set to 0
        if(pcep_send_uint(conn, buf))
            return true;

        buf = 0;
        buf = (((o->association_type << 16) & 0xFFFF0000) |
                 (o->association_id & 0xFFFF));
        if(pcep_send_uint(conn, buf))
            return true;

        if (pcep_conn_send(conn, &o->ipv4_association_source, 4)) {
            return true;
        }

        if (o->path_protection) {
            if (send_tlv_path_protection_assoc(conn,&o->path_protection_tlv)) {
                return true;
            }
        }

        if (o->disjoint_config) {
            if (send_tlv_disjoint_assoc_conf_tlv(conn, &o->disjoint_config_tlv)) {
                return true;
            }
        }

        if (o->extended_assoc_id) {
            if (send_tlv_extended_assoc_id(conn,&o->extended_assoc_id_tlv)) {
                return true;
            }
        }

        if (o->sr_candidate_path_identifier) {
            if (send_tlv_sr_candidate_path_identifier(conn,
                    &o->sr_candidate_path_identifier_tlv)) {
                return true;
            }
        }

        if (o->sr_preference) {
            if (send_tlv_sr_preference(conn, &o->sr_preference_tlv)) {
                return true;
            }
        }

        return false;
    }
    case PCEP_OBJ_ASSOCIATION_IPV6:
    {
        const struct pcep_obj_association_ipv6 *o = obj_body;
        uint32_t buf = 0;
        buf = (o->flag_remove & 0x1); //Reserved and unused flags need to be set to 0
        if(pcep_send_uint(conn, buf))
            return true;

        buf = 0;
        buf = (((o->association_type << 16) & 0xFFFF0000) |
                 (o->association_id & 0xFFFF));
        if(pcep_send_uint(conn, buf))
            return true;

        if (pcep_conn_send(conn, &o->ipv6_association_source, 16)) {
            return true;
        }

        if (o->extended_assoc_id) {
            if (send_tlv_extended_assoc_id(conn,&o->extended_assoc_id_tlv)) {
                return true;
            }
        }

        if (o->sr_candidate_path_identifier) {
            if (send_tlv_sr_candidate_path_identifier(conn,
                    &o->sr_candidate_path_identifier_tlv)) {
                return true;
            }
        }

        if (o->sr_preference) {
            if (send_tlv_sr_preference(conn, &o->sr_preference_tlv)) {
                return true;
            }
        }

        if (o->disjoint_config) {
            if (send_tlv_disjoint_assoc_conf_tlv(conn, &o->disjoint_config_tlv)) {
                return true;
            }
        }

        return false;
    }
    case PCEP_OBJ_VENDOR:
    {
        const struct pcep_obj_vendor *o = obj_body;
        if (pcep_send_uint(conn, JNPR_ENTERPRISE_NUMBER))
                return true;
        for (unsigned int i =0; i < o->size; i++) {
            switch(o->info[i].type) {
                case PCEP_VENDOR_INFO_TYPE_LSP:
                    if (send_tlv_header(conn, TLV_VENDOR_LSP_QUALIFIER, 8))
                        return true;
                    if (pcep_send_uint(conn, JNPR_ENTERPRISE_NUMBER))
                        return true;
                    if (pcep_send_uint(conn, o->info[i].u.lsp_type))
                        return true;
                break;
                case PCEP_VENDOR_INFO_TYPE_BW:
                    if (send_tlv_header(conn, TLV_VENDOR_LSP_BW, 8))
                        return true;
                    if (pcep_send_uint(conn, JNPR_ENTERPRISE_NUMBER))
                        return true;
                    if (pcep_send_float(conn, o->info[i].u.bps))
                        return true;
                break;
                case PCEP_VENDOR_INFO_TYPE_P2MP_TREE_NAME:
                    if (o->info[i].u.p2mp_tree_name[0]) {
                        uint16_t datalen = strlen(o->info[i].u.p2mp_tree_name);
                        uint8_t padlen = (datalen%4) ? 4 - (datalen%4):0;
                        if (send_tlv_header(conn, TLV_VENDOR_P2MP_TREE_NAME, datalen+4))
                            return true;
                        if (pcep_send_uint(conn, JNPR_ENTERPRISE_NUMBER))
                            return true;
                        if (pcep_conn_send(conn, o->info[i].u.p2mp_tree_name, datalen))
                            return true;
                        if (padlen) {
                            uint8_t padding[3] = {0, 0, 0};
                            if (pcep_conn_send(conn, padding, padlen))
                                return true;
                        }
                    }
                break;
                case PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE:
                    if (send_tlv_header(conn, TLV_VENDOR_LSP_ROUTE_PREFERENCE, 8))
                        return true;
                    if (pcep_send_uint(conn, JNPR_ENTERPRISE_NUMBER))
                        return true;
                    if (pcep_send_uint(conn, o->info[i].u.route_preference))
                        return true;
                break;
                case PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF:
                case PCEP_VENDOR_INFO_TYPE_UNKNOWN:
                    assert(0);
                break;
            }
        }
	    return false;
    }
    case PCEP_OBJ_S2LS:
    case PCEP_OBJ_S2LS_nonIANA:
    {
        const struct pcep_obj_s2ls *o = obj_body;
        uint32_t flag =  o->lsp_oper_state ;

        if (pcep_send_uint(conn, flag))
            return true;

        return false;
    }
    case PCEP_OBJ_FLOWSPEC: {
        bool res;

        res = send_pcep_obj_flowspec(conn, obj_body);
        return res;
    }
    }
    /* We should never get here */
    abort();
}

/**
 * Send an object via the connection
 *
 * @param[in] conn Connection handle
 * @param[in] obj object
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */

bool
pcep_send_object (struct pcep_conn *conn, const struct pcep_object *obj)
{
    const size_t reqlen = pcep_obj_reqlen(obj);

    pcep_obj_trace(conn, true, obj);

    if (pcep_buffer_reserve(get_output_buffer(conn), reqlen))
        return close_conn(conn, ENOMEM, 0);
    if (send_obj_header(conn, obj->type, obj->procrule, obj->ignore, reqlen))
        return true;
    if (send_obj_body(conn, obj->type, &obj->u))
        return true;
    return false;
}
