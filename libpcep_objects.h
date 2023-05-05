/**
 * @file libpcep/h/jnx/libpcep_objects.h
 *
 * Path Computation Element Protocol library, object definitions.
 * This header defines host view of data carried in various objects
 * defined by RFC5440 and its extensions.
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: libpcep_objects.h 1331188 2023-04-21 06:41:33Z gchandraseka $ */
#ifndef LIBPCEP_OBJECTS_H
#define LIBPCEP_OBJECTS_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

#define MAX_ERO_SUBS 100
#define MAX_ERO_LISTS 128
#define MAX_IRO_SUBS 100
#define MAX_RRO_SUBS 100
#define MAX_REQ_IDS  100
#define MAX_SYMB_NAME_SIZE 256
#define MAX_ERR_SPEC_SIZE 24
#define MAX_LSP_IDENTIFIERS_SIZE 52 /* IPV6-LSP-IDENTIFIERS TLV length is 52 */
#define PCCD_MAX_SID_DEPTH 16
/* Trimming Speaker ID length to 64 bytes if longer */
#define MAX_SPEAKER_ID_LEN 64
/* Limiting the Prefix to 16 making it consistent with other Max Limits */
#define MAX_PREFIX_SUPPORTED_PER_FLOWSPEC 16
#define MAX_FLOWSPEC_SUPPORTED_PER_LSP 20
#define PCEP_TRACE_BUFFER_SIZE 2048
/** 1 Path binding TLV contains new path binding value ,
 *  1 path binding TLV contains remove flag set with old binding value */
#define MAX_PATH_BINDING_TLVS 2


typedef enum {
	PCEP_OBJCLASS_OPEN               =  1U, /* RFC5440 */
	PCEP_OBJCLASS_RP                 =  2U, /* RFC5440 */
	PCEP_OBJCLASS_NOPATH             =  3U, /* RFC5440 */
	PCEP_OBJCLASS_ENDPOINTS          =  4U, /* RFC5440 */
	PCEP_OBJCLASS_BANDWIDTH          =  5U, /* RFC5440 */
	PCEP_OBJCLASS_METRIC             =  6U, /* RFC5440 */
	PCEP_OBJCLASS_ERO                =  7U, /* RFC5440 */
	PCEP_OBJCLASS_RRO                =  8U, /* RFC5440 */
	PCEP_OBJCLASS_LSPA               =  9U, /* RFC5440 */
	PCEP_OBJCLASS_IRO                = 10U, /* RFC5440 */
	PCEP_OBJCLASS_SVEC               = 11U, /* RFC5440 */
	PCEP_OBJCLASS_NOTIFICATION       = 12U, /* RFC5440 */
	PCEP_OBJCLASS_PCEPERROR          = 13U, /* RFC5440 */
	PCEP_OBJCLASS_LOADBALANCING      = 14U, /* RFC5440 */
	PCEP_OBJCLASS_CLOSE              = 15U, /* RFC5440 */
	PCEP_OBJCLASS_PATHKEY            = 16U,
//	PCEP_OBJCLASS_XRO                = 17U,
	/* Object class 18 is undefined */
//	PCEP_OBJCLASS_MONITORING         = 19U,
//	PCEP_OBJCLASS_PCCREQID           = 20U,
//	PCEP_OBJCLASS_OF                 = 21U,
//	PCEP_OBJCLASS_CLASSTYPE          = 22U,
	/* Object class 23 is undefined */
//	PCEP_OBJCLASS_GLOBALCONSTRAINTS  = 24U,
//	PCEP_OBJCLASS_PCEID              = 25U,
//	PCEP_OBJCLASS_PROCTIME           = 26U,
//	PCEP_OBJCLASS_OVERLOAD           = 27U,
//	PCEP_OBJCLASS_UNREACHDESTINATION = 28U,
//	PCEP_OBJCLASS_SERO               = 29U,
//	PCEP_OBJCLASS_SRRO               = 30U,
//	PCEP_OBJCLASS_BNCO               = 31U,
	PCEP_OBJCLASS_LSP                = 32U,
	PCEP_OBJCLASS_SRP                = 33U, /* draft-ietf-pce-stateful-pce-07  */
	PCEP_OBJCLASS_VENDOR             = 34U,
	PCEP_OBJCLASS_ASSOCIATION_nonIANA= 90U,
	PCEP_OBJCLASS_ASSOCIATION        = 40U,
	PCEP_OBJCLASS_S2LS               = 41U,
	PCEP_OBJCLASS_PATH_ATTRIBUTE     = 45U, /* draft-ietf-pce-multipath-06 */
	PCEP_OBJCLASS_S2LS_nonIANA       = 91U,
	PCEP_OBJCLASS_ASSOCIATION_nonRFC = 247U, /* Internal mapping for nonRFC assoc object to dummy
	                                            object class in PCCD as nonRFC assoc object class 
	                                            is same as 40 and only object format changed.
	                                            This is required as index of object_ops array is 
	                                            comination of object class and object type
	                                            TODO: Remove PCEP_OBJCLASS_ASSOCIATION_nonIANA and 
	                                            PCEP_OBJCLASS_ASSOCIATION_nonRFC implementations
	                                            in future versions as RFC complaint implementation 
	                                            is PCEP_OBJCLASS_ASSOCIATION */

	/* experimental obj class values*/
	PCEP_OBJCLASS_EXP_START = 248U,
	PCEP_OBJCLASS_FLOWSPEC = PCEP_OBJCLASS_EXP_START, /* draft-ietf-pce-pcep-flowspec-00 */
	PCEP_OBJCLASS_EXP_END = 255U,
} pcep_obj_class_t;

#define PCEP_MAX_OBJ_CLASS 91
#define PCEP_MAX_OBJ_TYPE 8

/**
 * Calculate internal object identifier. The mapping attempts
 * to be as packed as possible.
 *
 * @param[in] cls PCEP object class
 * @param[in] type PCEP object type
 * @return Library object identifier
 *
 *  4 bits for type and 8 bits for cls
 *  uniquely identifies a PCEP object
 */
#define PCEP_OBJECTID(cls, type) (\
        ((((type) - 1) & 0xF) << 8) | \
         (((cls)  - 1) & 0xFF))

/**
 * Return the object class of a particular object.
 *
 * @param[in] obj Library object identifier
 * @return PCEP object class
 */
#define PCEP_OBJCLASS(obj)     ((obj & 0xFF) + 1)

/**
 * Return the object type of a particular object.
 *
 * @param[in] obj Library object identifier
 * @return PCEP object type
 */
#define PCEP_OBJTYPE(obj)      (((obj >> 8) & 0xF) + 1)

typedef enum {
#define PCEP_OBJDEF(class, type) PCEP_OBJECTID(PCEP_OBJCLASS_ ##class, type)
	PCEP_OBJ_OPEN               = PCEP_OBJDEF(OPEN,          1), /**< OPEN object, RFC5440 */
	PCEP_OBJ_RP                 = PCEP_OBJDEF(RP,            1), /**< RP object, RFC5440 */
	PCEP_OBJ_NOPATH             = PCEP_OBJDEF(NOPATH,        1), /**< NO-PATH object, RFC5440 */
	PCEP_OBJ_ENDPOINTS_IPV4     = PCEP_OBJDEF(ENDPOINTS,     1), /**< END-POINTS object for IPv4, RFC5440 */
	PCEP_OBJ_ENDPOINTS_IPV6     = PCEP_OBJDEF(ENDPOINTS,     2), /**< END-POINTS object for IPv6, RFC5440 */
	PCEP_OBJ_P2MP_ENDPOINTS_IPV4  = PCEP_OBJDEF(ENDPOINTS,   3), /**< P2MP END-POINTS object for IPv4, RFC5440 */
	PCEP_OBJ_P2MP_ENDPOINTS_IPV6  = PCEP_OBJDEF(ENDPOINTS,   4), /**< P2MP END-POINTS object for IPv6, RFC5440 */
	PCEP_OBJ_BANDWIDTH_REQUEST  = PCEP_OBJDEF(BANDWIDTH,     1), /**< Requested BANDWIDTH object, RFC5440 */
	PCEP_OBJ_BANDWIDTH_REOPTIM  = PCEP_OBJDEF(BANDWIDTH,     2), /**< Existing LSP BANDWIDTH object, RFC5440 */
	PCEP_OBJ_METRIC             = PCEP_OBJDEF(METRIC,        1), /**< METRIC object, RFC5440 */
	PCEP_OBJ_PATH_ATTRIBUTE     = PCEP_OBJDEF(PATH_ATTRIBUTE, 1), /**< Path Attribute Object, draft-ietf-pce-multipath-06 */
	PCEP_OBJ_ERO                = PCEP_OBJDEF(ERO,           1), /**< Explicit Route Object, RFC5440 */
	PCEP_OBJ_RRO                = PCEP_OBJDEF(RRO,           1), /**< Reported Route Object, RFC5440 */
	PCEP_OBJ_LSP                = PCEP_OBJDEF(LSP,           1), /**< Label Switched Path object, RFC[XXX] */
	PCEP_OBJ_LSPA               = PCEP_OBJDEF(LSPA,          1), /**< Label Switched Path Attributes object, RFC5440 */
	PCEP_OBJ_IRO                = PCEP_OBJDEF(IRO,           1), /**< Include Route Object, RFC5440 */
	PCEP_OBJ_SVEC               = PCEP_OBJDEF(SVEC,          1), /**< SVEC object, RFC5440 */
	PCEP_OBJ_NOTIFICATION       = PCEP_OBJDEF(NOTIFICATION,  1), /**< NOTIFICATION object, RFC5440 */
	PCEP_OBJ_PCEPERROR          = PCEP_OBJDEF(PCEPERROR,     1), /**< PCEP-ERROR object, RFC5440 */
	PCEP_OBJ_LOADBALANCING      = PCEP_OBJDEF(LOADBALANCING, 1), /**< LOAD-BALANCING object, RFC5440 */
	PCEP_OBJ_CLOSE              = PCEP_OBJDEF(CLOSE,         1), /**< CLOSE object, RFC5440 */
	PCEP_OBJ_LABEL              = PCEP_OBJDEF(PATHKEY,       1), /**< LABEL object, RFC3209 */
	PCEP_OBJ_SRP                = PCEP_OBJDEF(SRP,           1), /**< draft-ietf-pce-stateful-pce-07 */
	PCEP_OBJ_ASSOCIATION_nonRFC = PCEP_OBJDEF(ASSOCIATION_nonRFC, 1), /**< draft-ananthakrishnan-pce-stateful-path-protection-00 */
	PCEP_OBJ_ASSOCIATION_nonIANA= PCEP_OBJDEF(ASSOCIATION_nonIANA, 1), /**< draft-ananthakrishnan-pce-stateful-path-protection-00 */
	PCEP_OBJ_ASSOCIATION        = PCEP_OBJDEF(ASSOCIATION,   1), /**< draft-ietf-pce-association-group-10 */
	PCEP_OBJ_ASSOCIATION_IPV6   = PCEP_OBJDEF(ASSOCIATION,   2), /**< IPv6 ASSOCIATION object, RFC8697 */
	PCEP_OBJ_VENDOR             = PCEP_OBJDEF(VENDOR,        1), /**< VENDOR-INFORMATION object RFC7150 */
	PCEP_OBJ_S2LS               = PCEP_OBJDEF(S2LS,          1), /* source to leave for P2MP*/
	PCEP_OBJ_S2LS_nonIANA               = PCEP_OBJDEF(S2LS_nonIANA,          1), /* source to leave for P2MP*/
	PCEP_OBJ_FLOWSPEC           = PCEP_OBJDEF(FLOWSPEC,      1), /**< draft-ietf-pce-pcep-flowspec-00 */
#undef PCEP_OBJDEF
} pcep_obj_type_t;

typedef enum {
    ASSOC_OBJ_RFC_COMPLAINT,
    ASSOC_OBJ_OLD_FORMAT,
    ASSOC_OBJ_OLD_OBJ_CLASS_OLD_FORMAT
}en_assoc_obj_complaince;

extern en_assoc_obj_complaince assoc_obj_complaince;
extern bool obj_s2ls_IANA_compliant;
extern bool tlv_p2mp_ipv4_lsp_id_IANA_compliant;

extern uint8_t srv6_ero_subobject_type;
extern uint8_t srv6_rro_subobject_type;
extern uint8_t srv6_pst_type;
extern uint16_t srv6_pce_capability_sub_tlv_type;
extern uint16_t pathattribute_color_tlv_type;

extern uint8_t maximum_srv6_segment_list_depth;

#define PCEP_OBJ_ASSOCIATION_VAL ( \
        (assoc_obj_complaince == ASSOC_OBJ_OLD_FORMAT) ? \
         PCEP_OBJ_ASSOCIATION_nonRFC : PCEP_OBJ_ASSOCIATION_nonIANA)

#define PCEP_OBJCLASS_ASSOCIATION_VAL ( \
        (assoc_obj_complaince == ASSOC_OBJ_OLD_FORMAT) ? \
         PCEP_OBJCLASS_ASSOCIATION_nonRFC : PCEP_OBJCLASS_ASSOCIATION_nonIANA)

#define PCEP_OBJ_S2LS_VAL (\
		obj_s2ls_IANA_compliant ? PCEP_OBJ_S2LS : PCEP_OBJ_S2LS_nonIANA)

#define PCEP_OBJCLASS_S2LS_VAL ( \
		obj_s2ls_IANA_compliant ? PCEP_OBJCLASS_S2LS : PCEP_OBJCLASS_S2LS_nonIANA)

typedef enum {
    PCEP_ERR_TYPE_SEF =  1, /**< Session establishment failure */
    PCEP_ERR_TYPE_CNS =  2, /**< Capability not supported */
    PCEP_ERR_TYPE_UO  =  3, /**< Unknown object */
    PCEP_ERR_TYPE_NSO =  4, /**< Not supported object */
    PCEP_ERR_TYPE_PV  =  5, /**< Policy violation */
    PCEP_ERR_TYPE_MOM =  6, /**< Mandatory object missing */
    PCEP_ERR_TYPE_PRM =  7, /**< Synchronized path computation request missing */
    PCEP_ERR_TYPE_URR =  8, /**< Unknown request reference */
    PCEP_ERR_TYPE_ASS =  9, /**< Attempt to establish a second PCEP session */
    PCEP_ERR_TYPE_RIO = 10, /**< Reception of an invalid object */
    PCEP_ERR_TYPE_P2MP_FRAG = 18, /**< P2mp fragmentation error */
    PCEP_ERR_TYPE_INVALID_OPERATION = 19, /**< Invalid Operation */
    PCEP_ERR_TYPE_SYNC_ERR = 20, /**< LSP State synchronization error */
    PCEP_ERR_TYPE_BSF = 22, /**< Binding SID failure */
    PCEP_ERR_TYPE_RIP = 23, /**< Reception of an invalid parameter */
    PCEP_ERR_TYPE_PCCREATE = 24, /**< LSP Instantiation error */
    PCEP_ERR_TYPE_STARTTLS = 25, /*< TLS session establishment error */
    PCEP_ERR_TYPE_PATH_COMPUTATION_FAILURE = 29,

    /* TBD : Below err types are from unassigned range.
           these need to be updated when IANA assigns them */
    PCEP_ERR_TYPE_FLOWSPEC = 255, /**< Flow specification error */
} pcep_error_type_t;

typedef enum {
    /* Type 1 values */
    PCEP_ERR_VAL_BAD_OPEN       =  1, /**< Bad open message */
    PCEP_ERR_VAL_OPEN_TIMEDOUT  =  2, /**< Open message timed out*/
    PCEP_ERR_VAL_NO_NEGOTIATION =  3, /**< Non negotiable session characteristics */
    PCEP_ERR_VAL_NEGOTIABLE     =  4, /**< Negotiable session characteristics */
    PCEP_ERR_VAL_STILL_NOT_ACPT =  5, /**< Session characteristics still not acceptable*/
    PCEP_ERR_VAL_NEGO_NOT_ACPT  =  6, /**< Not acceptable peer negotiation */
    PCEP_ERR_VAL_ACPT_TIMEDOUT  =  7, /**< Answer to open timed out (Keepalive/PcErr) */
    PCEP_ERR_VAL_VERS_SUPPORT   =  8, /**< Version not supported */
    
    /* Type 2 values */
    PCEP_ERR_VAL_GENERIC        =  0,
    
    /* Type 3 and 4 values */
    PCEP_ERR_VAL_OBJECT_CLASS      = 1,
    PCEP_ERR_VAL_OBJECT_TYPE       = 2,

    /* Type 6 values */
    PCEP_ERR_VAL_EP_MISSING        = 3, /** END-POINT Object missing */
    PCEP_ERR_VAL_LSP_MISSING       = 8, /** LSP Object missing */
    PCEP_ERR_VAL_ERO_MISSING       = 9, /** ERO Object missing */
    PCEP_ERR_VAL_SRP_MISSING       = 10, /** SRP Object missing */
    PCEP_ERR_VAL_LSPA_MISSING      = 11, /** LSPA Object missing */
    PCEP_ERR_VAL_CLNP_TLV_MISSING  = 13, /** LSP Cleanup TLV missing */
    PCEP_ERR_VAL_SYMB_NAME_MISSING = 14, /** LSP Symbolic name TLV missing */
    PCEP_ERR_VAL_DISJ_CONFIG_MISSING = 15, /** Disjoint Association Configuration TLV missing */

    /* Type 10 values */
    PCEP_ERR_VAL_BAD_LEVEL_VAL       = 2, /** Bad Level value */
    PCEP_ERR_VAL_UNSUP_NUM_SR_ERO    = 3, /** Unsupported number of segment ERO subobject */
    PCEP_ERR_VAL_BAD_LEVEL_FORMAT    = 4, /** Bad level format */
    PCEP_ERR_VAL_NON_IDENT_SR_ERO    = 5, /** Non identical ERO segment subobject */
    PCEP_ERR_VAL_SID_NAI_ABST_SR_ERO = 6, /** Both SID and NAI absent from segment ERO */
    PCEP_ERR_VAL_SID_NAI_ABST_SR_RRO = 7, /** Both SID and NAI absent from segment RRO */
    PCEP_ERR_VAL_MALFORMED_OBJECT    = 11, /** Malformed object */
    PCEP_ERR_VAL_UNSUPPORTED_NAI_TYPE  = 13, /** Unsupported NAI type */
    PCEP_ERR_VAL_NAI_TO_SID_CONVERSION = 15, /** NAI to SID conversion error*/
    PCEP_ERR_VAL_CONFLICTING_PATHID    = 38, /** Conflicting Path IDs */
    PCEP_ERR_VAL_INVALID_SID_STRUCTURE = 253, /** sum of all four sizes advertised in
                                                  the SID Structure is larger than 128 bits*/
    PCEP_ERR_VAL_MISSING_SRV6_CAP_SUB_TLV  = 254, /** Missing PCE-SRv6-CAPABILITY sub-TLV
                                                    - draft-ietf-pce-segment-routing-ipv6-09*/
    PCEP_ERR_VAL_UNSUP_NUM_SRV6_ERO = 255, /** Unsupported number of SRv6 ERO subobjects */

    /* type 18 P2mp fragmentation error */
    PCEP_ERR_VAL_FRAGMENTED_REPORT  = 2, /** Fragmented Report */
    PCEP_ERR_VAL_FRAGMENTED_UPDATE  = 3, /** Fragmented Update */
    PCEP_ERR_VAL_FRAGMENTED_INST  = 4, /** Fragmented Instantiation */

    /* Type 19 Invalid Operations */
    PCEP_ERR_VAL_NON_DELEGATED_LSP  = 1, /** Attempted LSP Update Request for a non-delegated
                                             LSP. */
    PCEP_ERR_VAL_NOT_ADV_ACTIVE_STATEFUL = 2, /** Attempted LSP Update Request if active
                                                  stateful PCE capability was not advertised. */
    PCEP_ERR_VAL_UNKNOWN_PLSP_ID = 3, /** Attempted LSP Update Request for an LSP identified
                                          by unknown PLSP-ID */
    PCEP_ERR_VAL_PCE_EXCEED_RES_LIMIT = 4, /** A PCE exceeded Resource Limit */
    PCEP_ERR_VAL_LIMIT_REACHED = 6, /** PCE-initiated LSP limit reached */
    PCEP_ERR_VAL_INVALID_REVOKE = 7, /** Delegation for PCE-initiated LSP cannot be revoked */
    PCEP_ERR_VAL_NON_ZERO_PLSP_ID = 8, /** Non-zero PLSP-ID in LSP initiation request */
    PCEP_ERR_VAL_LSP_NOT_PCE_INITIATED = 9, /** LSP is not PCE initiated */
    PCEP_ERR_VAL_NOT_ADV_P2MP_REPORT = 11, /** Attempted LSP State Report
                                                                     for P2MP if stateful PCE capability for P2MP was not advertised. */
    PCEP_ERR_VAL_NOT_ADV_P2MP_UPDATE = 12, /** Attempted LSP Update Request
                                                         for P2MP if active stateful PCE capability for P2MP was not advertised. */
    PCEP_ERR_VAL_NOT_ADV_P2MP_INSTANT = 13, /** Attempted LSP Instantiation
                             Request for P2MP if stateful PCE instantiation capability for P2MP was not advertised. */
    PCEP_ERR_VAL_SRV6_UNSUPPORTED = 255, /** Attempted SRv6 when the capability was not advertised*/

    PCEP_ERR_VAL_MISSING_PCE_SR_CAPABILITY_SUB_TLV = 12, /** Pce sr capability sub-tlv missing */
    /** Type 20 LSP State Synchronization Error */
    PCEP_ERR_VAL_PCE_SYNC_ERR = 1, /** PCE reporting that it cannot proceed with sync */
    PCEP_ERR_VAL_PCC_SYNC_ERR = 2, /** PCC reporting that it cannot complete sync */

    /** Type 22 Binding SID failure */
    PCEP_ERR_VAL_INVALID_SID = 1, /** Invalid Bindind SID sent by PCE */
    PCEP_ERR_VAL_UNABLE_ALLOCATE_SID = 2, /** PCC is unable to allocate label/SID */

    /* Type 23 Bad Parameter values */
    PCEP_ERR_VAL_SYMBOLIC_NAME_IN_USE = 1, /** SYMBOLIC-PATH-NAME in use */
    PCEP_ERR_SRPAG_REMOVE_ASSOCIATION = 255, /** SRPAG association cannot be removed in LSP lifetime **/

    /* Type 24 LSP instantiation error */
    PCEP_ERR_VAL_UNACCEPTABLE_INST_PARAM = 1, /** Unacceptable instantiation parameters */
    PCEP_ERR_VAL_INTERNAL_ERROR = 2, /** Internal error */
    PCEP_ERR_VAL_RSVP_SIGNALING_ERROR = 3, /** RSVP Signaling error */

    /* Type 25 TLS session establishment error */
    PCEP_ERR_VAL_RCV_STARTTLS_AFTER_PCEP    = 1,    /* Reception of StartTLS after any PCEP exchange */
    PCEP_ERR_VAL_RCV_UNEXPECTED_MSG         = 2,    /* Reception of any other message apart from StartTLS, Open, or PCErr */
    PCEP_ERR_VAL_CONN_WITH_TLS_ERR          = 3,    /* Failure, connection without TLS is not possible */
    PCEP_ERR_VAL_CONN_WITHOUT_TLS_ERR       = 4,    /* Failure, connection without TLS is possible */
    PCEP_ERR_VAL_STARTTLS_WAIT_TIMER_EXIPRY = 5,    /* No StartTLS message (nor PCErr/Open) before StartTLSWait timer expiry */

    /* Type 29, Path computation failure */
    PCEP_ERR_VAL_CONFLICTING_SRPAG_TLV = 251,       /** When Policy identifiers/ candidate path identifiers
                                                        changes during the lifetime of LSP */
    PCEP_ERR_VAL_MISSING_MANDATORY_SRPAG_TLV = 252, /** When any of the mandatory TLVs missing in 
                                                        PCInit/ PCUpdate messages */
    PCEP_ERR_VAL_MULTIPLE_SRPAG_IN_LSP =  253,      /** If a PCEP speaker receives a PCEP message with
                                                        more than one SRPAG for an LSP */
    PCEP_ERR_VAL_SRPAG_WITHOUT_SR_CAPAILITY_EXCHANGE = 254, /** If the PCEP speaker receives the SRPAG
                                                        association when SR capability was not exchanged */
    PCEP_ERR_VAL_SRPAG_IN_NON_SR_LSP = 255,         /** If SRPAG association is sent for non-SR LSP */

    /* Type 255 flow specification error */
    PCEP_ERR_VAL_UNSUPPORTED_FS = 1, /** Unsupported flow spec*/
    PCEP_ERR_VAL_MALFORMED_FS = 2,     /** Malformed flow spec object/tlv */
    PCEP_ERR_VAL_UNRESOLVABLE_FS_CONFLICT = 3, /** Unresolvable flow spec */
    PCEP_ERR_VAL_UNKNOWN_FS = 4,       /** Unknown flow spec */
    PCEP_ERR_VAL_UNSUPPORTED_LPM_ROUTE = 5,    /** Unsupported LPM Route */
} pcep_error_value_t;

typedef enum {
	PCEP_CLOSE_REASON_UNKNOWN   = 1U, /**< No explanation provided */
	PCEP_CLOSE_REASON_DEADTIMER = 2U, /**< DeadTimer expired */
	PCEP_CLOSE_REASON_MALFORMED = 3U, /**< Reception of a malformed PCEP message */
	PCEP_CLOSE_REASON_MANY_REQS = 4U, /**< Reception of an unacceptable number of unknown requests/replies */
	PCEP_CLOSE_REASON_MANY_MSGS = 5U, /**< Reception of an unacceptable number of unrecognized PCEP messages */
} pcep_close_reason_t; /**< Enumeration of good reasons to close a connection */

typedef enum {
    LSP_ERR_CODE_UNKNOWN                  = 1U, /**< Unknown reason */ 
    LSP_ERR_CODE_LIMIT_REACHED            = 2U, /**< Limit reached for PCE-controlled LSPs */
    LSP_ERR_CODE_TOO_MANY_PENDING_UPDATES = 3U, /**< Too many pending LSP update requests */
    LSP_ERR_CODE_UNACCEPTABLE_PARAMETERS  = 4U, /**< Unacceptable parameters */
    LSP_ERR_CODE_INTERNAL_ERROR           = 5U, /**< Internal error */
    LSP_ERR_CODE_ADMIN_DOWN               = 6U, /**< LSP administratively brought down */
    LSP_ERR_CODE_PREEMPTED                = 7U, /**< LSP preempted */
    LSP_ERR_CODE_RSVP_SIGNAL_ERROR        = 8U, /**< RSVP signalling error */
} lsp_err_code_t;	

/**
 * PCEP BANDWIDTH object
 */
struct pcep_obj_bandwidth {
	float bps; /**< Bytes per second */
};

/**
 * PCEP CLOSE object
 */
struct pcep_obj_close {
	pcep_close_reason_t reason; /** Reason for closing */
};

/**
 * PCEP END-POINTS object, IPv4 flavour
 */
struct pcep_obj_endpoints_ipv4 {
	struct in_addr source;
	struct in_addr destination;
};

/**
 * PCEP END-POINTS object, IPv6 flavour
 */
struct pcep_obj_endpoints_ipv6 {
	struct in6_addr source;
	struct in6_addr destination;
};

/**
 * Leaf Type
 */
typedef enum LeafType_{
    LEAF_TYPE_INVALID           = 0,  // Invalid
    NEW_LEAVES_TO_ADD           = 1,  // New Leaves to Add
    OLD_LEAVES_TO_REMOVE        = 2,  // Old Leaves to Remove
    OLD_LEAVES_CAN_MODIFIED     = 3,  // Old Leaves can be Modified
    OLD_LEAVE_MUST_UNCHAGED     = 4,  // Old Leaves must be Unchanged
} LeafType;

#define MAX_DESTINATION_ADDR 100

/**
 * PCEP P2MP-END-POINTS Object for IPv4
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                          Leaf type                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     Source IPv4 address                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Destination IPv4 address                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                                                               ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                  Destination IPv4 address                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 * PCEP P2MP-END-POINTS object, IPv4 flavour
 */
struct pcep_obj_p2mp_endpoints_ipv4 {
    LeafType leaftype;
    struct in_addr source;
    uint8_t subcount;
    struct in_addr destinations[MAX_DESTINATION_ADDR];
};

/**
 * PCEP P2MP-END-POINTS object, IPv6 flavour
 */
struct pcep_obj_p2mp_endpoints_ipv6 {
    LeafType leaftype;
    struct in6_addr source;
    uint8_t subcount;
    struct in6_addr destinations[MAX_DESTINATION_ADDR];
};

/**
 * PCEP ERROR object, RFC5440, section 7.15
 */
struct pcep_obj_error {
	uint8_t type;
	uint8_t value;
	uint32_t missing_request_id;
};

/**
 * PCEP LOAD-BALANCING object
 */
struct pcep_obj_loadbalancing {
	float    min_bandwidth;
	uint8_t  max_lsp;
};

/**
 * PCEP TE-PATH-BINDING TLV
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           Type = 55           |             Length            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |      BT       |    Flags      |            Reserved           |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     ~            Binding Value (variable length)                    ~
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *                          TE-PATH-BINDING TLV
 */

struct pcep_tlv_path_binding {
    uint8_t binding_type;
    u_int32_t mpls_label_binding_value;
    bool flag_r;
};

#define LSP_SETUP_FAILED_OUTSIDE_NODE 1
#define LSP_NOT_OPERATIONAL           2

typedef enum {
    LSP_OP_DOWN       = 0U, /**< not active */
    LSP_OP_UP         = 1U, /**< signalled */
    LSP_OP_ACTIVE     = 2U, /**< up and carrying traffic */
    LSP_OP_GOING_DOWN = 3U, /**< LSP is being torn down, resources
                                 are being released */
    LSP_OP_GOING_UP   = 4U, /**< LSP is being signalled */
    LSP_OP_RESV1      = 5U, /**< Reserved for future use */
    LSP_OP_RESV2      = 6U, /**< Reserved for future use */
    LSP_OP_RESV3      = 7U  /**< Reserved for future use */
} lsp_op_value_t;   		

#define PLSPID_RESERVED 0
/**
 * PCEP LSP object
 */
struct pcep_obj_lsp {
   uint32_t plsp_id:20;
   bool     delegated;
   bool     last_update;
   bool     remove;
   bool     administrative;
   bool     fragment;
   bool     p2mp_branch;
   bool     pce_created; /**< PCE initiated LSP */
   lsp_op_value_t operational; 
   uint8_t  symbolic_name[MAX_SYMB_NAME_SIZE];
   bool symbolic_name_tlv;
   uint8_t  errspec_len;
   uint8_t  errspec[MAX_ERR_SPEC_SIZE];
   uint8_t  lsp_identifiers_len;
   uint8_t  lsp_identifiers[MAX_LSP_IDENTIFIERS_SIZE];
   struct pcep_tlv_path_binding path_binding[MAX_PATH_BINDING_TLVS];
   bool      propagate_max_segment_list;
   u_int16_t max_segment_list;
};

/**
 * PCEP LSPA object
 */
struct pcep_obj_lspa {
        uint32_t pol_exclude_any;
        uint32_t pol_include_any;
        uint32_t pol_include_all;
        uint8_t  setup_prio;
        uint8_t  hold_prio;
        bool     local_prot;
        bool     symbolic_name_tlv;
        uint8_t  symbolic_name[MAX_SYMB_NAME_SIZE];
        /* PCE Initiated Bypass : begin */ 
        bool    bypass_tlv;
        bool    node_prot;
        bool    local_prot_in_use;
        struct in_addr bypadd_ipv4_addr;
        float   subsc_mul;
        /* PCE Initiated Bypass : end */ 
};

/**
 * RFC 5440,
 * Three values are currently defined:
 *  T=1: IGP metric
 *  T=2: TE metric
 *  T=3: Hop Counts
 */
typedef enum {
    IGP_METRIC                      = 1U,
    TE_METRIC                       = 2U,
    HOPCOUNT_METRIC                 = 3U,
    AGGREGATE_BANDWIDTH_CONSUMPTION = 4U,
    LOAD_OF_MOST_LOADED_LINK        = 5U,
    CUMULATIVE_IGP_COST             = 6U,
    CUMULATIVE_TE_COST              = 7U,
    P2MP_IGP_METRIC                 = 8U,
    P2MP_TE_METRIC                  = 9U,
    P2MP_HOP_COUNT_METRIC           = 10U,
    SEGMENT_ID_DEPTH                = 11U,
    PATH_DELAY_METRIC               = 12U,
    PATH_DELAY_VARIATION_METRIC     = 13U,
    PATH_LOSS_METRIC                = 14U,
    P2MP_PATH_DELAY_METRIC          = 15U,
    P2MP_PATH_DELAY_VARIATION_METRIC= 16U,   
    P2MP_PATH_LOSS_METRIC           = 17U,
    NO_OF_ADAPTATIONS_METRIC        = 18U,
    NO_OF_LAYERS_METRIC             = 19U,
    DOMAIN_COUNT_METRIC             = 20U,
    BORDER_NODE_COUNT_METRIC        = 21U,
    PCEP_METRIC_TYPE_MAX            = 22U,
} pcep_metric_obj_type;

/**
 * PCEP METRIC object
 */
struct pcep_obj_metric {
	float    value; /**< IEEE754.1985 value */
	uint8_t  type;
	bool     computed;
	bool     bound;
};

/**
 * PCEP NO-PATH object
 */
struct pcep_obj_nopath {
	uint8_t issue;
	bool    constraints;
	bool    pce_unavailable;
	bool    unknown_destination;
	bool    unknown_source;
};

/**
 * PCEP NOTIFICATION object
 */
struct pcep_obj_notification {
	uint32_t    overloaded_duration;
	uint8_t     type;
	uint8_t     value;
};

/**
 * PCEP OPEN object, RFC5440, section 7.3
 */
struct pcep_obj_open {
        uint8_t  keepalive;
        uint8_t  deadtimer;
        uint8_t  session_id;
        uint8_t  version:3;

        bool    stateful; /**< Stateful extension TLV */
        bool    active;   /**< Stateful extension TLV */
        bool    lsp_provisioning; /* LSP provisioning (instantiation) */
        /* RFC 8623 P2MP-CAPABILITY Bit 25 from MSB in [0-31] */
        bool    p2mp_lsp_report_capability;
        /* RFC 8623 P2MP-LSP-UPDATE-CAPABILITY Bit 24 from MSB in [0-31] */
        bool    p2mp_lsp_update_capability;
        /* RFC 8623 P2MP-LSP-INSTANTIATION-CAPABILITY Bit 23 from MSB in [0-31] */
        bool    p2mp_lsp_init_capability; 
        bool    spring_capability;  /**< SR-PCE-CAPABILITY TLV */
        bool    is_srv6_pst_present; /** SRv6 PST presence in SR-PCE-CAPABILITY TLV */
        bool    srv6_capability;  /**< SRv6-PCE-CAPABILITY sub-TLV */
        uint8_t msd;     /**< SR-PCE-CAPABILITY TLV */
        bool    path_setup_type_capability;     /**< PATH-SETUP-TYPE-CAPABILITY TLV*/
        bool    is_sr_pst_present;   /** if sr capability is present in pst capability */
        bool    pce_flowspec_capability;     /**< PCE-FLOWSPEC-CAPABILITY TLV*/
        /* ASSOC-Type-List TLV BEGIN*/ /*draft-ietf-pce-association-group-10*/
        bool    path_protection_association; /*draft-ietf-pce-stateful-path-protection-11*/
        bool    srpag_association; /*draft-barth-pce-segment-routing-policy-cp-04*/
        /* ASSOC-Type-List TLV END*/
        bool    multipath_capability; /*  draft-ietf-pce-multipath-06 */
        uint16_t max_segment_list;
        bool     disjoint_assoc_capability;
	uint16_t  major_version; /* To display the Major version number for Junos*/
	uint16_t  minor_version; /* To display the Minor version number for Junos*/
};

/**
 * PCEP RP object
 */
struct pcep_obj_rp {
	uint32_t request_id;
	bool     bidirectional;
	bool     loose;
	bool     reoptimization;
	uint8_t  priority:3;
    uint8_t  lsp_setup_type;
};

/**
 * PCEP ERO object
 */
typedef enum {
	PCEP_ERO_SUB_IPV4           =  1U, /**< IPV4 prefix */
	PCEP_ERO_SUB_IPV6           =  2U, /**< IPV6 prefix */
	PCEP_ERO_SUB_LABEL          =  3U, /**< Label */
	PCEP_ERO_SUB_UNNUMBERED_IID =  4U, /**< Unnumbered Interface ID */
	PCEP_ERO_SUB_AUTONOMOUS     = 32U, /**< Autonomous system number */
	PCEP_ERO_SUB_SR             = 36U, /**< SR-ERO subobject */
	PCEP_ERO_SUB_SRV6_DEFAULT   = 40U, /**< SRv6-ERO (PCEP-specific)
	(TEMPORARY - registered 2022-01-12, expires 2023-01-12 -
	https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml */
} pcep_obj_ero_sub_t;

struct pcep_obj_ero_sub_ipv4_prefix {
	struct in_addr     address;
	uint8_t            prefix_length;
};

struct pcep_obj_ero_sub_ipv6_prefix {
	struct in6_addr    address;
	uint8_t            prefix_length;
};

struct pcep_obj_ero_sub_label {
	bool               upstream;
	uint8_t            ctype;
	uint32_t           label;
};

struct pcep_obj_ero_sub_unnumbered_iid {
	uint32_t           router_id;
	uint32_t           interface_id;
};

struct pcep_obj_ero_sub_autonomous {
	uint16_t           system_number;
};

/**
 * PCEP ERO-SR subobject 
 * NAI type information
 */
typedef enum {
    PCEP_SR_ERO_NAI_TYPE_INVALID = -1,   /** Send error when NAI type is INVALID*/
    PCEP_SR_ERO_NAI_TYPE_ABSENT,         /**< NAI is absent */
    PCEP_SR_ERO_NAI_TYPE_IPV4_NODE_ID,   /**< IPV4 node id */
    PCEP_SR_ERO_NAI_TYPE_IPV6_NODE_ID,   /**< IPV6 node id  */
    PCEP_SR_ERO_NAI_TYPE_IPV4_ADJ,       /**< IPV4 Adjacency */
    PCEP_SR_ERO_NAI_TYPE_IPV6_ADJ,       /**< IPV6 Adjacency */
    PCEP_SR_ERO_NAI_TYPE_UNNUMBERED,      /**< Unnumbered Adjacency */
    PCEP_SR_ERO_NAI_TYPE_IPV6_LINKLOCAL_ADJ  /**< IPV6 Link Local Adjacency */
} pcep_obj_ero_sub_sr_t;

struct pcep_obj_ero_sub_sr_ipv4_node_id {
    struct in_addr     address;
};

struct pcep_obj_ero_sub_sr_ipv6_node_id {
    struct in6_addr    address;
};

struct pcep_obj_ero_sub_sr_ipv4_adj {
    struct in_addr     local;
    struct in_addr     remote;
};

struct pcep_obj_ero_sub_sr_ipv6_adj {
    struct in6_addr    local;
    struct in6_addr    remote;
};

struct pcep_obj_ero_sub_sr_unnumbered_adj {
    uint32_t           local_node_id;
    uint32_t           local_interface_id;
    uint32_t           remote_node_id;
    uint32_t           remote_interface_id;
};

/**
 * IPv6 Link-Local Adjacency: RFC 8664
 *
 *       0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      //               Local IPv6 address (16 octets)                //
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                    Local Interface ID                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      //               Remote IPv6 address (16 octets)               //
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                   Remote Interface ID                         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/
struct pcep_obj_ero_sub_sr_ipv6_linklocal_adj {
    struct in6_addr    local_ipv6_addr;
    uint32_t           local_interface_id;
    struct in6_addr    remote_ipv6_addr;
    uint32_t           remote_interface_id;
};

/**
 * SID Structure:  draft-ietf-pce-segment-routing-ipv6-09
 * The SID Structure is an optional part of the SR-ERO subobject
 *
 *   LB Length: 1 octet.  SRv6 SID Locator Block length in bits.
 *   LN Length: 1 octet.  SRv6 SID Locator Node length in bits.
 *   Fun. Length: 1 octet.  SRv6 SID Function length in bits.
 *   Arg. Length: 1 octet.  SRv6 SID Arguments length in bits.
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    LB Length  |  LN Length    | Fun. Length   |  Arg. Length  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Reserved                      |   Flags       |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/
struct pcep_obj_ero_sub_srv6_sid_structure {
    uint8_t            lb_length;
    uint8_t            ln_length;
    uint8_t            fun_length;
    uint8_t            arg_length;
};

/**
 * SRv6-ERO Subobject:  draft-ietf-pce-segment-routing-ipv6-09
 *
 * 'L' Flag: Indicates whether the subobject represents a loose-hop
 * Type: indicates the content of the subobject
 * Length: Contains the total length of the subobject in octets.
 * NAI Type (NT): Indicates the type and format of the NAI contained in
 *  the object body, if any is present
 * Flags: Used to carry additional information pertaining to the
 *  SRv6-SID
 * Endpoint Behavior: A 16 bit field representing the behavior
 *  associated with the SRv6 SIDs
 * SRv6 SID: SRv6 Identifier is the 128 bit IPv6 addresses representing
 *  the SRv6 segment.
 * NAI: The NAI associated with the SRv6-SID.
 * SID Structure: The SID Structure is an optional part of the SR-ERO subobject
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |L|   Type=TBD3 |     Length    | NT    |     Flags     |V|T|F|S|
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |              Reserved         |      Endpoint Behavior        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     |                      SRv6 SID (optional)                      |
 *     |                     (128-bit)                                 |
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     //                    NAI (variable, optional)                 //
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     SID Structure (optional)                  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/
struct pcep_obj_ero_sub_srv6 {
    pcep_obj_ero_sub_sr_t  nai_type;
    uint16_t               endpoint_behavior;
    bool                   V_bit;
    bool                   T_bit;
    bool                   F_bit;
    bool                   S_bit;
    struct in6_addr        sid;
    struct pcep_obj_ero_sub_srv6_sid_structure sid_structure;
    union {
        struct pcep_obj_ero_sub_sr_ipv6_node_id        ipv6_node_id;
        struct pcep_obj_ero_sub_sr_ipv6_adj            ipv6_adjacency;
        struct pcep_obj_ero_sub_sr_ipv6_linklocal_adj  ipv6_linklocal_adj;
    } NAI_data;
};

struct pcep_obj_ero_sub_sr {
    pcep_obj_ero_sub_sr_t  nai_type;
    bool                   F_bit;
    bool                   S_bit;
    bool                   C_bit;
    bool                   M_bit;
    uint32_t               sid;
    union {
        struct pcep_obj_ero_sub_sr_ipv4_node_id    ipv4_node_id;
        struct pcep_obj_ero_sub_sr_ipv6_node_id    ipv6_node_id;
        struct pcep_obj_ero_sub_sr_ipv4_adj        ipv4_adjacency;
        struct pcep_obj_ero_sub_sr_ipv6_adj        ipv6_adjacency;
        struct pcep_obj_ero_sub_sr_unnumbered_adj  unnum_adj;
    } NAI_data;
};



struct pcep_obj_ero_sub {
	bool               loose;
	pcep_obj_ero_sub_t type;
	union {
		struct pcep_obj_ero_sub_ipv4_prefix    ipv4_prefix;
		struct pcep_obj_ero_sub_ipv6_prefix    ipv6_prefix;
		struct pcep_obj_ero_sub_label          label;
		struct pcep_obj_ero_sub_unnumbered_iid unnumbered_iid;
		struct pcep_obj_ero_sub_autonomous     autonomous;
		struct pcep_obj_ero_sub_sr             sr_ero;
		struct pcep_obj_ero_sub_srv6           srv6_ero;
	} data;
};

/**
 * PCEP Path Attribute Object
 */
struct pcep_obj_path_attribute {
    uint32_t       path_id;
    uint32_t       weight;
    lsp_op_value_t op_state;
    bool           secondary_path;
};

struct pcep_obj_ero {
    uint8_t subcount;
    struct  pcep_obj_ero_sub subs[MAX_ERO_SUBS]; // array of subs
    struct  pcep_obj_path_attribute path_attribs;
};

/**
 * PCEP RRO object
 */
typedef enum {
	PCEP_RRO_SUB_IPV4           = 1U, /**< IPV4 address */
	PCEP_RRO_SUB_IPV6           = 2U, /**< IPV6 address */
	PCEP_RRO_SUB_LABEL          = 3U, /**< Label */
	PCEP_RRO_SUB_UNNUMBERED_IID = 4U, /**< Unnumbered Interface ID */
	PCEP_RRO_SUB_SR             = 36U, /**< SR-RRO subobject */
	PCEP_RRO_SUB_SRV6_DEFAULT   = 40U, /**< SRv6-ERO (PCEP-specific)
    (TEMPORARY - registered 2022-01-12, expires 2023-01-12 -
    https://www.iana.org/assignments/rsvp-parameters/rsvp-parameters.xhtml */
} pcep_obj_rro_sub_t;

struct pcep_obj_rro_sub_ipv4 {
	struct     in_addr address;
	uint8_t    flags;
	bool       lprot_available;
	bool       lprot_inuse;
};

struct pcep_obj_rro_sub_ipv6 {
	struct     in6_addr address;
	uint8_t    flags;
	bool       lprot_available;
	bool       lprot_inuse;
};

struct pcep_obj_rro_sub_label {
	bool               global_label;
	bool               upstream;
	uint8_t            ctype;
	uint32_t           label;
};

struct pcep_obj_rro_sub_unnumbered_iid {
	uint32_t           router_id;
	uint32_t           interface_id;
};

/**
 * PCEP RRO-SR subobject 
 * SID type information
 */
typedef enum {
    PCEP_SR_RRO_NAI_TYPE_INVALID = -1,   /** Send error when NAI type is INVALID*/
    PCEP_SR_RRO_NAI_TYPE_ABSENT,         /**< NAI is absent */
    PCEP_SR_RRO_NAI_TYPE_IPV4_NODE_ID,   /**< IPV4 node id */
    PCEP_SR_RRO_NAI_TYPE_IPV6_NODE_ID,   /**< IPV6 node id  */
    PCEP_SR_RRO_NAI_TYPE_IPV4_ADJ,       /**< IPV4 Adjacency */
    PCEP_SR_RRO_NAI_TYPE_IPV6_ADJ,       /**< IPV6 Adjacency */
    PCEP_SR_RRO_NAI_TYPE_UNNUMBERED,      /**< Unnumbered Adjacency */
    PCEP_SR_RRO_NAI_TYPE_IPV6_LINKLOCAL_ADJ  /**< IPV6 Link Local Adjacency */
} pcep_obj_rro_sub_sr_t;

struct pcep_obj_rro_sub_sr_ipv4_node_id {
    struct in_addr     address;
};

struct pcep_obj_rro_sub_sr_ipv6_node_id {
    struct in6_addr    address;
};

struct pcep_obj_rro_sub_sr_ipv4_adj {
    struct in_addr     local;
    struct in_addr     remote;
};

struct pcep_obj_rro_sub_sr_ipv6_adj {
    struct in6_addr    local;
    struct in6_addr    remote;
};

struct pcep_obj_rro_sub_sr_unnumbered_adj {
    uint32_t           local_node_id;
    uint32_t           local_interface_id;
    uint32_t           remote_node_id;
    uint32_t           remote_interface_id;
};

struct pcep_obj_rro_sub_sr_ipv6_linklocal_adj {
    struct in6_addr    local_ipv6_addr;
    uint32_t           local_interface_id;
    struct in6_addr    remote_ipv6_addr;
    uint32_t           remote_interface_id;
};

struct pcep_obj_rro_sub_srv6_sid_structure {
    uint8_t            lb_length;
    uint8_t            ln_length;
    uint8_t            fun_length;
    uint8_t            arg_length;
};

/**
 * SRv6-RRO Subobject: draft-ietf-pce-segment-routing-ipv6-09
 * The format of the SRv6-RRO subobject is the same as that of the
 *  SRv6-ERO subobject, but without the L flag
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |   Type=TBD4   |     Length    |  NT   |     Flags     |V|T|F|S|
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |              Reserved         |      Endpoint Behavior        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     |                      SRv6 SID                                 |
 *     |                     (128-bit)                                 |
 *     |                                                               |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     //                    NAI (variable)                           //
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     SID Structure (optional)                  |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 **/
struct pcep_obj_rro_sub_srv6 {
    pcep_obj_rro_sub_sr_t  nai_type;
    uint16_t               endpoint_behavior;
    bool                   V_bit;
    bool                   T_bit;
    bool                   F_bit;
    bool                   S_bit;
    struct in6_addr        sid;
    struct pcep_obj_rro_sub_srv6_sid_structure sid_structure;
    union {
        struct pcep_obj_rro_sub_sr_ipv6_node_id        ipv6_node_id;
        struct pcep_obj_rro_sub_sr_ipv6_adj            ipv6_adjacency;
        struct pcep_obj_rro_sub_sr_ipv6_linklocal_adj  ipv6_linklocal_adj;
    } NAI_data;
};

struct pcep_obj_rro_sub_sr {
    pcep_obj_rro_sub_sr_t  nai_type;
    bool                   F_bit;
    bool                   S_bit;
    bool                   C_bit;
    bool                   M_bit;
    uint32_t               sid;
    union {
        struct pcep_obj_rro_sub_sr_ipv4_node_id    ipv4_node_id;
        struct pcep_obj_rro_sub_sr_ipv6_node_id    ipv6_node_id;
        struct pcep_obj_rro_sub_sr_ipv4_adj        ipv4_adjacency;
        struct pcep_obj_rro_sub_sr_ipv6_adj        ipv6_adjacency;
        struct pcep_obj_rro_sub_sr_unnumbered_adj  unnum_adj;
    } NAI_data;
};

struct pcep_obj_rro_sub {
	bool               loose;
	pcep_obj_rro_sub_t type;
	union {
		struct pcep_obj_rro_sub_ipv4           ipv4_address;
		struct pcep_obj_rro_sub_ipv6           ipv6_address;
		struct pcep_obj_rro_sub_label          label;
		struct pcep_obj_rro_sub_unnumbered_iid unnumbered_iid;
		struct pcep_obj_rro_sub_sr             sr_rro;
		struct pcep_obj_rro_sub_srv6           srv6_rro;
	} data;
};

struct pcep_obj_rro {
    uint8_t subcount;
    struct  pcep_obj_rro_sub subs[MAX_RRO_SUBS]; // array of subs
    struct  pcep_obj_path_attribute path_attribs;
};

/**
 * PCEP IRO object
 */
struct pcep_obj_iro {
	uint8_t subcount;
	struct  pcep_obj_ero_sub subs[MAX_IRO_SUBS]; // array of subs
};

/**
 * PCEP SVEC object
 */
struct pcep_obj_svec {
	bool     link;
	bool     node;
	bool     SRLG;
	uint16_t id_count;
	uint32_t req_ids[MAX_REQ_IDS];
};

/**
 * PCEP LABEL object
 */
struct pcep_obj_label {
	uint32_t label;
};

#define SRP_ID_RESV1 0x00000000
#define SRP_ID_RESV2 0xFFFFFFFF

/**
 * PCEP Stateful PCE Request Parameters(SRP) object
 */
struct pcep_obj_srp {
    bool remove; /**< removal request from PCE draft-crabbe-pce-initated-pce-03 */	
    uint32_t srp_id;
    uint8_t lsp_setup_type;
};

/**
* PCEP path protection association TLV:
*                         draft-ietf-pce-stateful-path-protection-11
* 
* TLV for path protection, carrying
* 1. protection type: Section 14.1 of [RFC4872]
*     Supported PT are:
*                   0x00    Unprotected
*                   0x01    (Full) Rerouting
*                   0x02    Rerouting without Extra-Traffic
*
* 2. protecting bit : Section 14.1 of [RFC4872]
*     To identify if LSP is working or protecting LSP
*
* 3. secondary bit: Section 14.1 of [RFC4872]
*     To identify if LSP is secondary or primary bit
*
*     Supported S&P combinations are:
*     a.  Working primary LSP: P:0 & S:0
*     b.  Protecting secondary LSP: P:1 & S:1
*     Unsupported S&P combinations are:
*     a.  Protecting primary LSP: P:1 & S:0
*     b.  Working secondary LSP: P:0 & S:1
*
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |         Type = TBD2         |              Length = 4         |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |   PT      |               Unassigned Flags                |S|P|
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**/

struct pcep_obj_assoc_path_protection_tlv {
    uint8_t protection_type:6;

    /*unassigned flags - MUST be set to 0 on
      transmission and MUST be ignored on receipt */
    uint32_t unassigned_flags:24;
    uint8_t flag_secondary:1;
    uint8_t flag_protection:1;
};

/**
* PCEP extended association ID TLV: RFC 8697
* Association ID in association object is 16bit. So, Sending
* association ID using extended assocation ID TLV
*
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |         Type = 31             |            Length = 4         |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* //                Extended Association ID                      //
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*
* Extended association ID format carried in SRPAG association:
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |           Type = 31           |       Length = 8 or 20        |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                             Color                             |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* ~                           Endpoint                            ~
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**/

struct pcep_obj_asoc_extended_assoc_id_tlv {
    uint32_t extended_assoc_id;
    uint32_t srpag_color;

    /**
     * Below flag is set to true when extended association id TLV
     * is processed as SRPAG TLV containing color and endpoint.
     * TLV is decoded as SRPAG TLV (decoding color and endpoint
     * from TLV) when association type is SRPAG -
     * draft-ietf-pce-segment-routing-policy-cp-05
     * TLV is decoded as extended association ID in other cases
     */
    bool process_as_srpag_tlv;
    /**
     * Below flag is set to true when TLV is processed as SRPAG TLV
     * and SRPAG endpoint is IPv6
     */
    bool is_srpag_endpoint_ipv6;

    union {
        struct in_addr v4;
        struct in6_addr v6;
    }srpag_endpoint;
};

typedef enum {
    PROTO_ORIGIN_PCEP = 10U,
    PROTO_ORIGIN_BGP_SR = 20U,
    PROTO_ORIGIN_CONFIGURATION = 30U
} pcep_sr_cpath_proto_origin_t;

/**
* SR Canndidate path identifier TLV:
*                   draft-barth-pce-segment-routing-policy-cp-04
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |             Type              |             Length            |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* | Proto. Origin |                    Reserved                   |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                         Originator ASN                        |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                                                               |
* |                       Originator Address                      |
* |                                                               |
* |                                                               |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                         Discriminator                         |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pcep_obj_sr_candidate_path_identifier_tlv {
    uint32_t originator_asn;
    uint32_t discriminator;

    bool is_originator_address_ipv6;

    union {
        struct in_addr v4;
        struct in6_addr v6;
    } originator_address;
    pcep_sr_cpath_proto_origin_t proto_origin_;
};

/**
* SR Candidate path preference TLV:
*                   draft-barth-pce-segment-routing-policy-cp-04
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |             Type              |             Length            |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |                           Preference                          |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pcep_obj_sr_preference_tlv {
    uint32_t preference;
};

/**
* DISJOINT CONFIGURATION TLV:
* RFC 8800
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |            Type = 46          |             Length            |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |              Unassigned flags                       |T|P|S|N|L|
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct pcep_obj_disjoint_configuration_tlv {
    bool link_disjoint;
    bool node_disjoint;
    bool srlg_disjoint;
    bool shortest_path_flag;
    bool stictness_flag;
};

/**
* DISJOINT STATUS TLV:
* RFC 8800
* 0                   1                   2                   3
* 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |            Type = 47          |             Length            |
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
* |              Unassigned flags                       |T|P|S|N|L|
* +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct pcep_obj_disjoint_status_tlv {
    bool link_disjoint;
    bool node_disjoint;
    bool srlg_disjoint;
    bool shortest_path_flag;
    bool stictness_flag;
};

/**
 * PCEP Association Object
 *
 * Association groups are owned by the PCC, but the PCE may request
 * creation of an association group (for example before instantiating
 * LSPs that belong to that group).  Membership in an association group
 * can be initiated by either the PCE or the PCC.  Association groups
 * and their memberships are defined using the Association object.
 *
 * The Association Object is an optional object in the PCupd, PCRpt and
 * PCinit messages.
 *
 */

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Reserved              |            Flags            |R|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Association type = TBD1  |      Association ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              IPv4 Association Source                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                   Optional TLVs                             //
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pcep_obj_association {
        /**
         Reserved - MUST be set to 0 and ignored upon receipt
        */
        uint16_t reserved;

        /**
         * Flags - flags for the association object.
         * The unassigned flags MUST be set to zero on transmission and MUST be
         * ignored on receipt
         */

        /**
         * Flags - R flag indicating removal from the association group.
         */
        uint8_t flag_remove:1;

        /**
         * Type - the association type (for example path protection association
         * or SRPAG association).
         */
        uint16_t association_type ;

        /**
         * Association group id - identifier of the association group.  The
         * values 0 and 0xffffffff are reserved.  Value 0 is used when the PCE
         * requests allocation of an association group.  Value 0xffffffff
         * indicates all association groups.
         */
        uint32_t association_id:16;

        /**
         * ipv4_association_source: To know who is creating the association.
         * Currently PCC/RPD creates association for both PCE-Initiated LSP and
         * locally-created LSP
         */
        struct in_addr ipv4_association_source;

        bool path_protection;

        struct pcep_obj_assoc_path_protection_tlv path_protection_tlv;

        bool extended_assoc_id;

        struct pcep_obj_asoc_extended_assoc_id_tlv extended_assoc_id_tlv;

        bool sr_candidate_path_identifier;

        struct pcep_obj_sr_candidate_path_identifier_tlv sr_candidate_path_identifier_tlv;

        bool sr_preference;

        struct pcep_obj_sr_preference_tlv sr_preference_tlv;

        bool disjoint_config;

        struct pcep_obj_disjoint_configuration_tlv disjoint_config_tlv;

        bool disjoint_status;

        struct pcep_obj_disjoint_status_tlv disjoint_status_tlv;
};

/**
 * PCEP Association Object
 *
 * Association groups are owned by the PCC, but the PCE may request
 * creation of an association group (for example before instantiating
 * LSPs that belong to that group).  Membership in an association group
 * can be initiated by either the PCE or the PCC.  Association groups
 * and their memberships are defined using the Association object.
 *
 * The Association Object is an optional object in the PCupd, PCRpt and
 * PCinit messages.
 *
 */

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Reserved              |            Flags            |R|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Association type = TBD1  |      Association ID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   IPv6 Association Source                     |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//                   Optional TLVs                             //
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct pcep_obj_association_ipv6 {
        /**
         Reserved - MUST be set to 0 and ignored upon receipt
        */
        uint16_t reserved;

        /**
         * Flags - flags for the association object.
         * The unassigned flags MUST be set to zero on transmission and MUST be
         * ignored on receipt
         */

        /**
         * Flags - R flag indicating removal from the association group.
         */
        uint8_t flag_remove:1;

        /**
         * Type - the association type (for example path protection association
         * or SRPAG association).
         */
        uint16_t association_type ;

        /**
         * Association group id - identifier of the association group.  The
         * values 0 and 0xffffffff are reserved.  Value 0 is used when the PCE
         * requests allocation of an association group.  Value 0xffffffff
         * indicates all association groups.
         */
        uint32_t association_id:16;

        bool extended_assoc_id;

        bool sr_candidate_path_identifier;

        bool sr_preference;
        /**
         * ipv4_association_source: To know who is creating the association.
         * Currently PCC/RPD creates association for both PCE-Initiated LSP and
         * locally-created LSP
         */
        struct in6_addr ipv6_association_source;

        struct pcep_obj_asoc_extended_assoc_id_tlv extended_assoc_id_tlv;

        struct pcep_obj_sr_candidate_path_identifier_tlv sr_candidate_path_identifier_tlv;

        struct pcep_obj_sr_preference_tlv sr_preference_tlv;

        bool disjoint_config;

        struct pcep_obj_disjoint_configuration_tlv disjoint_config_tlv;

        bool disjoint_status;

        struct pcep_obj_disjoint_status_tlv disjoint_status_tlv;
};

/**
 * PCEP Association Object non RFC
 *
 * Association groups are owned by the PCC, but the PCE may request
 * creation of an association group (for example before instantiating
 * LSPs that belong to that group).  Membership in an association group
 * can be initiated by either the PCE or the PCC.  Association groups
 * and their memberships are defined using the Association object.
 *
 * The Association Object is an optional object in the PCupd, PCRpt and
 * PCinit messages.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Type   |  Generic flags    |R| Type-specific flags         |S|P|
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Association group id                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * //            Optional TLVs                                    //
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct pcep_obj_association_non_rfc {
        /**
         * Type - the association type (for example protection or make-before-
         * break).  The association type will be defined in separate documents.
         */
        uint8_t type:4 ;

        /**
         * Generic flags - flags for the association object.
         */
        uint16_t    generic_flags:10;

        /**
         * Generic flags - R flag indicating removal from the association group.
         */
        uint8_t     flag_remove:1;

        /**
         * Type-specific flags - specific to the association type, will be
         * defined at the time of the association type.
         */
        uint32_t    type_specific_flags:15;

        /**
         * The 'S' Flag  if P flag is set, S flag indicates whether the
         * protection LSP associated with the PPAG is in standby mode (e.g.,
         * signaled via RSVP-TE prior to failure).  The S flag is ignored if
         * P flag is set to 0.
         */
        uint8_t     flag_standby:1;

        /**
         * The 'P' Flag  indicates whether the LSP associated with the PPAG is
         * working or protection LSP.  If this flag is set, the LSP is
         * protection LSP.
         */
        uint8_t     flag_protection:1;

        /**
         * Association group id - identifier of the association group.  The
         * values 0 and 0xffffffff are reserved.  Value 0 is used when the PCE
         * requests allocation of an association group.  Value 0xffffffff
         * indicates all association groups.
         */
        uint32_t    association_group_id;
};


#define JNPR_ENTERPRISE_NUMBER    0x0a4c
#define MAX_VENDOR_INFO_LIST_SIZE 8
#define MAX_EXTENDED_ASSOC_ID_SUPPORTED_SIZE 4
#define TLV_EXTENDED_ASSOC_ID_IPV4_SRPAG_FIXED_LEN 8
#define TLV_EXTENDED_ASSOC_ID_IPV6_SRPAG_FIXED_LEN 20

#define TLV_SR_CANDIDATE_PATH_IDENTIFIER_FIXED_LEN 28
#define TLV_SR_PREFERENCE_FIXED_LEN 4
#define TLV_DISJOINT_STATUS_FIXED_LEN 4
#define TLV_DISJOINT_CONFIGURATION_FIXED_LEN 4

#define TLV_PATH_BINDING_BT_0_LEN 7
#define TLV_PATH_BINDING_BT_1_LEN 8
#define TLV_PATH_BINDING_BT_2_LEN 20
#define TLV_PATH_BINDING_BT_3_LEN 28

typedef enum {
    PCEP_VENDOR_INFO_TYPE_UNKNOWN   =1U,
    PCEP_VENDOR_INFO_TYPE_LSP       =2U,
    PCEP_VENDOR_INFO_TYPE_BW        =3U,
    PCEP_VENDOR_INFO_TYPE_P2MP_TREE_NAME =4U,
    PCEP_VENDOR_INFO_TYPE_LOCAL_CSPF =5U,
    PCEP_VENDOR_INFO_TYPE_ROUTE_PREFERENCE = 6U,
}pcep_vendor_info_type_t;

typedef enum {
       PCEP_VENDOR_LSP_TYPE_UNKNOWN       =0x00,
       PCEP_VENDOR_LSP_TYPE_AUTOBW        =0x01,
       PCEP_VENDOR_LSP_TYPE_P2MP          =0x02,
       PCEP_VENDOR_LSP_TYPE_BI_DIRECTIONAL=0x04,
       PCEP_VENDOR_LSP_TYPE_TEPLUSPLUS    =0x08,
} pcep_vendor_lsp_type_t;

struct pcep_vendor_info
{
    pcep_vendor_info_type_t type;
    uint32_t enterprise;
    union {
	pcep_vendor_lsp_type_t	lsp_type;
	float			bps;            /**< Bytes per second */
	uint8_t			p2mp_tree_name[MAX_SYMB_NAME_SIZE]; /*p2mp tree name*/
	uint8_t			pvi_local_cspf;
	uint32_t        route_preference;
    }u;
};

struct pcep_obj_vendor {
    uint32_t enterprise;
    uint8_t size;            /**< number of vendor info entries in the array */
    struct  pcep_vendor_info info[MAX_VENDOR_INFO_LIST_SIZE];
};


/**
 * PCEP S2LS object for P2MP Lsps
 */
/**
 * PCEP S2LS Object
 *
 * The S2LS (Source-to-Leaves) Object is used to report RSVP-TE state of
 * one or more destinations (leaves) encoded within the END-POINTS
 * object for a P2MP TE LSP. It MUST be carried in PCRpt message along
 * with END-POINTS object when N bit is set in LSP object.
 *
 * S2LS Object-Class is [TBD].
 * S2LS Object-Types is 1.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Flags                       |  O  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * //                      Optional TLVs                          //
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 * O(Operational - 3 bits):  On PCRpt messages, the O Field represents
 * the operational status of the LSP.
 */
typedef enum lsp_operational_state_ {
    lsp_oper_down      = 0, // 0 - DOWN:  not active.
    lsp_oper_up        = 1, // 1 - UP:  signalled.
    lsp_oper_active    = 2, // 2 - ACTIVE:  up and carrying traffic.
    lsp_oper_goingDown = 3, // 3 - GOING-DOWN:  LSP is being torn down,
    //    resources are being released.
    lsp_oper_goingUp   = 4, // 4 - GOING-UP:  LSP is being signalled.
    lsp_oper_max       = 5  // 5-7 - Reserved:  reserved for future use.
} lsp_operational_state;

struct pcep_obj_s2ls {
    lsp_operational_state lsp_oper_state;
};


/**
 * PCEP Flow Spec Object
 *
 * Flow Spec Object-Class is [TBD].
 * Flow Spec Object-Types is 1.
 * Draft Name and version : draft-ietf-pce-pcep-flowspec-03
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             FS-ID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        AFI                  |    Reserved    | Flags        |R| 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * //                         TLVs (variable)                     //
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/**
 * AFI(Address Family Identifier - 16 bits):  the AFI Field represents
 * the Address Family Identifier of the flow specification object.
 */
typedef enum fs_afi_ {
    FS_AFI_INVALID     = 0, //Invalid FS AFI
    FS_AFI_IPV4        = 1, //for IPv4 or VPNv4
    FS_AFI_IPV6        = 2, //for IPv6 or VPNv6
    FS_AFI_MAX         = 3
} fs_afi;

/* Route Distinguisher */
struct pce_fs_flow_spec_rd {
    uint32_t rd_upper;
    uint32_t rd_lower;
};

/* MultiCast FlowSpec TLV */
struct pce_fs_flow_spec_multicast {
    uint16_t flags;
    uint8_t  src_len;
    uint8_t  mgp_len;
    uint32_t source_prefix;
    uint32_t multi_group_prefix;
};

/* Threshold */
struct pce_fs_flow_spec_thd {
    uint32_t threshold;
};

/* Destination Prefix Flowspec TLV */
struct pce_fs_flow_spec_dest_pfx {
    uint8_t  mask;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } prefix;
};


/* PCEP FlowSpec Flow Filter */
struct pce_fs_flow_filter {
    struct pce_fs_flow_spec_multicast fs_mc;
    struct pce_fs_flow_spec_rd        fs_rd;
    struct pce_fs_flow_spec_thd       fs_thd;
    struct pce_fs_flow_spec_dest_pfx  fs_dst_pfx[MAX_PREFIX_SUPPORTED_PER_FLOWSPEC];
    uint8_t  fs_dst_pfx_cnt;
    uint32_t filter_tlv_recv;
};

struct pcep_obj_flowspec {
    /*
     * The Remove bit is set when a PCEP FLOWSPEC Object is
     * included in a PCEP message to indicate removal of the Flow
     * Specification from the associated tunnel.  If the bit is clear,
     * the Flow Specification is being added or modified
     */
    bool     remove;

    /**
     * The Longest Prefix Match (LPM) bit is set to indicate that
     * the Flow Specification is to be installed as a route subject to
     * longest prefix match forwarding.  If the bit is clear, the Flow
     * Specification described by the Flow Filter TLV is to be installed
     * as a Flow Specification.  If the bit is set, only Flow Specifications
     * that describe IPv4 or IPv6 destinations are meaningful in the Flow
     * Filter TLV.  If the L is set and the receiver does not support the
     * use of Flow Specifications that are present in the Flow Filter TLV
     * for the installation of a route subject to longest prefix match
     * forwarding, then the PCEP peer MUST respond with PCErr message with
     * error type TBD8 (FlowSpec Error) and error-value 5 (Unsupported LPM Route)
     */
    bool lpm;

    /*
     * A PCEP-specific identifier for the FlowSpec information.
     * A PCE or PCC creates an FS-ID for each FlowSpec that it
     * originates, and the value is unique within the scope of that PCE or
     * PCC and is constant for the lifetime of a PCEP session.
     */
    uint32_t fs_id;

    /*
     * Address Family Identifier as used in BGP [RFC4760]
     * (AFI=1 for IPv4 or VPNv4, AFI=2 for IPv6 and VPNv6 as per as per
     * [I-D.ietf-idr-flow-spec-v6]).
     */
    uint16_t AFI;

    /*
     * Speaker Entity Identifier TLV: As specified in [RFC8232], SPEAKER-
     * ENTITY-ID TLV encodes a unique identifier for the node that does
     * not change during the lifetime of the PCEP speaker.  This is used
     * to uniquely identify the FlowSpec originator and thus used in
     * conjunction with FS-ID to uniquely identify the FlowSpec
     * information. This TLV MUST be included.  If the TLV is missing,
     * the PCEP peer MUST respond with a PCErr message with error-type
     * TBD8 (FlowSpec Error), error-value 2 (Malformed FlowSpec).
     *
     * Trimming it to 64 bytes if longer
     */
    uint8_t  speaker_id[MAX_SPEAKER_ID_LEN+1];

    /*
     * Flow Filter TLV to convey Flow Specification filtering
     * rules that specify what traffic is carried on a path
     *
     * Flow Filter TLV (variable): One TLV MAY be included.  The Flow
     * Filter TLV is OPTIONAL when the R bit is set.  The TLV MUST be
     * present when the R bit is clear.  If the TLV is missing when the R
     * bit is clear, the PCEP peer MUST respond with a PCErr message with
     * error-type TBD8 (FlowSpec Error), error-value 2 (Malformed
     * FlowSpec).
     */
    struct pce_fs_flow_filter flow_filter;

    /* Carry flags for all Flowspec TLVs */
    uint32_t fs_tlv_recv;
};

#define FS_TLV_FLOW_FILTER_RCV_BIT  0x00000001
#define FS_TLV_SPEAKER_ID_RCV_BIT   0x00000002

#define FS_SUBTLV_MC_RCV_BIT  0x00000001
#define FS_SUBTLV_RD_RCV_BIT  0x00000002
#define FS_SUBTLV_DP_RCV_BIT  0x00000004   // destination prefix subtlv bit

/**
 * PCEP object. Holds common header fields and a union of all the supported
 * object-dependent payloads.
 */
struct pcep_object {
	pcep_obj_type_t type;     /**< Library object identifier */
	bool            procrule; /**< This object represents a processing rule */
	bool            ignore;   /**< This object has been ignored in calculation */

	union {
		struct pcep_obj_bandwidth      bandwidth;
		struct pcep_obj_close          close;
		struct pcep_obj_endpoints_ipv4 endpoints_ipv4;
		struct pcep_obj_endpoints_ipv6 endpoints_ipv6;
		struct pcep_obj_p2mp_endpoints_ipv4 p2mp_endpoints_ipv4;
		struct pcep_obj_p2mp_endpoints_ipv6 p2mp_endpoints_ipv6;
		struct pcep_obj_error          error;
		struct pcep_obj_metric         metric;
		struct pcep_obj_lsp            lsp;
		struct pcep_obj_lspa           lspa;
		struct pcep_obj_loadbalancing  loadbalancing;
		struct pcep_obj_nopath         nopath;
		struct pcep_obj_notification   notification;
		struct pcep_obj_open           open;
		struct pcep_obj_rp             rp;
		struct pcep_obj_ero            ero;
		struct pcep_obj_iro            iro;
		struct pcep_obj_rro            rro;
		struct pcep_obj_svec           svec;
		struct pcep_obj_label          label;
		struct pcep_obj_srp            srp;
		struct pcep_obj_association    association;
		struct pcep_obj_association_ipv6    association_ipv6;
		struct pcep_obj_association_non_rfc    association_non_rfc;
		struct pcep_obj_vendor         vendor;
		struct pcep_obj_s2ls            s2ls;
		struct pcep_obj_flowspec       flowspec; 
        struct pcep_obj_path_attribute path_attr;
	} u; /**< Union of all object-specific payloads */
};

typedef enum {
    TLV_NO_PATH_VECTOR           =  1,  /**< RFC5440, section 7.5 */
    TLV_OVERLOADED_DURATION      =  2,  /**< RFC5440 */
    TLV_REQ_MISSING              =  3,  /**< RFC5440 */
//    TLV_OF_LIST                  =  4,  /**< RFC5541 */
//    TLV_ORDER                    =  5,  /**< RFC5557 */
//    TLV_P2MP_CAPABLE             =  6,  /**< RFC6006 */
//    values 7-12 not used
//    TLV_DELEGATION_PARAM         = 13,  /**< FIXME: RFC[XXX] */
    TLV_STATEFUL_PCE_CAPABILITY  = 16,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_LSP_SYMBOLIC_NAME        = 17,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_IPV4_LSP_IDENTIFIERS     = 18,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_IPV6_LSP_IDENTIFIERS     = 19,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_LSP_UPDATE_ERROR_CODE    = 20,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_IPV4_RSVP_ERROR_SPEC     = 21,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_IPV6_RSVP_ERROR_SPEC     = 22,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_LSP_DB_VERSION           = 23,  /**< draft-ietf-pce-stateful-pce-01 */
    TLV_NODE_IDENTIFIER          = 24,  /**< TBD */
// value 25 not used
    TLV_SR_PCE_CAPABILITY        = 26,  /**< draft-sivabalan-pce-segment-routing-03 */
// value 27 not used
    TLV_PATH_SETUP_TYPE          = 28,  /**< draft-ietf-pce-lsp-setup-type-03 */
// Unused 29-30
    TLV_EXTENDED_ASSOCIATION_ID  = 31,  /**< draft-ietf-pce-association-group-10 */
    TLV_IPV4_P2MP_LSP_IDENTIFIERS_IANA = 32,
// Unused 33
    TLV_PATH_SETUP_TYPE_CAPABILITY = 34, /** Path setup type capability **/
    TLV_ASSOCIATION_TYPE_LIST    = 35, /** https://www.iana.org/assignments/pcep/
                                        pcep.xhtml#pcep-tlv-type-indicators */
//Unused 36,37
    TLV_PATH_PROTECTION_ASSOCIATION = 38, /** https://www.iana.org/assignments/pcep/
                                        pcep.xhtml#pcep-tlv-type-indicators */
    TLV_DISJOINT_CONFIGURATION      = 46, /** RFC8800 */
    TLV_DISJOINT_STATUS             = 47, /** RFC8800 */
// Unused 39-45, 48-49
    TLV_VENDOR_LSP_QUALIFIER     = 50,
    TLV_VENDOR_LSP_BW            = 51,
    TLV_IPV4_P2MP_LSP_IDENTIFIERS_nonIANA = 52,
    TLV_IPV6_P2MP_LSP_IDENTIFIERS = 33,
    TLV_VENDOR_P2MP_TREE_NAME     = 54,
    TLV_TE_PATH_BINDING           = 55, /**< draft-ietf-pce-binding-label-sid-15 */

    TLV_VENDOR_LOCAL_CSPF         = 57,  /** Non standardized code point*/
    TLV_SR_CANDIDATE_PATH_IDENTIFIER = 57, /**< draft-ietf-pce-segment-routing-policy-cp-05 */
    TLV_SR_PREFERENCE             = 59, /**< draft-ietf-pce-segment-routing-policy-cp-05 */
    TLV_MULTIPATH_CAPABILITY      = 60, // Multipath Capability
    TLV_MULTIPATH_WEIGHT          = 61, // Multipath Weight
    TLV_MULTIPATH_BACKUP          = 62, // Multipath Backup

/** Fix me: Temporary value, needs to be changed, 
 *  31 being used by extended associtaion id
 */

    /* Below code points need to move back to IANA assigned values once 
       after IANA has assigned code point */
    /* experimental tlv type */
    TLV_PCE_EXP_START               = 65504,
    TLV_PCE_FLOWSPEC_CAPABILITY     = TLV_PCE_EXP_START, // Flowspec Capability
    TLV_FLOWSPEC_FLOWFILTER         = TLV_PCE_EXP_START + 1, // FlowFilter TLV
    TLV_BYPASS                      = TLV_PCE_EXP_START + 2, // Bypass TLV */
    //kTypeSrPolicyIdentifierDefault = kTypeTlvExpStart + 3,  // Unused: Used to support earlier version of draft
    TLV_LSP_CLEANUP                 = TLV_PCE_EXP_START + 4,
    //kTypeSrCandidatePathIdentifierDefault = kTypeTlvExpStart + 4, // Unused: Used to support earlier version of draft
    //kTypeSrPreferenceDefault     = kTypeTlvExpStart + 5,  // Unused: Used to support earlier version of draft
    TLV_MULTIPATH_PATHATTRIBUTE_COLOR_DEFAULT = TLV_PCE_EXP_START + 6,
    TLV_VENDOR_LSP_ROUTE_PREFERENCE = TLV_PCE_EXP_START + 7,
    TLV_PCE_EXP_END                 = 65535,    
    TLV_VERSION_INFO                = TLV_PCE_EXP_START + 8, // To send Junos version in the Open message
} tlv_type_t;

#define TLV_IPV4_P2MP_LSP_IDENTIFIERS ( \
		tlv_p2mp_ipv4_lsp_id_IANA_compliant ? TLV_IPV4_P2MP_LSP_IDENTIFIERS_IANA : TLV_IPV4_P2MP_LSP_IDENTIFIERS_nonIANA)

/* Not standardized values */
#define ASSOCIATION_TYPE_TE_PLUS_PLUS 65504
#define ASSOCIATION_TYPE_MAX 65535
/** SR sub tlv for the Path setup type capability tlv **/
#define SUB_TLV_SR_PCE_CAPABILITY 26

#define SR_PST_TYPE 1
#define SRV6_PST_TYPE_DEFAULT 3
#define SRV6_PCE_CAPABILITY_SUB_TLV_TYPE_DEFAULT 27

/* Association type values start*/
 #define ASSOCIATION_TYPE_PATH_PROTECTION 1 /** https://www.iana.org/assignments/pcep/
                                        pcep.xhtml#association-type-field */
 #define ASSOCIATION_TYPE_DISJOINT 2 /** RFC8800 */

 #define ASSOCIATION_TYPE_SRPAG 6

/**
 * Below MSD types are defined in IGP and is not configurable.
 * As PCCD and IGP is not communicating currently, MSD types are hard coded
 * in PCCD as well
 */
typedef enum {
    MAX_SL_MSD_TYPE = 41,
    MAX_END_POP_MSD_TYPE = 42,
    MAX_H_ENCAPS_MSD_TYPE = 44,
    MAX_END_D_MSD_TYPE = 45
} msd_types_t;

/**
 * Below MSD max values are defined in IGP and is not configurable.
 * As PCCD and IGP is not communicating currently, MSD values are hard coded
 * in PCCD as well
 */
#define MAX_SL_MSD_VALUE 6
#define MAX_END_POP_MSD_VALUE 7
#define MAX_H_ENCAPS_MSD_VALUE_DEFAULT 6
#define MAX_END_D_MSD_VALUE 6

/*
 * Below non standardized code points/values are deprecated and needs to be used with caution
 * 1. #define DEFAULT_ASSOCIATION_TYPE_SRPAG 65505
 * 2. #define TLV_SR_POLICY_IDENTIFIER_DEFAULT (TLV_PCE_EXP_START + 3)
 * 3. #define TLV_SR_CANDIDATE_PATH_IDENTIFIER_DEFAULT (TLV_PCE_EXP_START + 4)
 * 4. #define TLV_SR_PREFERENCE_DEFAULT (TLV_PCE_EXP_START + 5)
 */

#endif /* LIBPCEP_OBJECTS_H */

