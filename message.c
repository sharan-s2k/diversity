/**
 * @file libpcep/message.c
 *
 * Path Computation Element Protocol, message handling code.
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: message.c 1325062 2023-03-29 15:13:08Z gchandraseka $ */
#include "message.h"

#include <assert.h>

#include "core.h"
#include "log.h"
#include "object.h"
#include "util.h"

#include <jnx/swversion.h>

/**
 * Retrieve the message length from the message header
 *
 * @param[in] data Message header
 * @return the message length
 */
uint16_t
pcep_msg_length (const uint8_t data[MSG_HEADER_LEN])
{
    return ntoh_uint16_t(data + 2);
}

/**
 * Retrieve the number of objects contained in the message
 *
 * @param[in] data Message data
 * @param[in] msglen Message length (as given by pcep_msg_length)
 * @return the number of objects contained in the message
 */
uint16_t
pcep_msg_objcount (const uint8_t *data, uint16_t msglen)
{
    uint16_t ret = 0;

    assert(msglen >= MSG_HEADER_LEN);
    msglen -= MSG_HEADER_LEN;
    data += MSG_HEADER_LEN;

    while (msglen >= OBJ_HEADER_LEN) {
        uint16_t objlen = pcep_obj_length(data);
        
        if (objlen > msglen)
            objlen = msglen;

        msglen -= objlen;
        data += objlen;
        ++ret;
    }
    return ret;
}

const char*
pcep_msg_type_to_str(pcep_msg_t message_type)
{
    switch (message_type) {
    case PCEP_MSG_OPEN:
        return "Open";
    case PCEP_MSG_KEEPALIVE:
        return "Keepalive";
    case PCEP_MSG_PC_REQUEST:
        return "PCRequest";
    case PCEP_MSG_PC_REPLY:
        return "PCReply";
    case PCEP_MSG_NOTIFICATION:
        return "PCNotification";
    case PCEP_MSG_ERROR:
        return "Error";
    case PCEP_MSG_CLOSE:
        return "Close";
    case PCEP_MSG_PC_UPDATE:
        return "PCUpdate";
    case PCEP_MSG_PC_REPORT:
        return "PCReport";
    case PCEP_MSG_PC_CREATE:
        return "PCCreate";
    case PCEP_MSG_START_TLS:
        return "StartTLS";
    }

    return "Unknwon";
}

/**
 * Parse a message
 *
 * @param[in] conn Connection handle
 * @param[out] msg Result structure for the message
 * @param[in] data Message data
 * @return true if the message is malformed
 * @attention An unknown message will return false but only the type will
 * be parsed
 */
bool
pcep_msg_parse (struct pcep_conn *conn, struct pcep_message *msg,
                const uint8_t *data)
{
    uint16_t msglen;
    uint16_t datalen;
    const uint8_t* msgdata;
    unsigned i;
    
    msg->version = *data >> 5;
    msg->flags   = *data & 0x1F;
    msg->type    = data[1];
    /*  msg->length, msg->objcount and msg->objects
     * are initialised/allocated by the caller */

    msgdata = data;
    msglen = msg->length;
    
    datalen = msg->length;

    data += MSG_HEADER_LEN;
    datalen -= MSG_HEADER_LEN;


    /* checking known message type */
    switch (msg->type) {
    case PCEP_MSG_OPEN:
    case PCEP_MSG_KEEPALIVE:
    case PCEP_MSG_CLOSE:
    case PCEP_MSG_ERROR:
    case PCEP_MSG_PC_REQUEST:
    case PCEP_MSG_PC_REPLY:
    case PCEP_MSG_PC_REPORT:
    case PCEP_MSG_PC_UPDATE:
    case PCEP_MSG_PC_CREATE:
    case PCEP_MSG_START_TLS:
        break;
    default:
        return false;
    }

    trace(conn, PCEP_TRC_IN_MSGS, "Received PCEP message type: %s, version: %d "
          "length: %u, flags: 0x%x",
          pcep_msg_type_to_str((pcep_msg_t)msg->type), msg->version,
          msg->length, msg->flags);

    /* checking non empty message */
    if (!msg->objcount &&
        ((msg->type != PCEP_MSG_KEEPALIVE) && (msg->type != PCEP_MSG_START_TLS))) {
        if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OTHER,
                   "Incorrect message received:", msgdata, msglen);
        log_error(get_pcep(conn), "Message of type %u lacking any objects",
                  msg->type);
        return true;
    }
    /* parsing objects */
    for (i = 0; i < msg->objcount; ++i) {
        uint16_t obj_len = pcep_obj_length(data);
        if (obj_len > datalen || pcep_obj_parse(conn, msg->objects + i, data,
                                                obj_len)) {
            trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OTHER,
                       "Incorrect message received:", msgdata, msglen);
            log_error(get_pcep(conn),
                      "Could not parse all objects from message");
            return true;
        }
        data += obj_len;
        datalen -= obj_len;
    }
    if (datalen > 0) {
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OTHER,
                   "Message contains data after last object:", msgdata, msglen);
        log_error(get_pcep(conn), "Message contains data after last object");
        return true;
    }

    /* checking appropriate objects */
    switch (msg->type) {
    case PCEP_MSG_OPEN:
        /* exactly one open object */
        if (msg->objcount!=1 || msg->objects->type != PCEP_OBJ_OPEN)
            break;
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OPEN,
                   "Open message received:", msgdata, msglen);
        return false;

    case PCEP_MSG_KEEPALIVE:
        /* no objects */
        if (msg->objcount!=0)
            break;
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_KEEPALIVE,
                   "Keepalive message received:", msgdata, msglen);
        return false;

    case PCEP_MSG_CLOSE:
        /* at least one close object */
        if (msg->objcount < 1 || msg->objects->type != PCEP_OBJ_CLOSE)
            break;
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_CLOSE,
                   "Close message received:", msgdata, msglen);
        return false;

    /* these messages have variable arguments, if it was properly parsed then it's ok */
    case PCEP_MSG_ERROR:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCERR,
                   "PCErr message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_PC_REQUEST:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCREQUEST,
                   "PCRequest message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_PC_REPLY:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCREPLY,
                   "PCReply message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_PC_REPORT:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCREPORT,
                   "PCReport message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_PC_UPDATE:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCUPDATE,
                   "PCUpdate message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_PC_CREATE:
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_PCUPDATE,
                   "PCCreate message received:", msgdata, msglen);
        return false;
    case PCEP_MSG_START_TLS:
        if (msg->objcount != 0)
            break;
        trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OPEN,
                   "StartTLS message received:", msgdata, msglen);
        return false;
    }
    if (get_conn_state(conn) == PCEP_CONN_SESSIONUP)
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
    trace_dump(conn, PCEP_TRC_DUMP_RECV|PCEP_TRC_DUMP_OTHER,
               "Incorrect message received:", msgdata, msglen);
    log_error(get_pcep(conn), "Malformed message of type %u", msg->type);
    return true;
}

/**
 * Send a message via a connection
 *
 * @param[in] conn Connection handle
 * @param[in] type Message type
 * @param[in] objs Array of objects contained in the message
 * @param[in] count Number of objects in the message
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
pcep_send_message (struct pcep_conn *conn, pcep_msg_t type,
                  const struct pcep_object *objs, size_t count)
{
    size_t i, len = MSG_HEADER_LEN;

    if (conn == NULL) {
        return true;
    }
    
    trace(conn, PCEP_TRC_OUT_MSGS, "Sending PCEP message '%s'",
          pcep_msg_type_to_str(type));

    for (i = 0; i < count; ++i)
        len += pcep_obj_reqlen(objs + i);

    /* Send out the header */
    if (pcep_send_byte(conn, 1 << 5))
        return true;
    if (pcep_send_byte(conn, type))
        return true;
    if (pcep_send_short(conn, len))
        return true;

    for (i = 0; i < count; ++i)
        if (pcep_send_object(conn, objs + i))
            return true;

    return false;
}

/**
 * Send an error message via a connection
 *
 * @param[in] conn Connection handle
 * @param[in] type Error type
 * @param[in] value Error value
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
pcep_send_pcerr (struct pcep_conn *conn, uint8_t type, uint8_t value)
{
    const struct pcep_object obj = {
        .type = PCEP_OBJ_PCEPERROR,
        .u    = {
            .error = {
                .type  = type,
                .value = value,
            },
        },
    };
    get_pcep(conn)->onerror(get_pcep(conn), get_context(conn), 0, &obj.u.error);
    return pcep_send_message(conn, PCEP_MSG_ERROR, &obj, 1);
}

/**
 * Send an open message
 *
 * @param[in] conn Connection handle
 * @param[out] open_obj Open object
 * @param[in] sid Session id
 * @param[in] keepalive keepalive timer proposal
 * @param[in] deadtimer Peer deadtimer proposal
 * @param[in] flags TLV flags
 * @param[in] msd maximum sid levels supported by PCCD
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_msg_open (struct pcep_conn *conn, struct pcep_obj_open *open_obj,
               uint8_t sid, uint8_t keepalive, uint8_t deadtimer,
               bool lsp_provisioning, bool p2mp_lsp_report_capblty,
               bool p2mp_lsp_update_capblty, bool p2mp_lsp_init_capblty,
               bool spring_capability, bool srv6_capability,
               unsigned flags, uint8_t msd,
               bool flowspec_capability, bool path_protection_assoc,
               bool srpag_assoc, bool multipath_capability,
               bool disjoint_assoc_capability)
{
    const struct pcep_object obj = {
        .type = PCEP_OBJ_OPEN,
        .u    = {
            .open = {
                .keepalive        = keepalive,
                .deadtimer        = deadtimer,
                .session_id       = sid,
                .version          = 1,

                .stateful         = !!(flags & PCEP_CAP_STATEFUL),
                .active           = !!(flags & PCEP_CAP_STATEFUL_ACTIVE),
                .lsp_provisioning = lsp_provisioning,
                .p2mp_lsp_report_capability = p2mp_lsp_report_capblty,
                .p2mp_lsp_update_capability = p2mp_lsp_update_capblty,
                .p2mp_lsp_init_capability = p2mp_lsp_init_capblty,
                .spring_capability = spring_capability,
                .srv6_capability  = srv6_capability,
                .msd              = msd,
                .pce_flowspec_capability = flowspec_capability,
                .path_protection_association = path_protection_assoc,
                .srpag_association = srpag_assoc,
                .multipath_capability = multipath_capability,
                .disjoint_assoc_capability = disjoint_assoc_capability,
		/* Example: when junos version is 23.1*/
		.major_version    = sw_version.sw_major, /*major_version = 23*/
		.minor_version    = sw_version.sw_minor, /*minor_version = 1*/
            },
        },
    };
    memcpy(open_obj, &obj.u.open, sizeof(obj.u.open)); // backup the open object
    return pcep_send_message(conn, PCEP_MSG_OPEN, &obj, 1);
}

/**
 * Send a negotiation message (PcErr message with open object)
 *
 * @param[in] conn Connection handle
 * @param[in] propopen Open object (negotiation)
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_pcerr_open (struct pcep_conn *conn, struct pcep_object *propopen)
{
    const struct pcep_object obj[2] = {
        {
            .type = PCEP_OBJ_PCEPERROR,
            .u    = {
                .error = {
                    .type  = PCEP_ERR_TYPE_SEF,
                    .value = PCEP_ERR_VAL_NEGOTIABLE,
                },
            },
        },
        *propopen
    };
    return pcep_send_message(conn, PCEP_MSG_ERROR, obj, 2);
}

/**
 * Send a keepalive message
 *
 * @param[in] conn Connection handle
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_msg_keepalive (struct pcep_conn *conn)
{
    return pcep_send_message(conn, PCEP_MSG_KEEPALIVE, NULL, 0);
}

/**
 * Send a close message
 *
 * @param[in] conn Connection handle
 * @param[in] reason Close reason
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_msg_close (struct pcep_conn *conn, uint8_t reason)
{
    const struct pcep_object obj = {
        .type = PCEP_OBJ_CLOSE,
        .u    = {
            .close = {
                .reason = reason,
            },
        },
    };
    return pcep_send_message(conn, PCEP_MSG_CLOSE, &obj, 1);
}
