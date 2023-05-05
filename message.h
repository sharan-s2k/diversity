/**
 * @file libpcep/message.h
 *
 * PCEP message definitions
 *
 * Copyright (c) 2011-2012, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: message.h 1325062 2023-03-29 15:13:08Z gchandraseka $ */
#ifndef PCEP_MESSAGE_H
#define PCEP_MESSAGE_H
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "jnx/libpcep.h"

#define MSG_HEADER_LEN 4

/**
 * A single PCEP message, parsed out
 */
struct pcep_message {
    uint8_t            version:3;
    uint8_t            flags:5;
    uint8_t            type;
    uint16_t           length;

    size_t             objcount;
    struct pcep_object *objects;
};

/**
 * Retrieve the message length from the message header
 *
 * @param[in] data Message header
 * @return the message length
 */
uint16_t
pcep_msg_length (const uint8_t data[MSG_HEADER_LEN]);

/**
 * Retrieve the number of objects contained in the message
 *
 * @param[in] data Message data
 * @param[in] msglen Message length (as given by pcep_msg_length)
 * @return the number of objects contained in the message
 */
uint16_t
pcep_msg_objcount (const uint8_t *data, uint16_t msglen);

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
                const uint8_t *data);

/**
 * Send an open message
 *
 * @param[in] conn Connection handle
 * @param[out] open_obj Open object
 * @param[in] sid Session id
 * @param[in] keepalive keepalive timer proposal
 * @param[in] deadtimer Peer deadtimer proposal
 * @param[in] flags TLV flags
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
               bool disjoint_assoc_capability);

/**
 * Send a negotiation message (PcErr message with open object)
 *
 * @param[in] conn Connection handle
 * @param[in] propopen Open object (negotiation)
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_pcerr_open (struct pcep_conn *conn, struct pcep_object *propopen);

/**
 * Send a keepalive message
 *
 * @param[in] conn Connection handle
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_msg_keepalive (struct pcep_conn *conn);

/**
 * Send a close message
 *
 * @param[in] conn Connection handle
 * @param[in] reason Close reason
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
send_msg_close (struct pcep_conn *conn, uint8_t reason);

#endif /* PCEP_MESSAGE_H */

