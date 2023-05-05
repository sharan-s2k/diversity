/**
 * @file libpcep/core.c
 *
 * Path Computation Element Protocol, core protocol services.
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: core.c 1325062 2023-03-29 15:13:08Z gchandraseka $ */
#include "core.h"
#include "log.h"
#include "message.h"
#include "object.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <time.h>

#include <jnx/aux_types.h>

#include "ipc_util.h"

/* maximum bytes read in one pass from a socket */
#define MAX_READ_BYTES 1048576L

/* to check if tt is pointing to null in connection_writable function*/
#define LOCAL_TIMER_VAR 0xf5f5f5f5f5f5f5f5;

/* in seconds */
#define CONNECT_TIMER 60
#define OPENWAIT_TIMER 60
#define KEEPWAIT_TIMER 60
#define ONE_MINUTE 60
#define STARTTLSWAIT_TIMER 60
#define SA_LEN 2

/* for message-rate-limit */
static bool pcep_ignore_close = false;

/* Semi-tweakable parameters */
const size_t input_hysteresis = 16 * 1024;
const size_t input_limit = 256 * 1024;
const size_t output_hysteresis = 64 * 1024;
const size_t output_limit = 0;

/**
 * Create a new library instance.
 *
 * @param[in] ctx Opaque user context, stored in the instance object
 * @param[in] logfn Logging function, invoked whenever the library wants
 *                  to produce a log message
 * @param[in] tracefn Trace function, invoked whenever the library wants
 *                  to produce a trace message
 * @param[in] onconnect Connect function, invoked whenever the library
 *                  successfully connect to PCE peer
 * @param[in] onerror Error function, invoked whenever the library
 *                  detect an error or send or receive a PCErr message
 * @param[in] onmessage Message function, invoked whenever the library
 *                  receive a properly formated message (except for PCErr)
 * @param[in] ptr Opaque user pointer, stored in the instance object
 * @return new library instance, or NULL when a new instance cannot be
 *         allocated.
 */
struct pcep *pcep_init (evContext ctx, pcep_log_fn logfn, pcep_trace_fn tracefn,
                       pcep_onconnect_fn onconnect, pcep_onerror_fn onerror,
                       pcep_onmessage_fn onmessage, void *ptr)
{
    struct pcep *ret = calloc(1, sizeof(struct pcep));
    if (!ret) return NULL;
    ret->context   = ctx;
    ret->logfn     = logfn;
    ret->tracefn   = tracefn;
    ret->onconnect = onconnect;
    ret->onerror   = onerror;
    ret->onmessage = onmessage;
    ret->userptr   = ptr;
    return ret;
}

/**
 * Clone of private idle_timer object.
 *
 * We are adding this here because we have to look into the <uap> in "connection_writable" function
 */
typedef struct local_evTimer_s {
	evTimerFunc	func;
	void *		uap;
	struct timespec	due, inter;
	int		index;
} local_evTimer;

typedef struct {
	evTimerFunc	func;
	void *		uap;
	struct timespec	lastTouched;
	struct timespec	max_idle;
	local_evTimer *	timer;
} local_idle_timer;

/**
 * Return a free session id.
 *
 * @param[in] pcep Library instance handle as obtained from #pcep_init()
 * @param[in] sockaddress Peer socket address (to check for duplicate SID)
 * @param[out] SID
 * @return true in case of error (no free sid available)
 */
static bool
get_free_session (struct pcep *pcep, const struct sockaddr *sockaddress,
                 uint8_t *sid)
{
    static uint8_t lastsid = 0;
    struct pcep_conn* conn;
    bool found;
    
    for (*sid = lastsid+1; *sid != lastsid; (*sid)++) {
        found = false;
        SLIST_FOREACH(conn, &pcep->connections, list) {
            if ((conn->parameters->local.proposition.session_id == *sid)
                && !memcmp(conn->parameters->local.sockaddress->sa_data,
                           sockaddress->sa_data, 2)) {
                found = true;
                break;
            }
        }
        if (!found) {
            lastsid = *sid;
            return false;
        }
    }
    // we dont test last sid because it cant be re-used (if now free)
    return true;
}

/**
 * Return user pointer associated with a library instance. The returned
 * pointer is the one provided to #pcep_init().
 *
 * @param[in] pcep Library instance handle
 * @return User-supplied pointer.
 */
void *
pcep_ptr (const struct pcep *pcep)
{
    return pcep->userptr;
}

/**
 * Clear an event for a connection
 *
 * @param[in] conn Connection instance
 * @param[in] id Event id to clear
 * @return void
 */
static void
conn_clear_event (struct pcep_conn *conn, evFileID *id)
{
    if (id->opaque) {
        evDeselectFD(conn->pcep->context, *id);
        id->opaque = NULL;
    }
}

/**
 * Clear a timer for a connection
 *
 * @param[in] conn Connection instance
 * @param[in] timer Timer to clear
 * @return void
 */
static void
conn_clear_timer (struct pcep_conn *conn, evTimerID *timer)
{
    if (timer->opaque) {
        local_evTimer *t = timer->opaque;
        local_idle_timer *tt = t->uap;
        local_idle_timer *p = (local_idle_timer*)LOCAL_TIMER_VAR;
        if ((tt != p) && (tt != NULL)) {
            evClearIdleTimer(conn->pcep->context, *timer);
        }
        timer->opaque = NULL;
    }
}

/**
 * Free a connection (release associated memory blocks)
 *
 * @param[in] conn Connection instance
 * @return void
 */
static void
free_conn (struct pcep_conn *conn)
{
    assert(conn->state == PCEP_CONN_CLOSED);

    if (!SLIST_EMPTY(&conn->pcep->connections)) {
	SLIST_REMOVE(&conn->pcep->connections, conn, pcep_conn, list);
    } else {
	trace(conn, PCEP_TRC_MEMORY, "Unexpected PCEP Connection head value");
    }

    trace(conn, PCEP_TRC_MEMORY, "Releasing unknown message buffer");
    free(conn->unknown_msg_buf);
    conn->unknown_msg_buf = NULL;

    pcep_buffer_free(&conn->input);
    pcep_buffer_free(&conn->output);
    free(conn);
}

/**
 * Free a library instance, closing all related connections and releasing
 * all allocated resources.
 *
 * @param[in] pcep Library instance handle as obtained from #pcep_init()
 * @return void
 */
void
pcep_finish (struct pcep *pcep)
{
    struct pcep_conn* conn;
    while ((conn = SLIST_FIRST(&pcep->connections))) {
        /* clear timers */
        conn->state = PCEP_CONN_CLOSING;
        conn_clear_timer(conn, &conn->deadid);
        conn_clear_timer(conn, &conn->aliveid);

        /* deregister, this should block the socket for write flush */
        evCancelConn(conn->pcep->context, conn->connid);

        /* now free it */
        close(conn->fd);
        conn->state = PCEP_CONN_CLOSED;
        free_conn(conn);
    }
    free(pcep);
}

/**
 * Close a connection
 * this function tries to flush the socket if the write buffer is not empty
 * in this case the connection will enter CLOSING state
 * the CLOSED state (corresponding to a file descriptor close) will occur
 * when this function is called again (forcing CLOSED state) or when
 * the out buffer will be flushed (detected on connection_writable)
 *
 * @param[in] conn Connection instance
 * @param[in] error Error number for the onerror callback function
 * @param[in] close_msg Close reason for the close message sent to peer
 * @return true (always return true)
 */
bool
close_conn (struct pcep_conn *conn, int error, int close_msg) {
    bool closing = false;
    log_error(conn->pcep, "Closing connection with state %u, err: %d, "
              "close_msg: %d",  conn->state, error, close_msg);

    /* an error in CLOSING state will force the CLOSED state */
    closing = (conn->state == PCEP_CONN_CLOSING);

    /* clear events and report error */
    if (!closing) {
        conn->state = PCEP_CONN_CLOSING;
        conn_clear_event(conn, &conn->exceptid);
        conn_clear_event(conn, &conn->readid);
        conn_clear_timer(conn, &conn->deadid);
        conn_clear_timer(conn, &conn->aliveid);
        conn_clear_timer(conn, &conn->tlsid);
        /* writeid is not cleared because we want to flush the connection */
        if (error)
            conn->pcep->onerror(conn->pcep, conn->context, error, NULL);
        if (close_msg) {
            /* if an error occurs in send_msg_close then close_conn will be
               called recursively and as conn->state will be PCEP_CONN_CLOSING
               the connection wil be forced close and fd will be freed
               so we shouldnt try to do anything with it here */
            if (send_msg_close(conn, close_msg))
                return true;
        }
    }

    /* check if i can enter CLOSED state */
    if (closing || pcep_buffer_used(&conn->output) == 0) {
        conn_clear_event(conn, &conn->writeid);
        conn_clear_event(conn, &conn->readid);
        close(conn->fd);
        conn->state = PCEP_CONN_CLOSED;
        pcep_ssl_free(conn);
        free_conn(conn);
    }
    return true;
}

/**
 * Callback on connection timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
connect_timedout (evContext ctx, void *uap, struct timespec due UNUSED,
                 struct timespec inter UNUSED)
{
    struct pcep_conn *conn = uap;
    assert(conn->state == PCEP_CONN_TCPPENDING || conn->state == PCEP_CONN_STARTTLSWAIT
		    || conn->state == PCEP_CONN_SSLPENDING);
    
    evInitID(&conn->deadid); // clean timer
    trace(conn, PCEP_TRC_SESSION_INIT, "Failed to establish connection");
    if (conn->state == PCEP_CONN_TCPPENDING) {
	    evCancelConn(ctx, conn->connid);
    }
    log_error(conn->pcep, "Failed to establish connection: %s",
              strerror(ETIMEDOUT));
    close_conn(conn, ETIMEDOUT, 0);
}

/**
 * Callback on OPEN timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
open_timedout (evContext ctx UNUSED, void *uap, struct timespec due UNUSED,
              struct timespec inter UNUSED)
{
    struct pcep_conn *conn = uap;
    assert(conn->state == PCEP_CONN_OPENWAIT ||
           conn->state == PCEP_CONN_OPENWAIT2);

    evInitID(&conn->deadid); // clean timer
    trace(conn, PCEP_TRC_SESSION_INIT, "Timed out waiting for Open message");
    log_error(conn->pcep, "Timed out waiting for Open message");
    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_OPEN_TIMEDOUT);
    close_conn(conn, ETIMEDOUT, 0);
}

/**
 * Callback on KEEPWAIT timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
keepwait_timedout (evContext ctx UNUSED, void *uap, struct timespec due UNUSED,
                  struct timespec inter UNUSED)
{
    struct pcep_conn *conn = uap;
    assert(conn->state == PCEP_CONN_KEEPWAIT);
    
    evInitID(&conn->deadid); // clean timer
    trace(conn, PCEP_TRC_SESSION_INIT, "Timed out waiting for Keepalive message"
          " in session establishment");
    log_error(conn->pcep, "Timed out waiting for Keepalive message in session "
              "establishment");
    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_ACPT_TIMEDOUT);
    close_conn(conn, ETIMEDOUT, 0);
}

/**
 * Callback on deadtimer timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
dead_timedout (evContext ctx UNUSED, void *uap, struct timespec due UNUSED,
              struct timespec inter UNUSED)
{
    struct pcep_conn *conn = uap;
    assert(conn->state == PCEP_CONN_SESSIONUP);
    
    evInitID(&conn->deadid); // clean timer
    log_error(conn->pcep, "DeadTimer expired");
    close_conn(conn, ETIMEDOUT, PCEP_CLOSE_REASON_DEADTIMER);
}

/**
 * Callback on keepalivetimer timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
keepalive_timedout (evContext ctx UNUSED, void *uap, struct timespec due UNUSED,
                   struct timespec inter UNUSED)
{
    struct pcep_conn *conn = uap;
    evInitID(&conn->aliveid); // clean timer
    conn->statistics.keepalive_sent++;
    send_msg_keepalive(conn);
}

/**
 * Callback on exception event on the connection
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] fd socket descriptor
 * @param[in] eventmask Event mask
 * @return void
 */
static void
connection_erred (evContext ctx UNUSED, void *uap, int fd, int eventmask)
{
    struct pcep_conn *conn = uap;
    assert(eventmask == EV_EXCEPT);
    assert(fd == conn->fd);

    log_error(conn->pcep, "Connection error detected on fd %d", fd);
    close_conn(conn, ENETRESET, 0);
}

/**
 * Transition to OPENWAIT
 * this function handles both OPENWAIT and OPENWAIT2 state
 * it principally arm the OPENWAIT timer
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
transition_to_openwait (struct pcep_conn *conn)
{
    static const struct timespec ts = { .tv_sec = OPENWAIT_TIMER, };

    assert(conn->state==PCEP_CONN_TCPPENDING ||
           conn->state==PCEP_CONN_OPENWAIT ||
           conn->state==PCEP_CONN_SSLPENDING);

    conn->state = (conn->state==PCEP_CONN_OPENWAIT)?
                                PCEP_CONN_OPENWAIT2:PCEP_CONN_OPENWAIT;

    trace(conn, PCEP_TRC_SESSION_INIT, "Entering openwait state=%u",
          conn->state);

    if (evResetIdleTimer(conn->pcep->context, conn->deadid, open_timedout,
                         conn, ts) == -1) {
        const int error = errno;
        log_error(conn->pcep, "Failed to arm OpenWait timer: %s",
                  strerror(error));
        return close_conn(conn, error, 0);
    }
    if (conn->state==PCEP_CONN_OPENWAIT2)
        conn->accepted = false; // init flag
    return false;
}

/**
 * Transition to KEEPWAIT
 * this function principally arms the KEEPWAIT timer
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
transition_to_keepwait (struct pcep_conn *conn)
{
    const struct timespec ts = { .tv_sec = KEEPWAIT_TIMER, };

    trace(conn, PCEP_TRC_SESSION_INIT, "Entering keepwait state");
    conn->state = PCEP_CONN_KEEPWAIT;

    if (evResetIdleTimer(conn->pcep->context, conn->deadid, keepwait_timedout,
                         conn, ts) == -1) {
        const int error = errno;
        log_error(conn->pcep, "Failed to arm KeepWait timer: %s",
                  strerror(error));
        return close_conn(conn, error, 0);
    }
    return false;
}

/**
 * Transition to SESSION_UP
 * this function principally arms the different timers
 * and call the onconnect callback
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
transition_to_sessionup (struct pcep_conn *conn)
{
    trace(conn, PCEP_TRC_SESSION_INIT, "Entering session up state");
    conn->state = PCEP_CONN_SESSIONUP;

    /* Clear KeepWait timer or re-purpose it to Dead timer */
    if (conn->parameters->remote.active.deadtimer) {
        const struct timespec ts = {
            .tv_sec = conn->parameters->remote.active.deadtimer,
        };
        conn->next_deadtimer = time(NULL)
                               + conn->parameters->remote.active.deadtimer;
        if (evResetIdleTimer(conn->pcep->context, conn->deadid, dead_timedout,
                             conn, ts) == -1) {
            const int error = errno;
            log_error(conn->pcep, "Failed to arm Dead timer: %s",
                      strerror(error));
            return close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
        }
	trace(conn, PCEP_TRC_SESSION_INIT, "Deadtimer has been armed: %usec", 
	      conn->parameters->remote.active.deadtimer);
    } else {
        conn_clear_timer(conn, &conn->deadid);
	trace(conn, PCEP_TRC_SESSION_INIT, "Deadtimer is turned off");
    }

    /* Arm the Keepalive timer */
    if (conn->parameters->local.active.keepalive) {
        const struct timespec ts = {
            .tv_sec = conn->parameters->local.active.keepalive,
        };
        if (evSetIdleTimer(conn->pcep->context, keepalive_timedout, conn, ts,
                           &conn->aliveid) == -1) {
            const int error = errno;
            log_error(conn->pcep, "Failed to start Keepalive timer: %s",
                      strerror(error));
            return close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
        }
    }
    conn->pcep->onconnect(conn->pcep, conn->context);
    return false;
}

/**
 * Callback on connection writable
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] fd socket descriptor
 * @param[in] eventmask Event mask
 * @return void
 */
static void
connection_writable (evContext ctx UNUSED, void *uap, int fd, int eventmask)
{
    size_t datalen;
    const void *data;
    struct pcep_conn *conn = uap;
    ssize_t wl;
    
    assert(eventmask == EV_WRITE);
    assert(fd == conn->fd);

    /* Acquire current output buffer contents */

    data = pcep_buffer_data(&conn->output, &datalen);

    /* Write the buffer out */
    if (!conn->parameters->pceps_session) {
       wl = write(fd, data, datalen);
    } else {
       trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: SSL_Write_func");
        wl = pcep_ssl_write(conn, data, datalen);
    }
    if (wl == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
        const int error = errno;
        log_error(conn->pcep, "Failed to write %zu bytes: %s",
                  wl, strerror(error));
        close_conn(conn, error, 0);
        return;
    }
    if (wl > 0)
        pcep_buffer_drain(&conn->output, wl);

    /* De-activate event if there is no more data */
    if (pcep_buffer_used(&conn->output) == 0) {
        if (conn->state == PCEP_CONN_CLOSING) {
            // finish to close the connection while the output buffer is empty */
            close_conn(conn, 0, 0);
            return;
        }
        conn_clear_event(conn, &conn->writeid);
    }

    /* adjust the keepalive timer accordingly */
    if (conn->parameters->local.active.keepalive
        && conn->state==PCEP_CONN_SESSIONUP) {
        if (conn->aliveid.opaque) {
            /* touch Keepalive timer */
            local_evTimer *t = conn->aliveid.opaque;
	    local_idle_timer *tt = t->uap;
            local_idle_timer *p = (local_idle_timer*)LOCAL_TIMER_VAR;
	    if ((tt != p) && (tt != NULL)) {
                if (evTouchIdleTimer(conn->pcep->context, conn->aliveid) == -1) {
                    const int error = errno;
                    log_error(conn->pcep, "Failed to re-arm Keepalive timer: %s",
                            strerror(error));
                    close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
                }
            } else {
                /* restart the Keepalive timer */
                const struct timespec ts = {
                    .tv_sec = conn->parameters->local.active.keepalive,
                };
                if (evSetIdleTimer(conn->pcep->context, keepalive_timedout, conn,
                                ts, &conn->aliveid) == -1) {
                    const int error = errno;
                    log_error(conn->pcep, "Failed to restart Keepalive timer: %s",
                            strerror(error));
                    close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
		    return;
                }
            }
        } else {
            /* restart the Keepalive timer */
            const struct timespec ts = {
                .tv_sec = conn->parameters->local.active.keepalive,
            };
            if (evSetIdleTimer(conn->pcep->context, keepalive_timedout, conn,
                               ts, &conn->aliveid) == -1) {
                const int error = errno;
                log_error(conn->pcep, "Failed to restart Keepalive timer: %s",
                          strerror(error));
                close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
                return;
            }
        }
    }
}

/**
 * Callback on START TLS WAIT timed out
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] due UNUSED
 * @param[in] inter UNUSED
 * @return void
 */
static void
starttlswait_timedout (evContext        ctx UNUSED,
                       void            *uap,
                       struct timespec  due UNUSED,
                       struct timespec  inter UNUSED)
{
    struct pcep_conn *conn = uap;

    if (conn->state != PCEP_CONN_STARTTLSWAIT) {
	    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Starttls Timed out, wrong state");
	    return;
    }

    evInitID(&conn->tlsid);
    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Timed out waiting for Start TLS message"
                                       " in session establishment");
    log_error(conn->pcep, "Timed out waiting for Start TLS message in session "
                          "establishment");
    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_ACPT_TIMEDOUT);
    close_conn(conn, ETIMEDOUT, 0);
}

/**
 * Transition to Start TLS message wait
 * this function principally arms the different timers
 * and call the onconnect callback
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
transition_to_tlswait (struct pcep_conn *conn)
{
   const struct timespec ts = {
        .tv_sec = conn->parameters->tls_wait_timer,
    };

    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Entering tls wait state tval:%d", conn->parameters->tls_wait_timer);
    conn->state = PCEP_CONN_STARTTLSWAIT;

    if (evSetIdleTimer(conn->pcep->context, starttlswait_timedout, conn, ts,
			    &conn->tlsid) == -1) {
        const int error = errno;
        log_error(conn->pcep, "PCEPS: Failed to arm Start TLS wait timer: %s",
                  strerror(error));
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_STARTTLS, PCEP_ERR_VAL_STARTTLS_WAIT_TIMER_EXIPRY);
        return close_conn(conn, error, 0);
    }
    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Exiting tls wait state");
    return false;
}

/**
 * This function registers the write event on the socket
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
activate_write (struct pcep_conn *conn)
{
    if (!conn->writeid.opaque && pcep_buffer_used(&conn->output)) {
        if (evSelectFD(conn->pcep->context, conn->fd, EV_WRITE,
                       connection_writable, conn, &conn->writeid) == -1) {
            const int error = errno;
            log_error(conn->pcep, "Failed to initialize write event: %s",
                      strerror(error));
            return close_conn(conn, error, 0);
        }
    }
    return false;
}

/**
 * This function sends data on the socket
 *
 * @param[in] conn Connection instance
 * @param[in] data Pointer to the data to send
 * @param[in] count Number of bytes to send
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
bool
pcep_conn_send (struct pcep_conn *conn, const void *data, size_t count)
{
    if (pcep_buffer_append(&conn->output, data, count)) {
        log_error(conn->pcep, "Failed to append %zu bytes of output data",
                  count);
        return close_conn(conn, ENOMEM, 0);
    }
    return activate_write(conn);
}

/**
 * Find appropriate keepalive value in the range <min_keep:max_keep>, where
 * the resulting keepalive will be at least 2 times lower than selected
 * deadtimer.
 * @param min_keep[in] Lower boundary for keepalive
 * @param max_keep[in[ Upper boundary for keepalive
 * @param deadtimer[in] Selected deadtimer to compute keepalive from.
 * @return Positive keepalive value, or -1 if such keepalive couldn't be found.
 */
static int
find_keepalive_for_deadtimer(unsigned min_keep, unsigned max_keep,
                             unsigned deadtimer)
{
    unsigned i = deadtimer / 2;
    
    if (min_keep == 0)
        return -1;
    if (max_keep !=  0 && max_keep < i) {
        i = max_keep;
    }

    for (; i >= min_keep; i--) {
        if (i*2 <= deadtimer) {
            return i;
        }
    }

    return -1;
}

/**
 * This function handles the peer open message
 * it checks the parameters and close the connection or enter the appropriate
 * state (OPENWAIT2, KEEPWAIT, SESSION_UP) depending on actual state
 * and accepted flag. It will also send then the counter-proposition in case it
 * enters OPENWAIT2.

 * @param[in] conn Connection instance
 * @param[in] msg Peer open message
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
process_peer_open (struct pcep_conn *conn, const struct pcep_message *msg)
{
    const struct pcep_obj_open *openobj;
    struct pcep_obj_open *propopen;
    struct pcep_object proposed = {
        .type = PCEP_OBJ_OPEN,
    };
    int res = 0;
    bool acceptable = true;
    bool ignore_deadtimer = false;
    

    trace(conn, PCEP_TRC_SESSION_INIT, "Processing peer open msg");
    /* msg type is PCEP_MSG_OPEN */
    openobj = &msg->objects->u.open;

    propopen = &proposed.u.open;

    if (conn->state == PCEP_CONN_OPENWAIT)
        memcpy(&conn->parameters->remote.proposition, openobj,
               sizeof(*openobj));

    memcpy(propopen, openobj, sizeof(*propopen)); // init counter proposition
    
    /* We accept only version 1 protocol */
    if (openobj->version != 1) {
        log_error(conn->pcep, "Proposed OPEN not acceptable: protocol version "
                  "is not 1 (%u)", openobj->version);
        propopen->version = 1;
        acceptable = false;
    }

    /* Warn on forbidden semantics */
    if (!openobj->keepalive && openobj->deadtimer) {
        log_error(conn->pcep, "Peer advertized mismatched timers (keepalive=%u "
                  "deadtimer=%u), fixed", openobj->keepalive,
                  openobj->deadtimer);
        propopen->deadtimer = 0;
        /* for correct deadtimer triggering - ignoring in this case */
	ignore_deadtimer = true;
    }
    /** RFC 8664:
     * If a PCEP speaker receives a PATH-SETUP-TYPE-CAPABILITY TLV with a
     * PST list containing PST=1, and supports that path setup type, then it
     * checks for the presence of the SR-PCE-CAPABILITY sub-TLV.If that
     * sub-TLV is absent, then the PCEP speaker MUST send a PCErr message
     * with Error-Type = 10 ("Reception of an invalid object") and Error-
     * value = 12 ("Missing PCE-SR-CAPABILITY sub-TLV") and MUST then close
     * the PCEP session.  If a PCEP speaker receives a PATH-SETUP-TYPE-
     * CAPABILITY TLV with a SR-PCE-CAPABILITY sub-TLV, but the PST list
     * does not contain PST=1, then the PCEP speaker MUST ignore the SR-PCE-
     * CAPABILITY sub-TLV.
     */
    if ((true == openobj->is_sr_pst_present) &&
        (true == openobj->path_setup_type_capability) &&
        (false == openobj->spring_capability)) {
        log_error(conn->pcep, " SR PST is received but SR-PCE-CAPABILITY sub-TLV is missing in PATH-SETUP-TYPE-CAPABILITY TLV");
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_RIO, PCEP_ERR_VAL_MISSING_PCE_SR_CAPABILITY_SUB_TLV);
        return close_conn(conn, EINVAL, 0);
    }
    /* We accept keepalives */
    if (conn->parameters->constraints.remote.keepalive.min_value) {
        if (openobj->keepalive
            && conn->parameters->constraints.remote.keepalive.min_value >
                openobj->keepalive) {
            /* We accept keepalives, but not more often than one in N seconds */
            log_error(conn->pcep, "Proposed OPEN not acceptable: keepalive %u "
                      "below minimum %u", openobj->keepalive,
                      conn->parameters->constraints.remote.keepalive.min_value);
            propopen->keepalive = conn->parameters->remote.proposal.keepalive;
            propopen->deadtimer = conn->parameters->remote.proposal.peer_deadtimer;
            acceptable = false;
        }
    }
    /* We want keepalives, but at least one in N seconds */
    if (conn->parameters->constraints.remote.keepalive.max_value) {
        if (!openobj->keepalive ||
            openobj->keepalive >
                conn->parameters->constraints.remote.keepalive.max_value) {
            log_error(conn->pcep, "Proposed OPEN not acceptable: keepalive %u "
                      "above maximum %u", openobj->keepalive,
                      conn->parameters->constraints.remote.keepalive.max_value);
            propopen->keepalive = conn->parameters->remote.proposal.keepalive;
            propopen->deadtimer =
                conn->parameters->remote.proposal.peer_deadtimer;
            acceptable = false;
        }
    }
    /* We do not want any keepalives */
    if (!conn->parameters->constraints.remote.keepalive.min_value
        && openobj->keepalive) {
        log_error(conn->pcep, "Proposed OPEN not acceptable: non-zero "
                              "keepalive %u", openobj->keepalive);
        propopen->keepalive = 0;
        propopen->deadtimer = 0;
        acceptable = false;
    }
    /* Check Stateful extension negotiation */
    if (conn->parameters->constraints.req_caps & PCEP_CAP_STATEFUL
        && !openobj->stateful) {
        log_error(conn->pcep, "Proposed OPEN not acceptable: not stateful");
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NO_NEGOTIATION);
        return close_conn(conn, EINVAL, 0);
    }
    if (conn->parameters->constraints.req_caps & PCEP_CAP_STATEFUL_ACTIVE
        && !openobj->active) {
        log_error(conn->pcep, "Proposed OPEN not acceptable: not active "
                              "stateful");
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NO_NEGOTIATION);
        return close_conn(conn, EINVAL, 0);
    }

    /* check for mismatched values of active stateful PCE capability in openmsg */
    if (conn->parameters->constraints.req_caps) {
        if ((!!((conn->parameters->constraints.req_caps
                | conn->parameters->constraints.opt_caps)
                & PCEP_CAP_STATEFUL_ACTIVE))
                != openobj->active) {
            if (conn->state == PCEP_CONN_OPENWAIT) {
                proposed.u.open.active = 0;
            /* 
             * We moved to draft draft-pce-pce-initiated-lsp-03 so we must not send
             * pcerr in this scenario. Commenting out below function call.
             */ 
            //  send_pcerr_open (conn, &proposed);
            } else {
                log_error(conn->pcep, "Mismatched Active stateful PCE"
                          "capability negotiation on the PCEP session. "
                          "Closing connection");
                return close_conn(conn, EINVAL, 0);
            }
        }
    }

    /* check for mismatched values of segment routing capability in openmsg */
    if (conn->parameters->constraints.req_caps) {
        if ((!!((conn->parameters->constraints.req_caps
                | conn->parameters->constraints.opt_caps)
                & conn->parameters->local.proposition.spring_capability))
                != openobj->spring_capability) {
            if (conn->state == PCEP_CONN_OPENWAIT) {
                proposed.u.open.spring_capability = 0;
            /* 
             * We moved to draft draft-pce-pce-initiated-lsp-03 so we must not send
             * pcerr in this scenario. Commenting out below function call.
             */ 
            //  send_pcerr_open (conn, &proposed);
            } else {
                log_error(conn->pcep, "Mismatched segment routing PCE"
                          "capability negotiation on the PCEP session. "
                          "Closing connection");
                return close_conn(conn, EINVAL, 0);
            }
        }
    }

    /**
     * draft-ietf-pce-segment-routing-ipv6-09:
     * If a PCEP speaker receives a PATH-SETUP-TYPE-CAPABILITY TLV with a
     * PST list containing PST=TBD2, but the SRv6-PCE-CAPABILITY sub-TLV is
     * absent, then the PCEP speaker MUST send a PCErr message with Error-
     * Type 10 (Reception of an invalid object) and Error-Value TBD5 (to be
     * assigned by IANA) (Missing PCE-SRv6-CAPABILITY sub-TLV) and MUST then
     * close the PCEP session.
     */
    if ((true == openobj->is_srv6_pst_present) &&
            (false == openobj->srv6_capability)) {
        log_error(conn->pcep, " SRv6 PST is received but SRv6-PCE-CAPABILITY sub-TLV"
                " is missing in PATH-SETUP-TYPE-CAPABILITY TLV");
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_RIO, PCEP_ERR_VAL_MISSING_SRV6_CAP_SUB_TLV);
        return close_conn(conn, EINVAL, 0);
    }

    /* check for appropriate deadtimer proposed by peer */
    if ((openobj->deadtimer < 2*openobj->keepalive)
        && (openobj->deadtimer != UINT8_MAX)) {
        log_error(conn->pcep, "deadtimer should be at least twice keepalive "
                  "timer (or 255) (keepalive %u deadtimer=%u)",
                  openobj->keepalive, openobj->deadtimer);
        acceptable = false;
    }

    /* adjust deadtimer if needed for counter-proposal */
    if ((propopen->deadtimer < 2*propopen->keepalive)
        && (propopen->deadtimer != UINT8_MAX)) {
        propopen->deadtimer = (2*propopen->keepalive > UINT8_MAX)?
            UINT8_MAX : 2*propopen->keepalive;
    }

    /* check that the result deadtimer is not greater than the maximum set by user */
    if ((propopen->deadtimer >
        conn->parameters->constraints.local.max_deadtimer) &&
	    (conn->parameters->constraints.local.max_deadtimer != 0)) {
        propopen->deadtimer =
                conn->parameters->constraints.local.max_deadtimer;

        res = find_keepalive_for_deadtimer(conn->parameters->constraints.remote.keepalive.min_value,
                                             conn->parameters->constraints.remote.keepalive.max_value,
                                             propopen->deadtimer);
        if (res < 0) {
            log_error(conn->pcep, "deadtimer greater than specified limit "
                      "(deadtimer=%u limit=%u)", propopen->deadtimer,
                      conn->parameters->constraints.local.max_deadtimer);
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NO_NEGOTIATION);
            return close_conn(conn, EINVAL, 0);
        }
        propopen->keepalive = res;
        log_error(conn->pcep, "Deadtimer in open object (%u) greater than set "
                  "maximum (%u), using keepalive: %u deadtimer: %u in counter "
                  "proposition", openobj->deadtimer,
                  conn->parameters->constraints.local.max_deadtimer,
                  propopen->keepalive, propopen->deadtimer);
        acceptable = false;
    }
    if (conn->parameters->local.proposition.multipath_capability &&
        (openobj->multipath_capability == false)) {
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NO_NEGOTIATION);
        log_error(conn->pcep, " PCE is not multipath capable. closing the PCEP connection");
        return close_conn(conn, EINVAL, 0);
    }
    conn->parameters->remote.proposition.multipath_capability = openobj->multipath_capability;
    conn->parameters->remote.proposition.max_segment_list = openobj->max_segment_list;

    if (conn->parameters->local.proposition.disjoint_assoc_capability &&
        (openobj->disjoint_assoc_capability == false)) {
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NO_NEGOTIATION);
        log_error(conn->pcep, " PCE is not disjoint association capable. "
                  "closing the PCEP connection");
        return close_conn(conn, EINVAL, 0);
    }
    conn->parameters->remote.proposition.disjoint_assoc_capability =
                                                        openobj->disjoint_assoc_capability;

    /* send new proposition if this one was not acceptable */
    if (!acceptable) {
        if (conn->state == PCEP_CONN_OPENWAIT) {
            memcpy(&conn->parameters->remote.negotiation, openobj,
                   sizeof(*openobj)); // backup negotiation
            /* 
             * We moved to draft draft-pce-pce-initiated-lsp-03 so we must not send
             * pcerr in this scenario. Commenting out below function call.
             */ 
            // send_pcerr_open(conn, &proposed);
            return transition_to_openwait(conn);
        } else {
            /* still not acceptable */
            memcpy(&conn->parameters->remote.active, openobj, sizeof(*openobj)); // last proposition
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                            PCEP_ERR_VAL_STILL_NOT_ACPT);
            return close_conn(conn, EINVAL, 0);
        }
    }

    /* Proposition accepted, send keepalive message as answer */
    memcpy(&conn->parameters->remote.active, openobj, sizeof(*openobj)); // backup last proposition
    if (ignore_deadtimer == true) {
	conn->parameters->remote.active.deadtimer = 0;
    }
    if (send_msg_keepalive(conn))
        return true;
    
    /* transition to KEEPWAIT or SESSIONUP depending on state and accepted flag */
    if (conn->state==PCEP_CONN_OPENWAIT2 && conn->accepted)
        return transition_to_sessionup(conn);
    else
        return transition_to_keepwait(conn);
}

/**
 * This function handles the peer negotiation message (PCErr open)
 * it checks the parameters and close the connection if they are not acceptable.
 * Otherwise it send back an open message to the peer with these parameters
 * The connection state remains same in this case.

 * @param[in] conn Connection instance
 * @param[in] msg Peer open message
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static
bool process_peer_negotiation (struct pcep_conn *conn,
                               const struct pcep_message *msg)
{
    const struct pcep_obj_open *openobj = NULL;
    trace(conn, PCEP_TRC_SESSION_INIT, "Processing peer negotiation msg");
    /* msg type is PCEP_MSG_ERROR */
    switch (msg->objects->type) {
    case PCEP_OBJ_PCEPERROR:
        /* examine peer counter proposition */
        if (msg->objcount==2 && msg->objects[1].type == PCEP_OBJ_OPEN) {
            openobj = &msg->objects[1].u.open;
            memcpy(&conn->parameters->local.negotiation, openobj,
                   sizeof(*openobj)); // backup negotiation

            /* We accept only version 1 protocol */
            if (openobj->version != 1) {
                log_error(conn->pcep, "Proposed OPEN not acceptable in counter "
                          "proposition: protocol version is not 1 (%u)",
                          openobj->version);
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }

            /* refuse forbidden semantics */
            if (!openobj->keepalive && openobj->deadtimer) {
                log_error(conn->pcep, "Peer advertized mismatched timers in "
                    "counter proposition (keepalive=%u deadtimer=%u), fixed",
                    openobj->keepalive, openobj->deadtimer);
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }
            /* We accept to send keepalives */
            if (conn->parameters->constraints.local.keepalive.min_value) {
                if (openobj->keepalive &&
                    conn->parameters->constraints.local.keepalive.min_value >
                        openobj->keepalive) {
                    /* We accept to send keepalives, but not more often than one in N seconds */
                    log_error(conn->pcep, "Proposed OPEN not acceptable in "
                        "counter proposition: keepalive %u below minimum %u",
                        openobj->keepalive,
                        conn->parameters->constraints.local.keepalive.min_value);
                    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                    PCEP_ERR_VAL_NEGO_NOT_ACPT);
                    return close_conn(conn, EINVAL, 0);
                }
            }
            /* We want to send keepalives, but at least one in N seconds */
            if (conn->parameters->constraints.local.keepalive.max_value) {
                if (!openobj->keepalive ||
                    openobj->keepalive >
                        conn->parameters->constraints.local.keepalive.max_value) {
                    log_error(conn->pcep, "Proposed OPEN not acceptable in "
                        "counter proposition: keepalive %u above maximum %u",
                        openobj->keepalive,
                        conn->parameters->constraints.local.keepalive.max_value);
                    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                    PCEP_ERR_VAL_NEGO_NOT_ACPT);
                    return close_conn(conn, EINVAL, 0);
                }
            }
            /* We do not want to send any keepalives */
            if (!conn->parameters->constraints.local.keepalive.min_value &&
                openobj->keepalive) {
                log_error(conn->pcep, "Proposed OPEN not acceptable in counter "
                          "proposition: non-zero keepalive %u",
                          openobj->keepalive);
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }
            /* Check Stateful extension negotiation */
            if (conn->parameters->constraints.req_caps & PCEP_CAP_STATEFUL &&
                !openobj->stateful) {
                log_error(conn->pcep, "Proposed OPEN not acceptable in counter "
                          "proposition: not stateful");
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }
            if (conn->parameters->constraints.req_caps &
                PCEP_CAP_STATEFUL_ACTIVE && !openobj->active) {
                log_error(conn->pcep, "Proposed OPEN not acceptable in counter "
                          "proposition: not active stateful");
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }

            /* check for appropriate deadtimer proposed by peer */
            if ((openobj->deadtimer < 2*openobj->keepalive) &&
                (openobj->deadtimer != UINT8_MAX)) {
                log_error(conn->pcep, "deadtimer should be at least twice "
                          "keepalive timer (or 255) in counter proposition "
                          "(keepalive %u deadtimer=%u)", openobj->keepalive,
                          openobj->deadtimer);
                pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                PCEP_ERR_VAL_NEGO_NOT_ACPT);
                return close_conn(conn, EINVAL, 0);
            }

            /* counter proposition accepted, let's work with it */
            memcpy(&conn->parameters->local.active, openobj, sizeof(*openobj));
            return pcep_send_message(conn, PCEP_MSG_OPEN, msg->objects+1, 1);
        }
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_NEGO_NOT_ACPT);
        return close_conn(conn, EINVAL, 0);
    default:
        log_error(conn->pcep, "Unexpected object in PCErr message (class=%u "
                  "type=%u)", PCEP_OBJCLASS(msg->objects->type),
                  PCEP_OBJTYPE(msg->objects->type));
        pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_BAD_OPEN);
    }
    return close_conn(conn, EINVAL, 0);
}

/**
 * This function checks if maximum of the unknown message rate was reached
 * Take actual index in unknown messages buffer, loop for 0 to max unknown
 * messages and check if any unknown message time index is higher than 1 minute.
 * If yes, then max unknown messages limit was not reached.
 *
 * @param[in] conn Connection instance
 * @param[in] ts Time (actual)
 * @return true if it was reached
 */

static bool
check_max_unknown_messages(struct pcep_conn *conn, time_t ts)
{
    unsigned long max;
    long i;

    if (conn->max_unknown_messages == 0) {
        return false;
    }
    i = conn->unknown_msg_idx;
    for (max = 0; max < conn->max_unknown_messages; max++) {
        if ((ts - conn->unknown_msg_buf[i]) > ONE_MINUTE) {
            return false;
        }
        i--;
        if (i < 0) {
            i = (conn->max_unknown_messages - 1);
        }
    }
    trace(conn, PCEP_TRC_IN_MSGS, "Reached max unknown mesaages");
    return true;
}

/**
 * This function handles the unknown message counter
 * Check if the max unknown messages was reached, increment the unknown
 * message counter and close the connection if needed
 *
 * @param[in] conn Connection instance
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
add_unknown_message (struct pcep_conn * conn)
{
    time_t ts = time(NULL);

    if (pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC)) {
        return true;
    }
    if (conn->max_unknown_messages == 0) {
        return false;
    }
    conn->unknown_msg_buf[conn->unknown_msg_idx] = ts;
    if (check_max_unknown_messages(conn, ts) == true) {
        return close_conn(conn, EINVAL, PCEP_CLOSE_REASON_MANY_MSGS);
    }
    conn->unknown_msg_idx++;
    conn->statistics.unknown_messages++;
    if (conn->unknown_msg_idx >= conn->max_unknown_messages) {
        conn->unknown_msg_idx = 0;
    }

    return false;
}

/**
 * This function allocates max unknown messages buffer
 *
 * @param[in] conn Connection instance
 * @return void
 */
static bool
pcep_alloc_max_unknown_messages_buffer (struct pcep_conn *conn)
{
    if (conn == NULL) {
        return true;
    }	
    if (conn->unknown_msg_buf != NULL) {
        trace(conn, PCEP_TRC_MEMORY, "Releasing unknown message buffer");
        free(conn->unknown_msg_buf);
        conn->unknown_msg_buf = NULL;
    }
    trace(conn, PCEP_TRC_MEMORY, "Allocating unknown message buffer with "
          "size=%u", conn->max_unknown_messages);
    if (conn->max_unknown_messages > 0) {
        conn->unknown_msg_buf = calloc(conn->max_unknown_messages, sizeof(time_t));
        if (conn->unknown_msg_buf == NULL) {
            errno = ENOMEM;
            log_error(conn->pcep, "Failed to calloc 'unknown_msg_buf': %s",
                      strerror(errno));
            return true;
        }
    }
    conn->unknown_msg_idx = 0;
    return false;
}

void
pcep_temporary_ignore_close(void)
{
    pcep_ignore_close = true;
}

/**
 * This function processes the peer message

 * @param[in] conn Connection instance
 * @param[in] msg Peer message
 * @return true if an error occured
 * @attention If an error occured the connection was closed!
 */
static bool
process_message (struct pcep_conn *conn, const struct pcep_message *msg)
{
    /* first check message version */
    if (msg->version != 1) {
        if (conn->state == PCEP_CONN_SESSIONUP) {
            conn->statistics.corrupted_messages++;
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
            return close_conn(conn, EINVAL, PCEP_CLOSE_REASON_MALFORMED);
        } else {
            /* during session establishment we respond with 1 8 */
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_VERS_SUPPORT);
            return close_conn(conn, EINVAL, 0);
        }
    }

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
        log_error(conn->pcep, "Message of type %u unknown", msg->type);
    }

    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: received pcep msg %u conn state %u",
          msg->type, conn->state);
    switch (conn->state) {
    case PCEP_CONN_STARTTLSWAIT:
        if (!conn->parameters->local.tls_enable) {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_STARTTLS, PCEP_ERR_VAL_CONN_WITHOUT_TLS_ERR);
            log_error(conn->pcep, "PCEPS: TLS not enabled, closing connection");
            return close_conn(conn, EINVAL, 0);
        }
        if (msg->type == PCEP_MSG_OPEN) {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_STARTTLS, PCEP_ERR_VAL_CONN_WITH_TLS_ERR);
            log_error(conn->pcep, "PCEPS: Unexpected OPEN message during Start TLS wait");
            return close_conn(conn, EINVAL, 0);
        } else if (msg->type == PCEP_MSG_ERROR) {
            log_error(conn->pcep, "PCEPS: Unexpected PCEP Error message during Start TLS wait");
            return close_conn(conn, EINVAL, 0);
        } else if (msg->type != PCEP_MSG_START_TLS) {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_STARTTLS, PCEP_ERR_VAL_RCV_UNEXPECTED_MSG);
            log_error(conn->pcep, "PCEPS: Unexpected message %u during Start TLS wait", msg->type);
            return close_conn(conn, EINVAL, 0);
        }

        conn_clear_timer(conn, &conn->tlsid);
        conn->parameters->remote.tls_enable = true;
        conn->state = PCEP_CONN_SSLPENDING;

        prepare_tls(conn);
        create_tls(conn->pcep->context, (void *)conn, NULL);
        return false;
    case PCEP_CONN_OPENWAIT:
        if (msg->type == PCEP_MSG_START_TLS) {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_STARTTLS, PCEP_ERR_VAL_CONN_WITHOUT_TLS_ERR);
            log_error(conn->pcep, "PCEP: Unexpected Start TLS message during OpenWait state");
	    conn->parameters->remote.tls_enable = true;
            return close_conn(conn, EINVAL, 0);
        }
        conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                              msg->type, msg->objects, msg->objcount);
        if (msg->type != PCEP_MSG_OPEN) {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_BAD_OPEN);
            log_error(conn->pcep, "PCEP: Unexpected message %u during OpenWait state");
            return close_conn(conn, EINVAL, 0);
        }
        return process_peer_open(conn, msg);
            
    case PCEP_CONN_OPENWAIT2:
        conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                              msg->type, msg->objects, msg->objcount);
        /* peer accepted our parameters while we are in OPENWAIT2 state */
        if (msg->type == PCEP_MSG_KEEPALIVE) {
            conn->accepted = true;
            return false;
        /* peer try to negotiate our parameters while we are in OPENWAIT2 state */
        } else if (msg->type == PCEP_MSG_ERROR) {
             return process_peer_negotiation(conn, msg);
        /* checking peer open */
        } else if (msg->type == PCEP_MSG_OPEN) {
             return process_peer_open(conn, msg);
        } else {
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF, PCEP_ERR_VAL_BAD_OPEN);
            log_error(conn->pcep, "Unexpected message %u during OpenWait2 state");
            return close_conn(conn, EINVAL, 0);
        }

    case PCEP_CONN_KEEPWAIT:
        conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                              msg->type, msg->objects, msg->objcount);
        switch ((pcep_msg_t)msg->type) {
        case PCEP_MSG_KEEPALIVE:
            memcpy(&conn->parameters->local.active,
                   &conn->parameters->local.proposition,
                   sizeof(conn->parameters->local.active));
            return transition_to_sessionup(conn);

        case PCEP_MSG_ERROR:
            return process_peer_negotiation(conn, msg);

        default:
            log_error(conn->pcep, "Unexpected message %u in KeepWait state",
                      msg->type);
            pcep_send_pcerr(conn, PCEP_ERR_TYPE_CNS, PCEP_ERR_VAL_GENERIC);
            return close_conn(conn, EINVAL, 0);
        }
        
    case PCEP_CONN_SESSIONUP:
        /* touch the deadtimer */
        if (conn->parameters->remote.active.deadtimer) {
            conn->next_deadtimer = time(NULL)
                                   + conn->parameters->remote.active.deadtimer;
            local_evTimer *t = conn->deadid.opaque;
	     local_idle_timer *tt = t->uap;
            local_idle_timer *p = (local_idle_timer*)LOCAL_TIMER_VAR;
            if ((tt != p) && (tt != NULL)) {
                if (evTouchIdleTimer(conn->pcep->context, conn->deadid) == -1) {
                    const int error = errno;
                    log_error(conn->pcep, "Failed to touch Dead timer: %s",
                              strerror(error));
                    return close_conn(conn, error, PCEP_CLOSE_REASON_UNKNOWN);
                }
	    }
	    trace(conn, PCEP_TRC_ALL, "Deadtimer has been touched");
        }

        switch ((pcep_msg_t)msg->type) {
        case PCEP_MSG_KEEPALIVE:
            /* Normal keepalive, nothing to do */
            conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                                  msg->type, msg->objects, msg->objcount);
            conn->statistics.keepalive_recv++;
            return false;

        case PCEP_MSG_CLOSE:
            conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                                  msg->type, msg->objects, msg->objcount);
            log_error(conn->pcep, "Close message received by peer");
            if (pcep_ignore_close) {
                trace(conn, PCEP_TRC_ALL, "Close message ignored (message-rate-limit reached)");
                pcep_ignore_close = false;
                return false;
            } else {
                return close_conn(conn, EINVAL, 0);
            }

        case PCEP_MSG_ERROR:
        case PCEP_MSG_NOTIFICATION:
        case PCEP_MSG_PC_REPLY:
        case PCEP_MSG_PC_REQUEST:
        case PCEP_MSG_PC_UPDATE:
        case PCEP_MSG_PC_CREATE:
        case PCEP_MSG_PC_REPORT:
            conn->pcep->onmessage(conn->pcep, conn->context, conn, conn->state,
                                  msg->type, msg->objects, msg->objcount);
            return false;

        default:
            break;
        }
        log_error(conn->pcep, "Unexpected message %u in SessionUp state",
                  msg->type);
        return add_unknown_message(conn);
    default:
        log_error(conn->pcep, "Unexpected connection state %u", conn->state);
        abort();
    }
    return true;
}

/**
 * Callback on connection readable
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] fd socket descriptor
 * @param[in] eventmask Event mask
 * @return void
 */
void
connection_readable (evContext ctx UNUSED, void *uap, int fd, int eventmask)
{
    struct pcep_conn *conn = uap;
    long readbytes = 0L;

    assert(eventmask == EV_READ);
    if (fd != conn->fd) {
	log_error(conn->pcep, "Connection fd Mis-match ev_fd:%d conn_fd:%d", fd, conn->fd);
        close_conn(conn, EINVAL, 0);
        return;
    }

    /* Loop while data is available */
    while (readbytes < MAX_READ_BYTES) {
        unsigned char buffer[65536];
        size_t buflen = sizeof(buffer);

        /* Trim read length to fit into buffer limit */
        if (pcep_buffer_limit(&conn->input)) {
            const size_t rem = pcep_buffer_available(&conn->input);
            if (rem == 0) {
                log_error(conn->pcep, "Buffer capacity reached and no "
                          "progress made");
                close_conn(conn, ENOMEM, (conn->state==PCEP_CONN_SESSIONUP)?
                           PCEP_CLOSE_REASON_UNKNOWN:0);
                return;
            }
            if (rem < buflen)
                buflen = rem;
        }

        /* Read data and append to buffer */
        {
            ssize_t rl; 
            if (!conn->parameters->pceps_session) {
                rl = read(fd, buffer, buflen);
            } else {
                rl = pcep_ssl_read(conn, buffer, buflen);
            }
            if (rl == 0) {
                log_error(conn->pcep, "Connection closed by peer");
                close_conn(conn, EINVAL, 0);
                return;
            }
            if (rl == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* let's try later */
                    return;
                } else {
                    int error = errno;
                    log_error(conn->pcep, "Failed to read %zu bytes: %s", buflen,
                              strerror(error));
                    /*
                     * If error is set to 0, close_conn() would close
                     * the connection and never trigger a reconnect to the pce
                     * Hence, setting error value to schedue a re-connect
                     */
                    if (!error) {
                        error = EINVAL;
                    }
                    if (error == ECONNRESET) {
                        close_conn(conn, error, 0);
                    } else {
                        close_conn(conn, error, (conn->state==PCEP_CONN_SESSIONUP)?
                                   PCEP_CLOSE_REASON_UNKNOWN:0);
                    }
                    return;
                }
            }
            if (pcep_buffer_append(&conn->input, buffer, rl)) {
                log_error(conn->pcep, "Failed to append %zu bytes into buffer", rl);
                close_conn(conn, ENOMEM, 0);
                return;
            }
            readbytes += rl;
        }

        /* Process whatever messages we have */
        while (true) {
            size_t datalen;
            const uint8_t *data = pcep_buffer_data(&conn->input, &datalen);
            /*
             * Extract message length and check if we have
             * the entire thing.
             */
            const uint16_t msglen = pcep_msg_length(data);
            struct pcep_message msg;
            struct pcep_object* objs;

            /* Minimum message size, per RFC5440 */
            if (datalen < 4)
                break;

            if (datalen < msglen)
                break;

            if (msglen < 4) {
                close_conn(conn, EINVAL, PCEP_CLOSE_REASON_MALFORMED);
                return;
            }

            /* Parse and process message. It may signal us to bail immediately */
            msg.length = msglen;
            msg.objcount = pcep_msg_objcount(data, msglen);

            objs = (struct pcep_object *) calloc(msg.objcount,
                                                 sizeof(struct pcep_object));
            if (!objs) {
                /*
                 * We have run out of memory and it is unlikely we will be able
                 * to do anything useful further. So just close the connection.
                 */
                log_error(conn->pcep, "Memory allocation failed");
                close_conn(conn, ENOMEM, PCEP_CLOSE_REASON_UNKNOWN);
                return;
            }
            msg.objects = objs;

            if (pcep_msg_parse(conn, &msg, data)) {
                log_error(conn->pcep, "Unable to parse message");
                free(objs);
                switch (conn->state) {
                case PCEP_CONN_OPENWAIT:
                case PCEP_CONN_OPENWAIT2:
                case PCEP_CONN_KEEPWAIT:
                    pcep_send_pcerr(conn, PCEP_ERR_TYPE_SEF,
                                    PCEP_ERR_VAL_BAD_OPEN);
                    close_conn(conn, EINVAL, 0);
                    return;

                case PCEP_CONN_SESSIONUP:
                    conn->statistics.corrupted_messages++;
                    close_conn(conn, EINVAL, PCEP_CLOSE_REASON_MALFORMED);
                    return;

                default:
                    return;
                }
            }

            if (process_message(conn, &msg)) {
                free(objs);
                return;
            } 

            if (pcep_buffer_drain(&conn->input, msglen)) {
                log_error(conn->pcep, "Unable to drain buffer");
                close_conn(conn, ENOMEM, (conn->state==PCEP_CONN_SESSIONUP)?
                               PCEP_CLOSE_REASON_UNKNOWN:0);
                free(objs);
                return;
            }

            free(objs);
            objs = NULL;
        }
    }
}

/**
 * Callback on connection established
 *
 * @param[in] ctx Event context as obtained from #pcep_init()
 * @param[in] uap Connection pointer (struct pcep_conn *) cast to (void *)
 * @param[in] fd socket descriptor
 * @param[in] la UNUSED
 * @param[in] lalen UNUSED
 * @param[in] ra UNUSED
 * @param[in] ralen UNUSED
 * @return void
 */
static void
connect_finished (evContext ctx, void *uap, int fd, const void *la UNUSED,
                 int lalen UNUSED, const void *ra UNUSED, int ralen UNUSED)
{
    int e = errno; /* Save errno */

    struct pcep_conn *conn = uap;

    /* Connection failed */
    if (fd == -1) {
        log_error(conn->pcep, "Failed to open connection : %s", strerror(e));
        close_conn(conn, e, 0);
        return;
    } else if (fd != conn->fd) {
        log_error(conn->pcep, "Connection fd mis-match ev fd:%d conn fd:%d", fd, conn->fd);
        close_conn(conn, EINVAL, 0);
        return;
    }

    /*
     * PR 1675816 fix replaces assert statement to below error condition
     * processing. The TCP re-connect is triggered periodically until
     * it is successful.
     */
    if (conn->state != PCEP_CONN_TCPPENDING) {
        log_error(conn->pcep, "Failed to connect, conn state %u, "
                  "expected state %u", conn->state, PCEP_CONN_TCPPENDING);
        close_conn(conn, e, 0);
        return;
    }

    evDeselectFD(ctx, conn->readid);
    if (evSelectFD(ctx, fd, EV_EXCEPT, connection_erred, conn,
                   &conn->exceptid) == -1) {
        e = errno;
        log_error(conn->pcep, "Failed to initialize exception event: %s",
                  strerror(e));
        close_conn(conn, e, 0);
        return;
    }
    trace(conn, PCEP_TRC_OUT_MSGS, "PCEPS: TLS enable: params:%u val%d",
          conn->parameters, conn->parameters->local.tls_enable);

    conn->parameters->pceps_session = false;
    conn->parameters->remote.tls_enable = false;

    if (evSelectFD(ctx, fd, EV_READ, connection_readable, conn,
			    &conn->readid) == -1) {
	    e = errno;
	    log_error(conn->pcep, "Failed to initialize read event: %s", strerror(e));
	    close_conn(conn, e, 0);
	    return;
    }

    if (!conn->parameters->local.tls_enable) {
        trace(conn, PCEP_TRC_OUT_MSGS, "PCEPS: TLS - DISABLED");

        if (send_msg_open(conn, &conn->parameters->local.proposition,
                          conn->session_id, conn->parameters->local.proposal.keepalive,
                          conn->parameters->local.proposal.peer_deadtimer,
                          conn->parameters->local.proposition.lsp_provisioning,
                          conn->parameters->local.proposition.p2mp_lsp_report_capability,
                          conn->parameters->local.proposition.p2mp_lsp_update_capability,
                          conn->parameters->local.proposition.p2mp_lsp_init_capability,
                          conn->parameters->local.proposition.spring_capability,
                          conn->parameters->local.proposition.srv6_capability,
                          conn->parameters->constraints.req_caps
                          | conn->parameters->constraints.opt_caps,
                          conn->parameters->local.proposition.msd,
                          conn->parameters->local.proposition.pce_flowspec_capability,
                          conn->parameters->local.proposition.path_protection_association,
                          conn->parameters->local.proposition.srpag_association,
                          conn->parameters->local.proposition.multipath_capability,
                          conn->parameters->local.proposition.disjoint_assoc_capability))
            return;
        if (transition_to_openwait(conn))
            return;
    } else {
        trace(conn, PCEP_TRC_OUT_MSGS, "PCEPS: TLS - ENABLED");

        pcep_send_message(conn, PCEP_MSG_START_TLS, NULL, 0);
        if (transition_to_tlswait(conn))
            return;
    }
}

/**
 * Initiate a new PCEP connection to the PCE residing at the specified address.
 *
 * @param[in] pcep Library instance handle
 * @param[in] ctx Connection-specific user context
 * @param[in] params Connection parameters and constraints
 * @return pcep_conn pointer on success, NULL on failure.
 */
struct pcep_conn *
pcep_connect (struct pcep *pcep, void *ctx,
	       struct pcep_connect_parameters *params, char* auth_key)
{
    struct pcep_conn *conn;
    static const struct timespec ts = { .tv_sec = CONNECT_TIMER, };

    if (!params) {
        log_error(pcep, "params pointer is NULL");
        errno = EINVAL;
        return NULL;
    }

    if (params->local.sockaddress && params->local.sockaddress->sa_family !=
        params->remote.sockaddress->sa_family) {
        log_error(pcep, "Local/remote address family mismatch (%d/%d)",
                  params->local.sockaddress->sa_family,
                  params->remote.sockaddress->sa_family);
        return NULL;
    }

    conn = calloc(1, sizeof(struct pcep_conn));
    if (!conn) {
        log_error(pcep, "Failed to allocate connection: %s", strerror(errno));
        return NULL;
    }
    
    /* Create a non-blocking socket */
    conn->fd = socket(params->remote.sockaddress->sa_family, SOCK_STREAM, 0);
    if (conn->fd == -1) {
        log_error(pcep, "Failed to create socket: %s", strerror(errno));
        goto out;
    }

    /* Optionally bind to local address */
    if (params->local.sockaddress && bind(conn->fd, params->local.sockaddress,
        params->local.socklen) == -1) {
        log_error(pcep, "Failed to bind to local address: %s", strerror(errno));
        goto out_close;
    }

    if(auth_key && pcep_set_socket_options(conn->fd, params->remote.sockaddress,
                               auth_key, params->is_ipv6_session ) == -1) {
	log_error(pcep, "Failed to set socket options: %s", strerror(errno));
        goto out_close;
    }	

    /* Fully initialize the connection */
    conn->pcep = pcep;
    conn->context = ctx;
    conn->parameters = params;
    conn->state = PCEP_CONN_TCPPENDING;
    
    conn->trace_mask = PCEP_TRC_ALL;
    conn->dump_mask = PCEP_TRC_ALL;

    if (get_free_session(pcep, params->remote.sockaddress, &conn->session_id)) {
        log_error(pcep, "Failed to generate a session number: %s",
                  strerror(ENOMEM));
        goto out_close;
    }

    pcep_buffer_init(conn, &conn->input, input_limit, input_hysteresis);
    pcep_buffer_init(conn, &conn->output, output_limit, output_hysteresis);

    conn->unknown_msg_idx = 0;
    conn->max_unknown_messages = PCEP_MAX_UNKNOWN_MESSAGES;
    conn->unknown_msg_buf = NULL;
    if (pcep_alloc_max_unknown_messages_buffer(conn)) {
        log_error(pcep, "Failed to calloc 'unknown_msg_buf': %s",
                  strerror(errno));
        goto out_close;
    }
    conn->next_deadtimer = 0;
    
    conn->parameters->local.proposition.version = 0;
    conn->parameters->local.negotiation.version = 0;
    conn->parameters->local.active.version = 0;

    conn->parameters->remote.proposition.version = 0;
    conn->parameters->remote.negotiation.version = 0;
    conn->parameters->remote.active.version = 0;
    conn->ssl = NULL;

    SLIST_INSERT_HEAD(&pcep->connections, conn, list);
    
    /* Start the Connect timer */
    if (evSetIdleTimer(pcep->context, connect_timedout, conn, ts,
                       &conn->deadid) == -1) {
        log_error(pcep, "Failed to initialize connect timer: %s",
                  strerror(errno));
        goto out_delist;
    }

    /* Initiate the connection */
    {
        char ra[params->remote.socklen];
        /*
        * Create a local copy of the remote address, because evConnect()
        * requires non-const pointer
        */
        memcpy(ra, params->remote.sockaddress, params->remote.socklen);

        if (evConnect(pcep->context, conn->fd, ra, params->remote.socklen,
                    connect_finished, conn, &conn->connid) == -1) {
            log_error(pcep, "Failed to initialize connection: %s", strerror(errno));
            goto out_timer;
        }
    }
    return conn;

out_timer:
    conn_clear_timer(conn, &conn->deadid);
out_delist:
    SLIST_REMOVE_HEAD(&pcep->connections, list);
    pcep_buffer_free(&conn->input);
    pcep_buffer_free(&conn->output);
out_close:
    close(conn->fd);
out:
    free(conn);
    return NULL;
}

/**
 * This function sets the trace mask
 *
 * @param[in] conn Connection instance
 * @param[in] trace_mask Trace mask
 * @return void
 */
void
pcep_set_trace_mask (struct pcep_conn *conn, uint16_t trace_mask)
{
    conn->trace_mask = trace_mask;
}

/**
 * This function returns the active trace mask associated with a connection
 *
 * @param[in] conn Connection instance
 * @return active trace mask
 */
uint16_t
pcep_get_trace_mask (struct pcep_conn *conn)
{
    return conn->trace_mask;
}

/**
 * This function sets the dump mask
 *
 * @param[in] conn Connection instance
 * @param[in] dump_mask Dump mask
 * @return void
 */

void
pcep_set_dump_mask (struct pcep_conn *conn, uint16_t dump_mask)
{
    conn->dump_mask = dump_mask;
}

/**
 * This function returns the active dump mask associated with a connection
 *
 * @param[in] conn Connection instance
 * @return active dump mask
 */
uint16_t
pcep_get_dump_mask (struct pcep_conn *conn)
{
    return conn->dump_mask;
}

/**
 * This function returns the number of received keepalives
 *
 * @param[in] conn Connection instance
 * @return keepalives received
 */
unsigned long
pcep_get_keepalives_recv (struct pcep_conn *conn)
{
    return conn->statistics.keepalive_recv;
}

/**
 * This function returns the number of sent keepalives
 *
 * @param[in] conn Connection instance
 * @return keepalives sent
 */
unsigned long
pcep_get_keepalives_sent (struct pcep_conn *conn)
{
    return conn->statistics.keepalive_sent;
}

/**
 * This function returns the number of corrupted messages
 *
 * @param[in] conn Connection instance
 * @return corrupted messages
 */
unsigned long
pcep_get_corrupted_message_count (struct pcep_conn *conn)
{
    return conn->statistics.corrupted_messages;
}

/**
 * This function returns the number of unknown messages
 *
 * @param[in] conn Connection instance
 * @return unknown messages
 */
unsigned long
pcep_get_unknown_message_count (struct pcep_conn *conn)
{
    return conn->statistics.unknown_messages;
}

/**
 * This function returns the connection state
 *
 * @param[in] conn Connection instance
 * @return connection state
 */
unsigned long
pcep_get_connection_state (struct pcep_conn *conn)
{
    return (conn->state > PCEP_CONN_OPENWAIT) ? (conn->state) : conn->state+1;
}

/**
 * This function returns the session id
 *
 * @param[in] conn Connection instance
 * @return session id
 */
uint8_t
pcep_get_local_session_id (struct pcep_conn *conn)
{
    return conn->session_id;
}

/**
 * This function returns the remote session id
 *
 * @param[in] conn Connection instance
 * @return remote session id
 */
uint8_t
pcep_get_remote_session_id (struct pcep_conn *conn)
{
    return conn->parameters->remote.active.session_id;
}

/**
 * This function returns the local dead timer running
 *
 * @param[in] conn Connection instance
 * @return local dead timer running
 */
uint8_t
pcep_get_local_deadtimer (struct pcep_conn *conn)
{
    return conn->parameters->remote.active.deadtimer;
}

/**
 * This function returns the peer dead timer running
 *
 * @param[in] conn Connection instance
 * @return peer dead timer running
 */
uint8_t
pcep_get_peer_deadtimer (struct pcep_conn *conn)
{
    return conn->parameters->local.proposal.peer_deadtimer;
}

/**
 * This function returns the local keepalive timer value
 *
 * @param[in] conn Connection instance
 * @return local keepalive timer valuer
 */
uint8_t
pcep_get_local_keepalive_timer (struct pcep_conn *conn)
{
    return conn->parameters->local.active.keepalive;
}

/**
 * This function returns the remote keepalive timer value
 *
 * @param[in] conn Connection instance
 * @return remote keepalive timer value
 */
uint8_t
pcep_get_remote_keepalive_timer (struct pcep_conn *conn)
{
    return conn->parameters->remote.active.keepalive;
}

/**
 * Clear the PCEP connection statistics
 *
 * @param[in] conn Connection instance
 */
void
pcep_conn_clear_statistics(struct pcep_conn *conn)
{
    if (conn == NULL)
        return;

    conn->statistics.keepalive_recv = 0;
    conn->statistics.keepalive_sent = 0;
    conn->statistics.corrupted_messages = 0;
    conn->statistics.unknown_messages = 0;
}

/**
 * This function sets the max unknown messages and allocates buffer
 *
 * @param[in] conn Connection instance
 * @param[in] max_unknw_msgs Max unknown messages
 * @return true in case of error (conn == NULL or buffer allocation error)
 */
bool
pcep_set_max_unknown_messages (struct pcep_conn *conn, unsigned max_unknw_msgs)
{
    if (conn == NULL) {
        return true;
    }
    conn->max_unknown_messages = max_unknw_msgs;
    if (pcep_alloc_max_unknown_messages_buffer (conn) == true) {
        return true;
    }
    return false;
}

/**
 * This function returns the max_unknown_messages associated with a connection
 *
 * @param[in] conn Connection instance
 * @return max unknown messages
 */
unsigned
pcep_get_max_unknown_messages (struct pcep_conn *conn)
{
    return conn->max_unknown_messages;
}

/**
 * This function closes a connection
 *
 * @param[in] conn Connection instance
 * @return void
 */
void
pcep_disconnect (struct pcep_conn *conn)
{
    switch(conn->state) {
    case PCEP_CONN_SESSIONUP:
        close_conn(conn, 0, PCEP_CLOSE_REASON_UNKNOWN);
        break;
    case PCEP_CONN_TCPPENDING:
        evCancelConn(conn->pcep->context, conn->connid);
        evInitID(&conn->connid);
        /* Intentionally left out break; */
    default:
        close_conn(conn, 0, 0);
        break;
    }
}

/**
 * This function returns number of seconds to next deadtimer
 *
 * @param[in] conn Connection instance
 * @param[in] ts Time stamp for "now" in the statistics computation
 * @return number of seconds
 */
unsigned long
pcep_stats_get_deadtimer (struct pcep_conn *conn, time_t ts)
{
    /* retrieve deadtimer remaining time */
    if (ts < conn->next_deadtimer) {
        return conn->next_deadtimer - ts;
    } else {
        return 0;
    }
}

/**
 * This function returns rate of unknown messages in last minute
 *
 * @param[in] conn Connection instance
 * @param[in] ts Time stamp for "now" in the statistics computation
 * @return rate of unknown messages
 */
unsigned
pcep_stats_get_unknown_messages_rate (struct pcep_conn *conn, time_t ts)
{
    unsigned c = 0;
    long long idx = conn->unknown_msg_idx;
    unsigned rate = 0;

    if (conn->max_unknown_messages == 0) {
        return 0;
    }
    while (c < conn->max_unknown_messages) {
        if ((ts - conn->unknown_msg_buf[idx]) > ONE_MINUTE) {
            break;
        }
        idx--;
        rate++;
        c++;
        if (idx <= 0) {
            idx = (conn->max_unknown_messages - 1);
        }
    }
    return rate;
}

/**
 * This function returns the Library handle associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Library handle
 */
struct pcep*
get_pcep (struct pcep_conn *conn)
{
    return conn->pcep;
}

/**
 * This function returns the context associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Connection context
 */
void *
get_context (struct pcep_conn *conn)
{
    return conn->context;
}

/**
 * This function is a wrapper to be used outside of libpcep
 * and returns the connection state associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Connection state
 */
pcep_conn_state_t
pcep_get_conn_state (struct pcep_conn *conn)
{
    return get_conn_state(conn);
}

/**
 * This function returns the connection state associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Connection state
 */
pcep_conn_state_t
get_conn_state (struct pcep_conn *conn)
{
    return conn->state;
}

/**
 * This function returns the output buffer associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Output buffer
 */
struct pcep_buffer*
get_output_buffer (struct pcep_conn *conn)
{
    return &conn->output;
}

/**
 * This function returns the FD associated with a connection
 *
 * @param[in] conn Connection instance
 * @return Connection file descriptor
 */
int
get_conn_fd (struct pcep_conn *conn)
{
    return conn->fd;
}

/**
 * This function returns the configured max sid depth
 *
 * @param[in] conn Connection instance
 * @return Max SID depth
 */
uint8_t
pcep_get_local_msd (struct pcep_conn *conn)
{
    return conn->parameters->local.proposition.msd;
}

/**
 * This function returns the PCE's maximum segment list
 *
 * @param[in] conn Connection instance
 * @return Max computed segment list
 */
uint16_t
pcep_get_remote_max_segment_list (struct pcep_conn *conn)
{
    if (conn->parameters && 
        conn->parameters->remote.active.max_segment_list < PCCD_PLATFORM_MAX_ERO_COUNT) {
        return conn->parameters->remote.proposition.max_segment_list;
    }
    return PCCD_PLATFORM_MAX_ERO_COUNT;
}

int
tls_connect_to_pkid (evContext *pccd_ctx); 

int
pcep_connect_to_pkid (evContext *pccd_ctx)
{
    return tls_connect_to_pkid(pccd_ctx);
}
