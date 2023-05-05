/**
 * @file libpcep/core.c
 *
 * Path Computation Element Protocol, core protocol services.
 *
 * Copyright (c) 2011-2013, Juniper Networks, Inc.
 * All rights reserved.
 */
/* $Id: core.c 1297074 2022-11-17 19:48:56Z ssharan $ */
#include "core.h"
#include "log.h"
#include "message.h"
#include "object.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <time.h>

#include <jnx/aux_types.h>

#include "ipc_util.h"

#include <stdio.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/x509_vfy.h>
#include <jnx/pki_api.h>

extern libpki_log_callback  g_log_callback;
int                         pkid_state = -1;
libpki_instance_t          *tls_pccd_pkic_instance = NULL;
static bool                 pkid_timer_initialized = false;
static bool                 connected_to_pkid = false;
static pkic_init_params_t   pki_params;
evTimerID                   pkid_timerid;
SSL_CTX                    *ssl_ctx = NULL;

/**
 * Callback on pkid connection time out
 */
static void
connect_to_pkid_timedout (evContext        ctx UNUSED,
                          void            *uap UNUSED,
                          struct timespec  due UNUSED,
                          struct timespec  inter UNUSED)
{
     const struct timespec ts = {
        .tv_sec = 30,
     };

     if (pkid_state == PKIC_IN_SERVICE) {
	     connected_to_pkid = true;
     } else if (pkid_state == PKIC_OUT_OF_SERVICE) {
	     if (pkic_connect((libpki_instance_t *)tls_pccd_pkic_instance) == EFAIL) {
		     connected_to_pkid = false;
	     } else {
		     connected_to_pkid = true;
	     }
     } else {
	     connected_to_pkid = false;
     }

     evResetIdleTimer(ctx, pkid_timerid, connect_to_pkid_timedout, NULL, ts);
     return;
}

/* Redirecting libpki's log to libpcep's trace */
static void
tls_pccd_pki_log (libpki_module_t  component __unused,
                  int              level __unused,
                  const char      *filename __unused,
                  int              line __unused,
                  const char      *logline __unused)
{
    return;
}

/*
 * All the events are from libpki comes through this callback
 */
static void
tls_pccd_pki_event_listener (pkic_state_t   state,
                             void          *cookie __unused)
{
    /*
     * If the connection state is PKIC_IN_SERVICE,
     * only then request the key chain
     */
    pkid_state = state;
    return;
}

int
tls_connect_to_pkid (evContext *pccd_ctx)
{
    const struct timespec pkid_ts = {
	    .tv_sec = 30,
    };

    g_log_callback = tls_pccd_pki_log;
    libpki_init(NULL, tls_pccd_pki_log);
    libpki_set_log_level(LOG_DEBUG);

    if (!pkid_timer_initialized) {
        memset(&pki_params, 0, sizeof(pkic_init_params_t));
        pki_params.pip_context = *pccd_ctx;
        pki_params.pip_event_listener = tls_pccd_pki_event_listener;
        pki_params.pip_permanent_conn = TRUE;
        tls_pccd_pkic_instance = pkic_ctor(&pki_params);
        pkid_timer_initialized = true;

    }

    /*
     * This is done to forcefully set the log callback so that
     * libpki doesn't write to stdout in any case
     */
    if (pkic_connect((libpki_instance_t *)tls_pccd_pkic_instance) == EFAIL) {
        connected_to_pkid = false;
    } else {
        connected_to_pkid = true;
    }
    if (evSetIdleTimer(*pccd_ctx, connect_to_pkid_timedout, NULL, pkid_ts,
                           &pkid_timerid) == -1) {
	return false;
    }
    return connected_to_pkid;
}

static SSL_CTX *
InitCTX (void)
{
    const SSL_METHOD *method = TLS_client_method(); //* Create new client-method instance */
    SSL_CTX    *ctx;

    OpenSSL_add_all_algorithms();         /* Load cryptos, et.al. */
    SSL_load_error_strings();             /* Bring in and register error messages */
    ctx = SSL_CTX_new(method);            /* Create new context */
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

/*
 * This callback is received from libpki when the client cert validation
 * is done
 */
static void
pki_validation_response_cb (void       *response_arg,
                            const X509 *ee_certificate)
{
    struct pcep_conn *conn = (struct pcep_conn *)response_arg;

    if (!conn) {
	return;
    }

    if (!ee_certificate) {
        trace(conn, PCEP_TRC_SESSION_INIT,
              "PCEPS: pki cert validation - Certificate is not valid");
        close_conn(conn, EINVAL, 0);
        return;
    } else {
        trace(conn, PCEP_TRC_SESSION_INIT,
              "PCEPS: pki cert validation - Certificate is valid");
        conn->parameters->pceps_session = true;
        if (send_msg_open(conn, &conn->parameters->local.proposition,
                          conn->session_id, conn->parameters->local.proposal.keepalive,
                          conn->parameters->local.proposal.peer_deadtimer,
                          conn->parameters->local.proposition.lsp_provisioning,
                          conn->parameters->local.proposition.p2mp_lsp_report_capability,
                          conn->parameters->local.proposition.p2mp_lsp_update_capability,
                          conn->parameters->local.proposition.p2mp_lsp_init_capability,
                          conn->parameters->local.proposition.spring_capability,
                          conn->parameters->local.proposition.srv6_capability,
                          conn->parameters->constraints.req_caps |
                                            conn->parameters->constraints.opt_caps,
                          conn->parameters->local.proposition.msd,
                          conn->parameters->local.proposition.pce_flowspec_capability,
                          conn->parameters->local.proposition.path_protection_association,
                          conn->parameters->local.proposition.srpag_association,
                          conn->parameters->local.proposition.multipath_capability,
                          conn->parameters->local.proposition.disjoint_assoc_capability)) {
            return;
        }
        transition_to_openwait(conn);
    }
    return;
}

void
create_tls (evContext   pccd_ctx __unused,
            void       *data,
            const void *tag __unused)
{
    int x = 0;
    if (data == NULL) {
        return;
    }
    struct pcep_conn *conn = (struct pcep_conn *)data;

    if (conn->state != PCEP_CONN_SSLPENDING) {
	trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS Error: Connection in Wrong state, expected SSL pending state");
	close_conn(conn, EINVAL, 0);
	return;
    }

    x = SSL_connect(conn->ssl);
    int y = SSL_get_error(conn->ssl, x);
    if (x == 1) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: SSL Handshake success");
    } else if ((y == SSL_ERROR_WANT_READ) || (y == SSL_ERROR_WANT_WRITE)) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: SSL Handshake WANT READ/WRITE ERROR\n");
        evDefer(pccd_ctx, create_tls, conn);
        return;
    } else {
        trace(conn, PCEP_TRC_OUT_MSGS, "PCEPS: Unrecoverable ssl-error, %d, %d \n", x, y);
        return;
    }

    X509 *cert = NULL;
    cert = SSL_get_peer_certificate(conn->ssl);
    STACK_OF(X509) *chain = NULL;
    chain = SSL_get_peer_cert_chain(conn->ssl);

    if (chain == NULL) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Error: Peer chain is NULL");
        return;
    }

    if (cert == NULL) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Error: Could not get a certificate");
        return;
    }
    int ret = 0;
    X509_NAME *p_subject_x = NULL;
    unsigned char *dn_x = NULL;
    unsigned char *dn_x_t = NULL;

    int dn_len_x = 0;
    X509_STORE_CTX *xctx = X509_STORE_CTX_new();
    if (xctx == NULL) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Error: Could not allocate x509 context objext");
	close_conn(conn, EINVAL, 0);
        return;
    }

    if (!X509_STORE_CTX_init(xctx, NULL, cert, chain)) {
        trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Error: Could not initialize x509 context");
	if (xctx) {
	   X509_STORE_CTX_free(xctx);
	}
	close_conn(conn, EINVAL, 0);
        return;
    }

    /*
     * libpki verification logic also includes something where it can
     * additionally do the client's EE(end entity) certificate's subject name check against
     * the passed subject name.
     * Since we do not have such requirement, we pass the same name as what we
     * got from the certificate so that the subject name validation passes
     */
    p_subject_x = X509_get_subject_name(cert);

    dn_len_x = i2d_X509_NAME(p_subject_x, NULL);
    dn_x = (char *)malloc(dn_len_x);
    dn_x_t = dn_x;
    i2d_X509_NAME(p_subject_x, &dn_x_t);

    if (!dn_x) {
        sk_X509_pop_free(chain, X509_free);
        return;
    }

    if (pkid_state != PKIC_IN_SERVICE) {
	    log_error(conn->pcep, "PCEPS: PKID out of Service, Can't request certificate validation");
            close_conn(conn, EINVAL, 0);
	    return;
    }
    /*
     * TODO: Check if pki_request api is sync or async call
     * (Risk of crashing if "conn" is passed in async call)
     */
    ret = pki_request_chain_validation(tls_pccd_pkic_instance,
                                 DER_SUBJECT_DN,
                                 dn_len_x,
                                 dn_x,
                                 chain,
                                 &pki_validation_response_cb,
                                 conn);
    if (ret != 0) {
	trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Certificate validation request to PKI Failed");
    } else {
	trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: Certificate validation request to PKI Sent");

    }
    evDeselectFD(pccd_ctx, conn->readid);
    if (evSelectFD(pccd_ctx, conn->fd, EV_READ, connection_readable, conn,
                   &conn->readid) == -1) {
        int e = errno;
        log_error(conn->pcep, "PCEPS: Failed to initialize read event: %s", strerror(e));
        close_conn(conn, e, 0);
        return;
    }
    trace(conn, PCEP_TRC_SESSION_INIT, "PCEPS: createtls operations complete");
}

void
prepare_tls(struct pcep_conn *conn)
{
    if (ssl_ctx == NULL) {
        SSL_library_init();
        ssl_ctx = InitCTX();
    }
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    conn->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(conn->ssl, conn->fd);
}

void
pcep_ssl_free(struct pcep_conn *conn)
{
    if (conn->ssl) {
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
}

ssize_t
pcep_ssl_write(struct pcep_conn *conn, const void *data, size_t datalen)
{
    return SSL_write(conn->ssl, data, datalen);
}

ssize_t
pcep_ssl_read(struct pcep_conn *conn, unsigned char buffer[65535], size_t buflen)
{
    return SSL_read(conn->ssl, buffer, buflen);
}
