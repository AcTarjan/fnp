#ifndef QUIC_H
#define QUIC_H

#include "picoquic.h"
#include "picoquic_internal.h"


quic_cnx_t* quic_create_client_cnx(quic_context_t* quic, fsockaddr_t* remote);

quic_context_t* quic_create_context(fsockaddr_t* local, fnp_quic_config_t* conf);

void quic_handle_context_event(fsocket_t* socket, u64 event);

void quic_free_context(quic_context_t* quic);

#endif
