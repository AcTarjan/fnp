#ifndef QUIC_CC_H
#define QUIC_CC_H

#include "fnp_cc.h"
#include "quic_common.h"

void quic_congestion_notify(
    quic_cnx_t* cnx,
    congestion_notification_t notification,
    u64 nb_bytes_acknowledged,
    u64 current_time);

/* Trigger sending more data if window increases */
u64 picoquic_cc_increased_window(quic_cnx_t* cnx, u64 previous_window);

#endif //QUIC_CC_H
