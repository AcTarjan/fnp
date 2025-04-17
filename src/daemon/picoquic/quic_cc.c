#include "quic_cc.h"
#include "picoquic_internal.h"
#include "fnp_cc.h"

void quic_congestion_notify(
    quic_cnx_t* cnx,
    congestion_notification_t notification,
    u64 nb_bytes_acknowledged,
    u64 current_time)
{
    congestion_algorithm_t* algo = &cnx->cc_algo;
    algo->notify(algo, notification, nb_bytes_acknowledged, current_time);
}


u64 picoquic_cc_increased_window(quic_cnx_t* cnx, u64 previous_window)
{
    uint64_t new_window;
    if (cnx->path[0]->rtt_min <= PICOQUIC_TARGET_RENO_RTT)
    {
        new_window = previous_window * 2;
    }
    else
    {
        double w = (double)previous_window;
        w /= (double)PICOQUIC_TARGET_RENO_RTT;
        w *= (cnx->path[0]->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT)
                 ? PICOQUIC_TARGET_SATELLITE_RTT
                 : (double)cnx->path[0]->rtt_min;
        new_window = (uint64_t)w;
    }
    return new_window;
}
