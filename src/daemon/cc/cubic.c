#include "fnp_cc.h"
#include <stdlib.h>
#include <string.h>

#include "fnp_common.h"
#include "cc_internal.h"

#define PICOQUIC_CUBIC_C 0.4
#define PICOQUIC_CUBIC_BETA_ECN (7.0 / 8.0)
#define PICOQUIC_CUBIC_BETA (3.0 / 4.0)


static void cubic_reset(congestion_algorithm_t* algo, uint64_t current_time)
{
    algo->send_mtu = 1536;
    algo->cwin = PICOQUIC_CWIN_INITIAL;

    cubic_state_t* state = &algo->cubic_state;
    memset(state, 0, sizeof(cubic_state_t));
    state->alg_state = cubic_alg_slow_start;
    state->ssthresh = UINT64_MAX;
    state->W_last_max = (double)state->ssthresh / (double)algo->send_mtu;
    state->W_max = state->W_last_max;
    state->start_of_epoch = current_time;
    state->previous_start_of_epoch = 0;
    state->W_reno = PICOQUIC_CWIN_INITIAL;
}

static double cubic_root(double x)
{
    /* First find an approximation */
    double v = 1;
    double y = 1.0;
    double y2;
    double y3;

    /*
     * v = 1
     *
     * x = (cubic_state->W_max * (1.0 - PICOQUIC_CUBIC_BETA)) / PICOQUIC_CUBIC_C
     * PICOQUIC_CUBIC_C = 0.4
     * (1.0 - PICOQUIC_CUBIC_BETA) = 1 - 7/8 = 1/8
     *
     * v > x * 8
     * 1 > (cubic_state->W_max * (1/8) / 0.4) * 8
     * cubic_state->W_max < 2/5
     */
    while (v > x * 8)
    {
        v /= 8;
        y /= 2;
    }

    while (v < x)
    {
        v *= 8;
        y *= 2;
    }

    for (int i = 0; i < 3; i++)
    {
        y2 = y * y;
        y3 = y2 * y;
        y += (x - y3) / (3.0 * y2);
    }

    return y;
}

/* Compute W_cubic(t) = C * (t - K) ^ 3 + W_max */
static double cubic_W_cubic(cubic_state_t* cubic_state, uint64_t current_time)
{
    double delta_t_sec = ((double)(current_time - cubic_state->start_of_epoch) / 1000000.0) - cubic_state->K;
    double W_cubic = (PICOQUIC_CUBIC_C * (delta_t_sec * delta_t_sec * delta_t_sec)) + cubic_state->W_max;

    return W_cubic;
}

/* On entering congestion avoidance, need to compute the new coefficients
 * of the cubic curve */
static void cubic_enter_avoidance(cubic_state_t* cubic_state, uint64_t current_time)
{
    cubic_state->alg_state = cubic_alg_congestion_avoidance;
    cubic_state->K = cubic_root(cubic_state->W_max * (1.0 - PICOQUIC_CUBIC_BETA_ECN) / PICOQUIC_CUBIC_C);
    cubic_state->start_of_epoch = current_time;
    cubic_state->previous_start_of_epoch = cubic_state->start_of_epoch;
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void cubic_enter_recovery(congestion_algorithm_t* algo,
                                 congestion_notification_t notification,
                                 uint64_t current_time)
{
    cubic_state_t* state = &algo->cubic_state;
    /* Update similar to new reno, but different beta */
    state->W_max = (double)algo->cwin / (double)algo->send_mtu;
    /* Apply fast convergence */
    if (state->W_max < state->W_last_max)
    {
        state->W_last_max = state->W_max;
        state->W_max = state->W_max * PICOQUIC_CUBIC_BETA_ECN;
    }
    else
    {
        state->W_last_max = state->W_max;
    }
    /* Compute the new ssthresh */
    state->ssthresh = (uint64_t)(state->W_max * PICOQUIC_CUBIC_BETA_ECN * (double)algo->send_mtu);
    if (state->ssthresh < PICOQUIC_CWIN_MINIMUM)
    {
        /* If things are that bad, fall back to slow start */
        state->alg_state = cubic_alg_slow_start;
        state->ssthresh = UINT64_MAX;
        state->previous_start_of_epoch = state->start_of_epoch;
        state->start_of_epoch = current_time;
        state->W_reno = PICOQUIC_CWIN_MINIMUM;
        algo->cwin = PICOQUIC_CWIN_MINIMUM;
    }
    else
    {
        if (notification == congestion_notification_timeout)
        {
            algo->cwin = PICOQUIC_CWIN_MINIMUM;
            state->previous_start_of_epoch = state->start_of_epoch;
            state->start_of_epoch = current_time;
            state->alg_state = cubic_alg_slow_start;
        }
        else
        {
            /* Enter congestion avoidance immediately */
            cubic_enter_avoidance(state, current_time);
            /* Compute the initial window for both Reno and Cubic */
            double W_cubic = cubic_W_cubic(state, current_time);
            uint64_t win_cubic = (uint64_t)(W_cubic * (double)algo->send_mtu);
            state->W_reno = ((double)algo->cwin) / 2.0;

            /* The formulas that compute "W_cubic" at the beginning of congestion avoidance
            * guarantee that "w_cubic" is larger than "w_reno" even if "fast convergence"
            * is applied as long as "beta_cubic" is greater than
            * (-1 + sqrt(1+4))/2, about 0.618033988749895.
            * Since beta_cubic is set to 3/4, we do not need to compare "w_cubic" and
            * "w_reno" to pick the largest. */
            algo->cwin = win_cubic;
        }
    }
}

/* On spurious repeat notification, restore the previous congestion control.
 * Assume that K is still valid -- we only update it after exiting recovery.
 * Set cwin to the value of W_max before the recovery event
 * Set W_max to W_max_last, i.e. the value before the recovery event
 * Set the epoch back to where it was, by computing the inverse of the
 * W_cubic formula */
static void cubic_correct_spurious(congestion_algorithm_t* algo,
                                   cubic_state_t* cubic_state,
                                   uint64_t current_time)
{
    if (cubic_state->ssthresh != UINT64_MAX)
    {
        cubic_state->W_max = cubic_state->W_last_max;
        cubic_enter_avoidance(cubic_state, cubic_state->previous_start_of_epoch);
        double W_cubic = cubic_W_cubic(cubic_state, current_time);
        cubic_state->W_reno = W_cubic * (double)algo->send_mtu;
        cubic_state->ssthresh = (uint64_t)(cubic_state->W_max * PICOQUIC_CUBIC_BETA * (double)algo->send_mtu);
        algo->cwin = (uint64_t)cubic_state->W_reno;
    }
}

/*
 * Properly implementing Cubic requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
static void cubic_notify(
    congestion_algorithm_t* algo,
    congestion_notification_t notification,
    u64 nb_bytes_acknowledged,
    uint64_t current_time)
{
    cubic_state_t* cubic_state = &algo->cubic_state;

    switch (notification)
    {
    /* RTT measurements will happen before acknowledgement is signalled */
    case congestion_notification_acknowledgement:
        switch (cubic_state->alg_state)
        {
        case cubic_alg_slow_start:
            {
                algo->cwin += nb_bytes_acknowledged;
                /* cwin 超过 ssthresh, 进入拥塞避免  */
                if (algo->cwin >= cubic_state->ssthresh)
                {
                    cubic_state->W_reno = ((double)algo->cwin) / 2.0;
                    cubic_enter_avoidance(cubic_state, current_time);
                }
                break;
            }
        case cubic_alg_recovery:
            {
                /* exit recovery, move to CA or SS, depending on CWIN */
                cubic_state->alg_state = cubic_alg_slow_start;
                algo->cwin += nb_bytes_acknowledged;
                /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                if (algo->cwin >= cubic_state->ssthresh)
                {
                    cubic_state->alg_state = cubic_alg_congestion_avoidance;
                }
                break;
            }
        case cubic_alg_congestion_avoidance:
            {
                /* Compute the cubic formula */
                double W_cubic = cubic_W_cubic(cubic_state, current_time);
                uint64_t win_cubic = (uint64_t)(W_cubic * (double)algo->send_mtu);
                /* Also compute the Reno formula */
                cubic_state->W_reno += (double)nb_bytes_acknowledged * (double)algo->send_mtu /
                    cubic_state->W_reno;

                /* Pick the largest */
                algo->cwin = FNP_MAX(win_cubic, (uint64_t)cubic_state->W_reno);
                break;
            }
        }
        break;
    case congestion_notification_repeat_ack:
    case congestion_notification_timeout:
    case congestion_notification_ecn_ec:
        switch (cubic_state->alg_state)
        {
        case cubic_alg_slow_start:
        case cubic_alg_recovery:
        case cubic_alg_congestion_avoidance:
            {
                cubic_enter_recovery(algo, notification, current_time);
                break;
            }
        }
        break;
    case congestion_notification_spurious_repeat:
        /* Reset CWIN based on ssthresh, not based on current value. */
        cubic_correct_spurious(algo, cubic_state, current_time);
        break;
    case congestion_notification_reset:
        cubic_reset(algo, current_time);
        break;
    default:
        break;
    }

    /* Compute pacing data */
    // picoquic_update_pacing_data(cnx, path_x, cubic_state->alg_state == cubic_alg_slow_start &&
    //                             cubic_state->ssthresh == UINT64_MAX);
}

/* Observe the state of congestion control */
void cubic_observe(struct congestion_algorithm* algo, uint64_t* cc_state, uint64_t* cc_param)
{
    cubic_state_t* cubic_state = &algo->cubic_state;
    *cc_state = (uint64_t)cubic_state->alg_state;
    *cc_param = (uint64_t)cubic_state->W_max;
}


/* Definition record for the Cubic algorithm */
#define cubic_name "cubic" /* CBIC */


void init_cubic_algorithm(congestion_algorithm_t* algo, u64 current_time)
{
    algo->id = congestion_algo_cubic;
    algo->name = cubic_name;
    algo->notify = cubic_notify;
    algo->observe = cubic_observe;

    // 重置cubic state
    cubic_reset(algo, current_time);
}
