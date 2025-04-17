#ifndef CUBIC_H
#define CUBIC_H

#include "fnp_common.h"

typedef enum
{
    cubic_alg_slow_start = 0, // 慢启动阶段
    cubic_alg_recovery, // 恢复阶段
    cubic_alg_congestion_avoidance // 拥塞避免阶段
} cubic_alg_state_t;

typedef struct st_cubic_state_t
{
    cubic_alg_state_t alg_state;
    u64 start_of_epoch;
    u64 previous_start_of_epoch;
    double K;
    double W_max;
    double W_last_max;
    double W_reno; //reno算法的窗口, 实际拥塞窗口不小于W_reno
    u64 ssthresh;
} cubic_state_t;

#endif //CUBIC_H
