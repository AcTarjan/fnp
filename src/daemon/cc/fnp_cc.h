#ifndef FNP_CC_H
#define FNP_CC_H

#include "fnp_common.h"
#include "cubic.h"


typedef enum congestion_algorithm_id
{
    congestion_algo_cubic = 0,
    congestion_algo_new_reno,
    congestion_algo_fast,
} congestion_algorithm_id_t;

typedef enum
{
    congestion_notification_acknowledgement,
    congestion_notification_repeat_ack,
    congestion_notification_timeout,
    congestion_notification_spurious_repeat,
    congestion_notification_rtt_measurement,
    congestion_notification_ecn_ec,
    congestion_notification_cwin_blocked,
    congestion_notification_seed_cwin,
    congestion_notification_reset,
    congestion_notification_lost_feedback /* notification of lost feedback */
} congestion_notification_t;


typedef void (*congestion_algorithm_notify_func)(
    struct congestion_algorithm* algo,
    congestion_notification_t notification,
    u64 nb_bytes_acknowledged,
    uint64_t current_time);

typedef void (*congestion_algorithm_observe_func)(
    struct congestion_algorithm* algo,
    uint64_t* cc_state,
    uint64_t* cc_param);

typedef struct congestion_algorithm
{
    char const* name;
    congestion_algorithm_id_t id;
    congestion_algorithm_notify_func notify;
    congestion_algorithm_observe_func observe;
    // 拥塞算法上下文
    void* context;
    u64 cwin; //拥塞窗口
    int send_mtu;

    union
    {
        cubic_state_t cubic_state; //拥塞状态, 不同的拥塞算法不同
    };
} congestion_algorithm_t;

#define default_congestion_algorithm congestion_algo_cubic

// 初始化为指定的拥塞算法
int init_congestion_algorithm(congestion_algorithm_t* algo, congestion_algorithm_id_t algo_id, u64 current_time);


#endif //FNP_CC_H
