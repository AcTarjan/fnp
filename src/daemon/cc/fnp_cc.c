#include "fnp_cc.h"

#include "fnp_common.h"
#include "fnp_error.h"


extern void init_cubic_algorithm(congestion_algorithm_t* algo, u64 current_time);

int init_congestion_algorithm(congestion_algorithm_t* algo, congestion_algorithm_id_t algo_id, u64 current_time)
{
    switch (algo_id)
    {
    case congestion_algo_cubic:
        {
            init_cubic_algorithm(algo, current_time);
            break;
        }
    default:
        return FNP_ERR_CC_ALGO;
    }

    return FNP_OK;
}
