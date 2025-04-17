#include "fnp_context.h"
#include "fnp_worker.h"

int main()
{
    int ret = init_fnp_daemon("fnp.yaml");
    if (ret != 0)
    {
        printf("fnp_init_daemon error!\n");
        return -1;
    }

    ret = start_fnp_worker();
    if (ret != 0)
    {
        printf("fnp_start_worker error!\n");
        return -1;
    }

    int lcore_id = rte_lcore_id();
    printf("fnp daemon start, lcore_id: %d\n", lcore_id);

    // Main Lcore进入事件循环
    rte_eal_mp_wait_lcore();
}
