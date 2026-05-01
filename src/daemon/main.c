#include "fnp_context.h"
#include "fnp_worker.h"
#include "fnp_master.h"

#include <stdio.h>
#include <stdlib.h>

static void write_daemon_ready_file(void)
{
    const char *app_id = getenv("FNP_APP_ID");
    if (app_id == NULL || app_id[0] == '\0')
    {
        app_id = "fnp";
    }

    char ready_path[256];
    snprintf(ready_path, sizeof(ready_path), "/var/run/dpdk/%s/ready", app_id);

    FILE *fp = fopen(ready_path, "w");
    if (fp == NULL)
    {
        perror("failed to write fnp daemon ready file");
        return;
    }

    fprintf(fp, "ready\n");
    fclose(fp);
}

int main(int argc, char* argv[])
{
    const char* config_path = "k8s/conf/fnp-vdev-tap.yaml";
    if (argc > 2)
    {
        fprintf(stderr, "Usage: %s [config_path]\n", argv[0]);
        return -1;
    }

    if (argc == 2)
    {
        config_path = argv[1];
    }

    printf("using config: %s\n", config_path);

    int ret = init_fnp_daemon((char*)config_path);
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
    write_daemon_ready_file();

    fnp_master_loop();
}
