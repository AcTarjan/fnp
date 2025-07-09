#include "fnp_common.h"

char* fnp_string_duplicate(const char* original)
{
    if (original == NULL)
    {
        return NULL;
    }
    size_t len = strlen(original);

    int allocated = len + 1;
    char* str = (char*)fnp_malloc(allocated);
    if (str != NULL)
    {
        fnp_memcpy(str, original, len);
        str[allocated - 1] = 0;
    }

    return str;
}

void fnp_string_free(char* str)
{
    if (str != NULL)
    {
        fnp_free(str);
    }
}


static void show_measure_rate(fnp_rate_measure_t* meas)
{
    while (1)
    {
        fnp_sleep(5000 * 1000); // 每5秒计算一次速率
        fnp_compute_rate(meas);
    }
}

fnp_rate_measure_t* fnp_register_measure()
{
    fnp_rate_measure_t* meas = fnp_zmalloc(sizeof(fnp_rate_measure_t));
    pthread_t ctrl_thread;
    int ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_measure_task", NULL,
                                     show_measure_rate, meas);
    if (ret != 0)
    {
        RTE_LOG(ERR, EAL, "Failed to create control thread\n");
        return ret;
    }
    return meas;
}

void fnp_compute_rate(fnp_rate_measure_t* meas)
{
    if (meas->packet_count == 0)
    {
        printf("No packets received yet.\n");
        return;
    }

    u64 hz = fnp_get_tsc_hz();
    double delay = (double)(meas->last_tsc - meas->first_tsc) / (double)hz;
    printf(
        "packet count is %llu, byte count is %llu, first tsc is %llu, last tsc is %llu, hz is %llu, delay is %.2lf\n",
        meas->packet_count, meas->byte_count, meas->first_tsc, meas->last_tsc, hz, delay);

    double pps = (double)meas->packet_count / delay / 1000000.0;
    double Bps = (double)meas->byte_count / delay / 1000000000.0;
    printf("pps is %.2lfMpps, Bps is %.2lfGBps, bps is %.2lfGbps\n", pps, Bps, Bps * 8);
    if (meas->file != NULL)
    {
        fprintf(meas->file, "%.2lf %.2lf", pps, Bps);
    }
}

void fnp_update_rate_measure(fnp_rate_measure_t* meas, i32 data_len)
{
    u64 tsc = fnp_get_tsc();
    if (unlikely(meas->packet_count == 0))
    {
        meas->first_tsc = tsc;
    }

    meas->last_tsc = tsc;
    meas->packet_count++;
    meas->byte_count += data_len;

    if (meas->packet_count == meas->interval_count)
    {
        fnp_compute_rate(meas);
        meas->packet_count = 0;
        meas->byte_count = 0;
    }
}
