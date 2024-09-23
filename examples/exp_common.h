#ifndef FNP_EXP_COMMON_H
#define FNP_EXP_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

int64_t get_timestamp_us() {
    struct timeval tv;
    int64_t timestamp;

    if (gettimeofday( &tv, 0) == -1) {
        return -1;
    }

    timestamp = (int64_t)tv.tv_sec * 1000000LL + (int64_t)tv.tv_usec;

    return timestamp;
}

static int64_t last_time = 0;

void showBw(int64_t count) {
    int64_t now = get_timestamp_us();
    double diff = (double)(now - last_time);
    double bw = (double)count / diff;

    printf("bw: %.4lf MBps\n", bw);
    last_time = now;
}
#endif //FNP_EXP_COMMON_H
