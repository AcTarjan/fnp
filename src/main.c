#include <unistd.h>

#include "fnp_init.h"

int main()
{
    fnp_init("fnp.yaml");

    //控制线程
    while (true)
    {
        sleep(10);
    }
}