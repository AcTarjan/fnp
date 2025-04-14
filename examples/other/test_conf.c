#include <stdio.h>
#include "libfnp-conf.h"

int main() {
    fnp_config conf;
    int x = parse_fnp_config("/root/fnp/libs/fnp/fnp.yaml", &conf);
    printf("x = %d\n", x);
}