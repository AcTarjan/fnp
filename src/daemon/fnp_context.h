#ifndef FNP_CONTEXT_H
#define FNP_CONTEXT_H

#include "fnp_common.h"
#include "libfnp-conf.h"
#include "fnp_network.h"
#include "fnp_worker.h"


typedef struct fnp_context
{
    fnp_config conf;
    fnp_worker_context_t worker;
    fnp_network_t net;
} fnp_context_t;

extern fnp_context_t fnp;

#define get_fnp_context() (&fnp)

i32 init_fnp_daemon(char* path);


#endif // FNP_CONTEXT_H
