#ifndef FNP_CONTEXT_H
#define FNP_CONTEXT_H

#include "fnp_common.h"
#include "hash.h"
#include "../../deps/conf/libfnp-conf.h"


typedef struct fnp_context
{
    fnp_config conf;
    rte_hash* arpTbl;
    rte_hash* sockTbl; // key is proto
} fnp_context_t;

extern fnp_context_t fnp;

#define get_fnp_context() (&fnp)

i32 init_fnp_daemon(char* path);


#endif // FNP_CONTEXT_H
