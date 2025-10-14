#ifndef FNP_FAPI_H
#define FNP_FAPI_H

#include <rte_eal.h>

int register_frontend_action(const struct rte_mp_msg* msg, const void* peer);

int create_fsocket_action(const struct rte_mp_msg* msg, const void* peer);

int accept_fsocket_action(const struct rte_mp_msg* msg, const void* peer);

int close_fsocket_action(const struct rte_mp_msg* msg, const void* peer);

#endif //FNP_FAPI_H
