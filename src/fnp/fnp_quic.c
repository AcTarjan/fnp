#include "fnp_quic.h"
#include "fnp_sockaddr.h"

int fnp_init_fsockaddr(fnp_addr_t *addr, const char *ip, uint16_t port)
{
    addr.ip = fnp_ipv4_ston(ip);
    addr.port = fnp_swap16(port);
    return 0;
}

// 创建一个QUIC服务端
int fnp_quic_create_server(faddr_t *local)
{
}

// 创建一个QUIC客户端连接
// local: 本地地址，可以为NULL
// remote: 远程地址, 不能为空
int fnp_quic_create_client(faddr_t *local, faddr_t *remote)
{
}
