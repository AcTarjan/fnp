#include "fnp_sock.h"
#include "fnp_udp.h"

#include <rte_malloc.h>
#include <tcp_sock.h>


static struct rte_hash* sock_table = NULL;

#define RXTX_RING_SIZE    2048


int sock_init()
{
    int socket_id = (int)rte_socket_id();
    sock_table = create_ipv4_5tuple_hash(socket_id);
    if (sock_table == NULL)
    {
        printf("Unable to create the sock table on socket %d\n", socket_id);
        return -1;
    }

    return 0;
}

sock_t* sock_create(uint8_t proto, uint32_t lip, uint16_t lport, uint32_t rip, uint16_t rport)
{
    sock_t*  sock = NULL;
    ipv4_5tuple_t key;

    key.proto = proto;
    key.local_ip = lip;
    key.local_port = lport;
    key.remote_ip = 0;
    key.remote_port = 0;

    //TODO: 判断ip是否合法

    //判断端口是否用作服务端监听的端口
    if ( lookup_sock_from_hash(&key) )
    {
        char* ipstr = ipv4_ntos(lip);
        printf("%s:%d已被占用\n", ipstr, lport);
        free(ipstr);
        return NULL;
    }

    //判断sock是否已经存在
    key.remote_ip = rip;
    key.remote_port = rport;
    if ( lookup_sock_from_hash(&key) )
    {
        printf("连接%d:%d to %d:%d已存在\n", lip, lport,rip, rport);
        return NULL;
    }

    switch (key.proto)
    {
    case IPPROTO_UDP:
        {
            udp_sock_t* sk = (void*)udp_sock_ipv4(&key);
            if (sk == NULL)
            {
                printf("create udp sock failed\n");
                return NULL;
            }
            sock = &sk->sock;
            break;
        }
    case IPPROTO_TCP:
        {
            tcp_sock_t* sk = (void*)tcp_sock_ipv4(&key);
            if (sk == NULL)
            {
                printf("create tcp sock failed\n");
                return NULL;
            }
            sock = &sk->sock;
            break;
        }
    default:
        {
            printf("unkown proto %d\n", key.proto);
            return NULL;
        }
    }
    rte_memcpy(&sock->key, &key, sizeof(ipv4_5tuple_t));

    int socket_id = rte_socket_id();

    sprintf(sock->rx_name, "rx:%d-%u_%d-%u_%d",
        key.proto, key.local_ip,  key.local_port, key.remote_ip, key.remote_port);
    sprintf(sock->tx_name, "tx:%d-%u_%d-%u_%d",
        key.proto, key.local_ip,  key.local_port, key.remote_ip, key.remote_port);

    sock->rx = rte_ring_create(sock->rx_name, RXTX_RING_SIZE, socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (sock->rx == NULL)
    {
        rte_free(sock);
        return NULL;
    }

    sock->tx = rte_ring_create(sock->tx_name, RXTX_RING_SIZE, socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (sock->tx == NULL)
    {
        rte_ring_free(sock->rx);
        rte_free(sock);
        return NULL;
    }

    //添加到hash表 TODO: 加锁
    if (add_sock_to_hash(sock) < 0)
    {
        printf("add sock to hash failed\n");
        // free(sock);
        return NULL;
    }

    return sock;
}


int add_sock_to_hash(sock_t* sock)
{
    return ipv4_5tuple_add(sock_table, &sock->key, sock);
}

void remove_sock_from_hash(sock_t* sock)
{
    ipv4_5tuple_remove(sock_table, &sock->key);
}

bool lookup_sock_from_hash(ipv4_5tuple_t* key)
{
    return ipv4_5tuple_lookup(sock_table, key);
}

sock_t* get_sock_from_hash(struct rte_ipv4_hdr* hdr)
{
    sock_t* sock = NULL;
    ipv4_5tuple_get_value(sock_table, hdr, (void**)&sock);
    return sock;
}

void sock_free(sock_t* sock)
{
    remove_sock_from_hash(sock);
    switch (sock->proto)
    {
    case IPPROTO_TCP:
        {
            tcp_free_sock((tcp_sock_t*)sock);
            break;
        }
    }
}

//接收来自应用程序的数据
void sock_output()
{
    struct rte_mbuf* mbufs[64];
    uint32_t next = 0;
    void* key = NULL;
    sock_t* sock = NULL;
    while (rte_hash_iterate(sock_table, &key, (void**)&sock, &next) >= 0)
    {
        unsigned int num = rte_ring_dequeue_bulk(sock->tx, mbufs, 64, NULL);
        if (num > 0)
            printf("dequeue %d mbufs\n", num);
        for (int i = 0; i < num; i++)
        {
            udp_send_mbuf(mbufs[i]);
        }
    }

}
