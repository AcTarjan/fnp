#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#define PKTMBUF_POOL_NAME "master_mbuf_pool"
#define RTE_MP_TX_DESC_DEFAULT 512
#define MBUF_CACHE_SIZE 512
#define CLIENT_QUEUE_RINGSIZE 1024
#define PORT_NUM 1
#define CLIENT_NUM 1

#define MSG_NAME    "CREATE_SOCKET"

struct rte_mempool* pool = NULL;
struct rte_ring* send_ring = NULL;
struct rte_ring* recv_ring = NULL;

static int init_mbuf_pools(void)
{
    const unsigned int num_mbufs_server = 1024 * PORT_NUM;
    const unsigned int num_mbufs_client = CLIENT_NUM * (CLIENT_QUEUE_RINGSIZE + RTE_MP_TX_DESC_DEFAULT * 1);
    const unsigned int num_mbufs_mp_cache = (CLIENT_NUM + 1) * MBUF_CACHE_SIZE;
    const unsigned int num_mbufs =
        num_mbufs_server + num_mbufs_client + num_mbufs_mp_cache;

    /* don't pass single-producer/single-consumer flags to mbuf create as it
     * seems faster to use a cache instead */
    printf("Creating mbuf pool '%s' [%u mbufs] ...\n",
            PKTMBUF_POOL_NAME, num_mbufs);
    pool = rte_pktmbuf_pool_create(PKTMBUF_POOL_NAME, num_mbufs,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    return 0;
}

static int init_shm_rings(void)
{
    unsigned socket_id;
    const unsigned ringsize = CLIENT_QUEUE_RINGSIZE;

    socket_id = rte_socket_id();

    send_ring = rte_ring_create("master_send_ring",
                    ringsize, socket_id,
                    RING_F_SP_ENQ | RING_F_SC_DEQ ); /* single prod, single cons */
    if (send_ring == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create send ring queue for master\n");

    printf("send ring: %p\n", send_ring);

    recv_ring = rte_ring_create("master_recv_ring",
                    ringsize, socket_id,
                    RING_F_SP_ENQ | RING_F_SC_DEQ); /* single prod, single cons */
    if (recv_ring == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create recv ring queue for master %u\n");
    printf("recv ring: %p\n", recv_ring);

    return 0;
}

struct req_param
{
    uint32_t ip;
    uint16_t port;
    char rx_name[32];
    char tx_name[32];
};

static int bind_sock_msg(const struct rte_mp_msg *msg, const void *peer)
{
    int ret;

    const struct req_param *m = (const struct req_param *)msg->param;
    if (msg->len_param != sizeof(*m)) {
        RTE_LOG(ERR, EAL, "create socket received invalid message!\n");
        return -1;
    }

    printf("recv msg: ip %d\n", m->ip);
    printf("recv msg: port %d\n", m->port);


    struct rte_mp_msg reply;
    memset(&reply, 0, sizeof(reply));
    strcpy(reply.name, MSG_NAME);
    struct req_param* p = reply.param;
    reply.len_param = sizeof(*p);
    p->ip = m->ip;
    p->port = m->port;
    sprintf(p->rx_name, "master_send_ring");
    sprintf(p->tx_name, "master_recv_ring");

    ret = rte_mp_reply(&reply, peer);
    if (ret < 0)
    {
        printf("error sending reply\n");
        return -1;
    }

    printf("send reply successfully!\n");
    return 0;
}

struct test
{
    int a;
    int b;
};

int main()
{
    int retval;

    int argc = 5;
    char* argv[20] = {"app", "-l", "3", "--proc-type=primary", "--file-prefix=master"};

    //  ./app -c 0x1 --proc-type=secondary
    retval = rte_eal_init(argc, argv);
    if (retval < 0)
        return -1;

    init_mbuf_pools();

    init_shm_rings();

    int ret = rte_mp_action_register(MSG_NAME, bind_sock_msg);
    if (ret && rte_errno != ENOTSUP)
        return -1;

    struct test* t = rte_malloc(NULL, sizeof(struct test), 0);
    t->a = 666;
    t->b = 888;
    printf("test addr: %p\n", t);

    printf("lcore_id: %d\n", rte_lcore_id());
    while(1) {
        struct rte_mbuf* mbuf;
        if (rte_ring_dequeue(recv_ring, (void**)&mbuf) == 0) {
            printf("master: received packet\n");
            printf("mbuf addr: %p\n", mbuf);
            char* data = rte_pktmbuf_mtod(mbuf, char*);
            printf("data: %s\n", data);

            rte_pktmbuf_free(mbuf);
        }
    }

    return 0;
}
