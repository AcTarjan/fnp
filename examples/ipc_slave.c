
#include <rte_eal.h>
#include <rte_mbuf.h>
#include <unistd.h>

#define PKTMBUF_POOL_NAME "master_mbuf_pool"
#define RTE_MP_TX_DESC_DEFAULT 512
#define MBUF_CACHE_SIZE 512
#define CLIENT_QUEUE_RINGSIZE 1024
#define PORT_NUM 1
#define CLIENT_NUM 1
#define MSG_NAME    "CREATE_SOCKET"


#define MZ_PORT_INFO "PORT_INFO"

struct rte_memzone* mz = NULL;
struct rte_mempool* pool = NULL;
struct rte_ring* send_ring = NULL;      //对应master的recv_ring
struct rte_ring* recv_ring = NULL;      //对应master的send_ring

struct req_param
{
    uint32_t ip;
    uint16_t port;
    char rx_name[32];
    char tx_name[32];
};

int main()
{
    int retval;

    int argc = 5;       //未使用--no-pci
    char* argv[20] = {"app", "-l", "4", "--proc-type=secondary", "--file-prefix=master", "--no-pci"};

    retval = rte_eal_init(argc, argv);
    if (retval < 0)
        return -1;

    // mz = rte_memzone_lookup(MZ_PORT_INFO);
    // if (mz == NULL)
    //     rte_exit(EXIT_FAILURE, "Cannot get port info structure\n");
    // ports = mz->addr;



    pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot get mempool for mbufs\n");

    struct rte_mp_msg req;
    struct rte_mp_reply reply;
    struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
    sprintf(req.name, MSG_NAME);
    req.num_fds = 0;
    req.len_param = sizeof(struct req_param);
    struct req_param* req_msg = req.param;
    req_msg->ip = 123456;
    req_msg->port = 8080;
    // rte_mp_sendmsg(&msg);
    if (rte_mp_request_sync(&req, &reply, &ts) == 0 &&
    reply.nb_received == 1) {
        struct rte_mp_msg* msg = &reply.msgs[0];
        struct req_param *p = (struct req_param *)msg->param;
        printf("Received reply from server: msg_name: %s\n", msg->name);
        printf("Received reply from server: ip %d\n", p->ip);
        printf("Received reply from server: port %d\n", p->port);
        printf("Received reply from server: rx_name %s\n", p->rx_name);
        printf("Received reply from server: tx_name %s\n", p->tx_name);
        send_ring = rte_ring_lookup(p->tx_name);
        if (send_ring == NULL)
            rte_exit(EXIT_FAILURE, "Cannot get send ring - is server process running?\n");

        recv_ring = rte_ring_lookup(p->rx_name);
        if (recv_ring == NULL)
            rte_exit(EXIT_FAILURE, "Cannot get recv ring - is server process running?\n");
    }
    free(reply.msgs);

    printf("lcore_id: %d\n", rte_lcore_id());
    while(1) {
        struct rte_mbuf* mbuf = rte_pktmbuf_alloc(pool);
        if (mbuf == NULL) {
            printf("slave: mbuf alloc failed\n");
            sleep(1);
            continue;
        }
        char* data = rte_pktmbuf_mtod(mbuf, char*);
        sprintf(data, "hello master");

        if (rte_ring_enqueue(send_ring, mbuf) == 0) {
            printf("slave: send packet to master\n");
        }

        sleep(1);
    }

    return 0;
}
