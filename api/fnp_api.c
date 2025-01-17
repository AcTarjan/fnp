#include "fnp_api.h"
#include "fnp_msg.h"
#include "fnp_common.h"

#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>


typedef struct fnp_socket {
  uint32_t lip;
  uint32_t rip;
  uint16_t lport;
  uint16_t rport;
  uint8_t proto;
  struct rte_ring* rx;
  struct rte_ring* tx;
} fnp_socket_t;

static struct rte_mempool* pool = NULL;

uint32_t fnp_ipv4_ston(const char* ip)
{
  if (ip == NULL)
    return 0;
  struct in_addr addr;
  inet_aton(ip, &addr);

  return addr.s_addr;
}

char* fnp_ipv4_ntos(uint32_t ip)
{
  struct in_addr addr;
  addr.s_addr = ip;
  return inet_ntoa(addr);
}

int fnp_init() {
  int argc = 6;
  char* argv[20] = {
    "fnp-api",
    "-l", "1",
    "--proc-type=secondary",
    "--file-prefix=fnp",
    "--no-pci"
  };

  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
  {
    printf("fail to init rte eal\n");
    return ret;
  }

  pool = rte_mempool_lookup(FNP_MBUF_MEMPOOL_NAME);
  if (pool == NULL)
  {
    printf("Cannot get mbuf mempool: %s\n", FNP_MBUF_MEMPOOL_NAME);
    return -1;
  }

  return 0;
}

struct rte_mbuf* fnp_alloc_mbuf()
{
  return rte_pktmbuf_alloc(pool);
}

void* fnp_socket(uint8_t proto, uint32_t lip, uint16_t lport,
  uint32_t rip, uint16_t rport)
{
  fnp_socket_t* socket = rte_malloc(NULL, sizeof(fnp_socket_t), 0);
  if (socket == NULL)
  {
    return NULL;
  }

  socket->proto = proto;
  socket->lip = lip;
  socket->lport = lport;
  socket->rip = rip;
  socket->rport = rport;
  socket->rx = NULL;
  socket->tx = NULL;

  return socket;
}

int fnp_bind(void* socketfd, int reuse)
{
  struct rte_mp_msg req;
  struct rte_mp_reply reply;
  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};

  fnp_socket_t* socket = (fnp_socket_t*)socketfd;

  //发送参数给fnp-daemon
  sprintf(req.name, FNP_BIND_SOCKET_MSG_NAME);
  req.num_fds = 0;
  req.len_param = sizeof(bind_socket_req_t);   //参数长度
  bind_socket_req_t* param = req.param;
  param->proto = socket->proto;
  param->lip = socket->lip;
  param->lport = socket->lport;
  param->rip = socket->rip;
  param->rport = socket->rport;

  if (rte_mp_request_sync(&req, &reply, &ts) == 0 &&
  reply.nb_received == 1) {   //等待fnp-daemon返回响应
    struct rte_mp_msg* msg = &reply.msgs[0];
    bind_socket_reply_t *r = (bind_socket_reply_t *)msg->param;
    FNP_INFO("Received reply from fnp-daemon: msg_name: %s\n", msg->name);
    FNP_INFO("Received reply from fnp-daemon: rx_name %s\n", r->rx_name);
    FNP_INFO("Received reply from fnp-daemon: tx_name %s\n", r->tx_name);
    socket->tx = rte_ring_lookup(r->tx_name);
    if (socket->tx == NULL)
    {
      FNP_ERR("socket can't lookup tx ring", r->tx_name);
      return -1;
    }

    socket->rx = rte_ring_lookup(r->rx_name);
    if (socket->rx == NULL)
    {
      FNP_ERR("socket can't lookup rx ring", r->rx_name);
      return -2;
    }
    // rte_free(reply.msgs);
    return 0;
  }

  FNP_ERR("socket can't get reply from fnp-daemon");
  return -3;
}


int fnp_listen(void* socketfd)
{
  return 0;
}

int fnp_send(void* socketfd, struct rte_mbuf* m)
{
  fnp_socket_t* socket = (fnp_socket_t*)socketfd;

  sockinfo_t* info = sockinfo(m);
  info->lip = socket->lip;
  info->rip = socket->rip;
  info->lport = socket->lport;
  info->rport = socket->rport;
  info->proto = socket->proto;


  if (rte_ring_enqueue(socket->tx, m) != 0)
  {
    FNP_ERR("enqueue mbuf failed");
    return -1;
  }
  return 0;
}




struct rte_mbuf* fnp_recv(void* socketfd)
{
  struct rte_mbuf* m = NULL;
  fnp_socket_t* socket = (fnp_socket_t*)socketfd;
  while (rte_ring_dequeue(socket->rx, (void**)&m) != 0);

  return m;
}