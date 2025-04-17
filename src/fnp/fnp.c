#include "fnp.h"

#include "fnp_error.h"
#include "fnp_common.h"
#include "fnp_socket.h"
#include "fnp_msg.h"

#include "tcp_sock.h"

#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_time.h>

static int pid; // 进程号，用来标识fnp前端
static struct rte_mempool *pool = NULL;

/************* mbuf api start **************/

inline MBUF_TYPE fnp_alloc_mbuf()
{
  struct rte_mbuf *m = NULL;
  while ((m = rte_pktmbuf_alloc(pool)) == NULL)
  {
    printf("alloc mbuf failed, wait 1s\n");
    rte_delay_us_block(1000000);
    i32 avail = rte_mempool_avail_count(pool);
    printf("mempool avail count: %d\n", avail);
  }
  return m;
}

inline void fnp_free_mbuf(MBUF_TYPE m)
{
  rte_pktmbuf_free((struct rte_mbuf *)m);
}

inline i32 fnp_get_mbuf_len(MBUF_TYPE m)
{
  if (m == NULL)
    return 0;
  return rte_pktmbuf_data_len((struct rte_mbuf *)m);
}

inline void fnp_set_mbuf_len(MBUF_TYPE m, i32 len)
{
  rte_pktmbuf_append((struct rte_mbuf *)m, len);
}

inline u8 *fnp_mbuf_data(MBUF_TYPE m)
{
  if (m == NULL)
    return NULL;
  return rte_pktmbuf_mtod((struct rte_mbuf *)m, u8 *);
}
/************* mbuf api end **************/

static int register_to_fnp_backend()
{
  struct rte_mp_msg msg;
  struct rte_mp_reply reply;
  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0}; // 5s

  // 初始化消息请求
  sprintf(msg.name, FNP_MSG_NAME_REGISTER);
  msg.num_fds = 0;
  msg.len_param = sizeof(register_req_t); // 参数长度
  register_req_t *req = msg.param;
  pid = getpid();
  req->pid = pid;
  FNP_INFO("register to fnp-backend, pid: %d\n", pid);

  if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
      reply.nb_received == 1)
  { // 等待fnp-daemon返回响应
    struct rte_mp_msg *msg = &reply.msgs[0];
    register_reply_t *r = (register_reply_t *)msg->param;
    FNP_INFO("received reply from fnp-backend, msg: %s code: %d\n", msg->name, r->code);

    return r->code;
  }

  return FNP_ERR_MSG_TIMEOUT;
}

static int handle_keepalive_req(const struct rte_mp_msg *msg, const void *peer)
{
  // FNP_INFO("received keepalive from fnp-backend\n");

  struct rte_mp_msg resp;
  sprintf(resp.name, FNP_MSG_NAME_KEEPALIVE_RESP);
  resp.num_fds = 0;
  resp.len_param = 4;
  int *data = resp.param;
  *data = pid;
  rte_mp_sendmsg(&resp);
  return 0;
}

int fnp_init()
{
  int argc = 6;
  char *argv[20] = {
      "fnp-api",
      "-l", "2",
      "--proc-type=secondary",
      "--file-prefix=fnp",
      "--no-pci"};

  int ret = rte_eal_init(argc, argv);
  CHECK_RET(ret);

  // 向fnp-backend注册
  FNP_INFO("FNP-FE register to FNP-BE\n");
  ret = register_to_fnp_backend();
  CHECK_RET(ret);

  // 注册保活
  ret = rte_mp_action_register(FNP_MSG_NAME_KEEPALIVE_REQ, handle_keepalive_req);
  CHECK_RET(ret);

  // 获取内存池
  pool = rte_mempool_lookup(FNP_MBUF_MEMPOOL_NAME);
  if (pool == NULL)
  {
    printf("Cannot get mbuf mempool: %s\n", FNP_MBUF_MEMPOOL_NAME);
    return -1;
  }
  printf("get mbuf mempool: %s\n", pool->name);

  printf("FNP-FE init successfully. main lcore: %d\n", rte_lcore_id());
  return 0;
}

/******************** fnp socket api start *****************/
FNP_SOCKET_TYPE fnp_create_socket(u8 proto, u32 lip, u16 lport, i32 opt)
{
  fsocket_t *socket = NULL;
  struct rte_mp_msg msg;
  struct rte_mp_reply reply;
  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0}; // 5s

  // 初始化消息请求
  sprintf(msg.name, FNP_MSG_NAME_CREATE_SOCKET);
  msg.num_fds = 0;
  msg.len_param = sizeof(create_socket_req_t); // 参数长度
  create_socket_req_t *req = msg.param;
  init_fsockaddr(&req->addr, proto, lip, 0, lport, 0);
  req->opt = opt;

  if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
      reply.nb_received == 1)
  { // 等待fnp-daemon返回响应
    struct rte_mp_msg *msg = &reply.msgs[0];
    create_socket_reply_t *r = (create_socket_reply_t *)msg->param;
    FNP_INFO("received reply from fnp-backend, msg: %s code: %d\n", msg->name, r->code);
    if (r->code != FNP_OK)
    {
      return NULL;
    }

    return r->socket;
  }

  FNP_ERR("socket can't get reply from fnp-daemon\n");
  return NULL;
}

static int tcp_connect(fsocket_t *socket)
{
  i32 state = 0;
  tcp_sock_t *sock = (tcp_sock_t *)socket;
  while ((state = tcp_get_state(sock)) != TCP_ESTABLISHED &&
         state != TCP_CLOSED)
    rte_delay_us_sleep(100000); // 100ms
  if (state == TCP_CLOSED)
    return FNP_ERR_GENERIC;
  return FNP_OK;
}

int fnp_connect(FNP_SOCKET_TYPE socketfd, u32 rip, u16 rport)
{
  fsocket_t *socket = (fsocket_t *)socketfd;
  struct rte_mp_msg msg;
  struct rte_mp_reply reply;
  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0}; // 5s

  // 初始化消息请求
  sprintf(msg.name, FNP_MSG_NAME_SOCKET_CONNECT);
  msg.num_fds = 0;
  msg.len_param = sizeof(socket_connect_req_t); // 参数长度
  socket_connect_req_t *req = msg.param;
  req->socket = socket;
  req->rip = rip;
  req->rport = rport;

  for (int i = 0; i < 5; i++)
  {
    if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
        reply.nb_received == 1)
    { // 等待fnp-backend返回响应
      struct rte_mp_msg *msg = &reply.msgs[0];
      socket_connect_reply_t *r = (socket_connect_reply_t *)msg->param;
      FNP_INFO("received reply from fnp-backend, msg: %s code: %d\n", msg->name, r->code);
      if (r->code == FNP_ERR_NO_ARP_CACHE)
      {
        rte_delay_us_sleep(100000); // 100ms
        continue;
      }
      CHECK_RET(r->code);

      if (socket->proto == IPPROTO_TCP)
        return tcp_connect(socket);
      return FNP_OK;
    }
  }

  return FNP_ERR_MSG_TIMEOUT;
}

FNP_SOCKET_TYPE fnp_accept(FNP_SOCKET_TYPE socketfd)
{
  fsocket_t *socket = (fsocket_t *)socketfd;
  fsocket_t *new = NULL;

  while (rte_ring_dequeue(socket->rx, (void **)&new) != 0)
    ; // 等待tcp连接

  // 注意:此时new->can_free为false
  // 在new入队前设置的,避免在队列中时, new被释放.

  return new;
}

void fnp_close(FNP_SOCKET_TYPE socketfd)
{
  fsocket_t *socket = (fsocket_t *)socketfd;

  socket->can_free = true; // 用户空间不使用了
  set_socket_req(socket, FNP_CLOSE_REQ);
}

int fnp_send(FNP_SOCKET_TYPE socket, MBUF_TYPE m)
{
  fsocket_t *sk = (fsocket_t *)socket;

  // 等待一段时间，避免发送过快，内存池不足
  rte_delay_us_block(200); // 200us
  // rte_delay_us_sleep(1); // 1us, sleep会让出cpu,导致实际时间会远超过1us

  // 判断发送窗口
  while (rte_ring_enqueue(sk->tx, m) != 0)
  {
    // 发送过快，导致发送队列满，等待一段时间
    rte_delay_us_sleep(2000); // 1000us
    FNP_WARN("enqueue mbuf failed\n");
  }

  return 0;
}

int fnp_sendto(FNP_SOCKET_TYPE socket, MBUF_TYPE m, faddr_t *remote)
{
  fsocket_t *sk = (fsocket_t *)socket;

  fsockinfo_t *info = fsockinfo(m);
  info->addr.ip = remote->ip;
  info->addr.port = remote->port;

  if (rte_ring_enqueue(sk->tx, m) != 0)
  {
    FNP_ERR("enqueue mbuf failed");
    return -1;
  }

  return 0;
}

MBUF_TYPE fnp_recv(FNP_SOCKET_TYPE socketfd)
{
  struct rte_mbuf *m = NULL;
  fsocket_t *socket = (fsocket_t *)socketfd;

  // 没有数据
  while (rte_ring_dequeue(socket->rx, (void **)&m) != 0)
  {
    // 收到FIN了
    if (!socket->can_recv)
    {
      if (rte_ring_count(socket->rx) == 0) // 必须再次确认没有数据
        return NULL;
    }
  }

  return m;
}

MBUF_TYPE fnp_recvfrom(FNP_SOCKET_TYPE socket, faddr_t *remote)
{
  struct rte_mbuf *m = NULL;
  fsocket_t *sk = (fsocket_t *)socket;
  while (rte_ring_dequeue(sk->rx, (void **)&m) != 0) // 应用设置超时
    return NULL;

  fsockinfo_t *info = fsockinfo(m);
  remote->ip = info->addr.ip;
  remote->port = info->addr.port;

  return m;
}

// 速率计算相关
static inline i64 get_timestamp_us()
{
  struct timeval tv;
  if (gettimeofday(&tv, 0) == -1)
  {
    return -1;
  }

  i64 timestamp = (i64)tv.tv_sec * 1000000LL + (i64)tv.tv_usec;
  return timestamp;
}

void fnp_compute_rate(fnp_rate_measure_t *meas, i64 size)
{
  meas->total += size;
  i64 now = get_timestamp_us();
  i64 diff_time = now - meas->last;

  // 每50ms计算一次
  if (diff_time > 50000)
  {
    double bw = (double)meas->total / diff_time;
    if (meas->last != 0)
      FNP_INFO("bandwidth: %.4lf MBps\n", bw);
    meas->last = now;
    meas->total = 0;
  }
}
