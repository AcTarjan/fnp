#include "fnp.h"

#include "fnp_error.h"
#include "fnp_common.h"
#include "fnp_socket.h"
#include "fnp_internal.h"
#include "fnp_msg.h"

#include "tcp_sock.h"

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_time.h>
#include <unistd.h>


int fnp_init()
{
  //初始化DPDK
  int argc = 6;
  char* argv[20] = {
    "fnp-api",
    "-l", "2",
    "--proc-type=secondary",
    "--file-prefix=fnp",
    "--no-pci"
  };

  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
  {
    printf("Error with EAL initialization\n");
    return -1;
  }

  // 初始化与fnp-backend的通信管道
  init_fmsg_center();

  // 向fnp-backend注册
  ret = register_frontend_to_daemon();
  CHECK_RET(ret);


  // 获取内存池
  // pool = rte_mempool_lookup(FNP_MBUF_MEMPOOL_NAME);
  // if (pool == NULL)
  // {
  //   printf("Cannot get mbuf mempool: %s\n", FNP_MBUF_MEMPOOL_NAME);
  //   return -1;
  // }

  // printf("get mbuf mempool: %s\n", pool->name);
  printf("fnp-frontend %d init successfully. main lcore: %d\n", frontend->pid, rte_lcore_id());
  return FNP_OK;
}


/******************** fnp socket api start *****************/
fsocket_t* fnp_create_socket(fnp_protocol_t proto, const fsockaddr_t* local, const fsockaddr_t* remote, void* conf)
{
  fnp_msg_t* msg = new_fmsg(frontend->pid, fmsg_type_create_socket);
  create_socket_param_t* req = msg->data;

  req->proto = proto;
  fsockaddr_copy(&req->local, local);
  fsockaddr_copy(&req->remote, remote);
  req->conf = conf;

  // wait for reply
  int ret = send_fmsg_with_reply(fnp_master_id, msg);
  if (ret != 0)
  {
    printf("fail to create socket: %d\n", ret);
    return NULL;
  }

  fsocket_t* socket = msg->ptr;
  if (socket == NULL)
    return NULL;

  frontend_add_socket(frontend, socket);

  fnp_free(msg);
  return socket;
}

int fnp_connect(fsocket_t* socket)
{
  socket->request_syn = 1; // 设置请求syn标志

  return FNP_OK;
}


fsocket_t* fnp_accept(fsocket_t* socket)
{
  fsocket_t* new_socket = NULL;

  while (1)
  {
    while (!fnp_pring_dequeue(socket->rx, (void**)&new_socket)); // 等待tcp连接

    tcp_sock_t* sock = new_socket;
    if (tcp_get_state(sock) == TCP_CLOSED)
    {
      socket->frontend_id = 0;
      continue;
    }

    frontend_add_socket(frontend, new_socket); //添加到frontend中
    return new_socket;
  }
}

void fnp_close(fsocket_t* socket)
{
  frontend_remove_socket(frontend, socket);
  socket->request_close = 1;
}

int fnp_send(fsocket_t* socket, fnp_mbuf_t m)
{
  // 等待一段时间，避免发送过快，内存池不足
  rte_delay_us_block(200); // 200us
  // rte_delay_us_sleep(1); // 1us, sleep会让出cpu,导致实际时间会远超过1us

  // 判断发送窗口
  while (fnp_pring_enqueue(socket->tx, m) != 0)
  {
    // 发送过快，导致发送队列满，等待一段时间
    rte_delay_us_sleep(2000); // 1000us
    FNP_WARN("enqueue mbuf failed\n");
  }

  return 0;
}

int fnp_sendto(fsocket_t* socket, fnp_mbuf_t m, fsockaddr_t* raddr)
{
  fmbuf_info_t* info = get_fmbuf_info(m);
  fsockaddr_copy(&info->remote, raddr);

  if (!fnp_pring_enqueue(socket->tx, m))
  {
    FNP_ERR("enqueue mbuf failed");
    return -1;
  }

  return 0;
}

// 可以通过get_sockinfo获取到目的地址等mbufinfo
fnp_mbuf_t fnp_recv(fsocket_t* socket)
{
  struct rte_mbuf* m = NULL;

  // 没有数据
  while (!socket->receive_fin)
  {
    if (fnp_pring_dequeue(socket->rx, (void**)&m))
      break;
  }

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

void fnp_compute_rate(fnp_rate_measure_t* meas, i64 size)
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
