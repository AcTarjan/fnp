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


int fnp_init(int main_lcore, int lcores[], int num_lcores)
{
  //初始化lcores
  char main_lcore_argv[16];
  sprintf(main_lcore_argv, "--main-lcore=%d", main_lcore);

  int argc = 5;
  char* argv[20] = {
    "fnp-api",
    "--proc-type=secondary",
    "--file-prefix=fnp",
    "--no-pci",
    main_lcore_argv,
  };

  u32 lcore_mask = 0;
  lcore_mask |= (1U << main_lcore); // 设置主lcore
  for (int i = 0; i < num_lcores; i++)
  {
    lcore_mask |= (1U << lcores[i]);
  }

  char lcore_argv[16];
  sprintf(lcore_argv, "-c %#x", lcore_mask);
  argv[argc++] = lcore_argv;

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


int fnp_sendto(fsocket_t* socket, fnp_mbuf_t* m, fsockaddr_t* raddr)
{
  fmbuf_info_t* info = get_fmbuf_info(m);
  fsockaddr_copy(&info->local, &socket->local);
  fsockaddr_copy(&info->remote, raddr);

  if (!fnp_socket_enqueue_for_net(socket, m))
  {
    return FNP_ERR_RING_FULL;
  }

  return 0;
}

int fnp_send(fsocket_t* socket, fnp_mbuf_t* m)
{
  return fnp_sendto(socket, m, &socket->remote); // 默认发送到远程地址
}


// 可以通过get_sockinfo获取到目的地址等mbufinfo
fnp_mbuf_t* fnp_recv(fsocket_t* socket)
{
  if (socket->receive_fin)
    return NULL;

  struct rte_mbuf* m = NULL;
  // 等待接收数据
  while (!fnp_pring_dequeue(socket->rx, (void**)&m));

  // 判断是否是最后一个数据包
  fmbuf_info_t* info = get_fmbuf_info(m);
  socket->receive_fin = info->receive_fin;

  return m;
}


static void show_measure_rate(fnp_rate_measure_t* meas)
{
  while (1)
  {
    fnp_sleep(5000 * 1000); // 每5秒计算一次速率
    fnp_compute_rate(meas);
  }
}

fnp_rate_measure_t* fnp_register_measure()
{
  fnp_rate_measure_t* meas = fnp_zmalloc(sizeof(fnp_rate_measure_t));
  pthread_t ctrl_thread;
  int ret = rte_ctrl_thread_create(&ctrl_thread, "fnp_measure_task", NULL,
                                   show_measure_rate, meas);
  if (ret != 0)
  {
    RTE_LOG(ERR, EAL, "Failed to create control thread\n");
    return ret;
  }
  return meas;
}

void fnp_compute_rate(fnp_rate_measure_t* meas)
{
  if (meas->packet_count == 0)
  {
    printf("No packets received yet.\n");
    return;
  }

  double delay = (double)(meas->last_tsc - meas->first_tsc) / (double)meas->hz;
  printf("packet count is %llu, byte count is %llu, first tsc is %llu, last tsc is %llu, hz is %llu, delay is %.2lf\n",
         meas->packet_count, meas->byte_count, meas->first_tsc, meas->last_tsc, meas->hz, delay);

  double pps = (double)meas->packet_count / delay / 1000000.0;
  double Bps = (double)meas->byte_count / delay / 1000000000.0;
  printf("pps is %.2lfMpps, Bps is %.2lfGBps, bps is %.2lfGbps\n", pps, Bps, Bps * 8);
}

void fnp_update_rate_measure(fnp_rate_measure_t* meas, i32 data_len)
{
  u64 tsc = fnp_get_tsc();
  if (unlikely(meas->packet_count == 0))
  {
    meas->hz = fnp_get_tsc_hz();
    meas->first_tsc = tsc;
  }

  meas->last_tsc = tsc;
  meas->packet_count++;
  meas->byte_count += data_len;

  if (meas->packet_count == meas->interval_count)
  {
    fnp_compute_rate(meas);
    meas->packet_count = 0;
    meas->byte_count = 0;
  }
}
