#include "fnp.h"

#include "fnp_error.h"
#include "fnp_common.h"
#include "fnp_internal.h"
#include "fnp_api.h"


#include <sys/time.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_time.h>


/******************** fnp socket api start *****************/
int fnp_create_socket(fnp_protocol_t proto, const fsockaddr_t* local, const fsockaddr_t* remote, void* conf)
{
  struct rte_mp_msg msg = {0};
  struct rte_mp_reply reply = {0};
  struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};
  sprintf(msg.name, FAPI_CREATE_FSOCKET_ACTION_NAME);
  msg.len_param = sizeof(fapi_create_socket_req_t);
  fapi_create_socket_req_t* req = msg.param;
  req->proto = proto;
  fsockaddr_copy(&req->local, local);
  fsockaddr_copy(&req->remote, remote);
  req->conf = conf;

  //等待master返回响应
  if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
    reply.nb_received == 1)
  {
    struct rte_mp_msg* reply_msg = &reply.msgs[0];
    fapi_common_resp_t* resp = (fapi_common_resp_t*)reply_msg->param;
    if (resp->code != FNP_OK)
    {
      printf("fail to create socket: %d\n", resp->code);
      return resp->code;
    }

    if (unlikely(reply_msg->num_fds != 2))
    {
      printf("fail to create socket: error num of fds %d\n", reply_msg->num_fds);
      return FNP_ERR_PARAM;
    }


    // 更新efd
    fsocket_t* socket = resp->ptr;
    socket->rx_efd_in_frontend = reply_msg->fds[0];
    socket->tx_efd_in_frontend = reply_msg->fds[1];

    frontend_add_fsocket(socket);
    free(reply.msgs);

    return socket->fd;
  }

  return FNP_ERR_TIMEOUT;
}

int fnp_accept(int fd)
{
  fsocket_t* server_socket = frontend_get_fsocket(fd);
  if (server_socket == NULL)
    return FNP_ERR_BAD_FD;

  if (fnp_ring_count(server_socket->rx) == 0)
    return FNP_ERR_EMPTY; //没有连接可接受

  struct rte_mp_msg msg = {0};
  struct rte_mp_reply reply = {0};
  struct timespec ts = {.tv_sec = 2, .tv_nsec = 0};
  sprintf(msg.name, FAPI_ACCEPT_FSOCKET_ACTION_NAME);
  msg.len_param = sizeof(fapi_common_req_t);
  fapi_common_req_t* req = msg.param;
  req->ptr = server_socket;

  //等待master返回响应
  if (rte_mp_request_sync(&msg, &reply, &ts) == 0 &&
    reply.nb_received == 1)
  {
    struct rte_mp_msg* reply_msg = &reply.msgs[0];
    fapi_common_resp_t* resp = (fapi_common_resp_t*)reply_msg->param;
    if (resp->code != FNP_OK)
    {
      printf("fail to create socket: %d\n", resp->code);
      return resp->code;
    }

    if (unlikely(reply_msg->num_fds != 2))
    {
      printf("fail to create socket: error num of fds %d\n", reply_msg->num_fds);
      return FNP_ERR_PARAM;
    }

    fsocket_t* new_socket = resp->ptr;

    // 更新efd
    new_socket->rx_efd_in_frontend = reply_msg->fds[0];
    new_socket->tx_efd_in_frontend = reply_msg->fds[1];

    frontend_add_fsocket(new_socket);
    free(reply.msgs);

    return new_socket->fd;
  }

  return FNP_ERR_TIMEOUT;
}

void fnp_close(int fd)
{
  fsocket_t* socket = frontend_get_fsocket(fd);
  if (socket == NULL)
    return;
  frontend_remove_fsocket(socket);
  socket->close_requested = 1; //标记已经请求关闭了

  struct rte_mp_msg msg = {0};
  sprintf(msg.name, FAPI_CLOSE_FSOCKET_ACTION_NAME);
  msg.len_param = sizeof(fapi_common_req_t);
  fapi_common_req_t* req = msg.param;
  req->ptr = socket;

  if (rte_mp_sendmsg(&msg) < 0)
  {
    FNP_WARN("fail to send close msg to fnp-daemon: %s", rte_strerror(rte_errno));
  }
}


int fnp_sendto(int fd, fnp_mbuf_t* m, fsockaddr_t* raddr)
{
  fsocket_t* socket = frontend_get_fsocket(fd);
  if (unlikely(socket == NULL))
    return FNP_ERR_BAD_FD;

  fmbuf_info_t* info = get_fmbuf_info(m);
  fsockaddr_copy(&info->local, &socket->local);
  fsockaddr_copy(&info->remote, raddr);

  if (unlikely(fnp_ring_enqueue(socket->tx, m) == 0))
  {
    return FNP_ERR_FULL;
  }

  // 会严重降低吞吐量，注释掉
  // fsocket_notify_backend(socket);

  return FNP_OK;
}

int fnp_send(int fd, fnp_mbuf_t* m)
{
  fsocket_t* socket = frontend_get_fsocket(fd);
  if (unlikely(socket == NULL))
    return FNP_ERR_BAD_FD;
  return fnp_sendto(fd, m, &socket->remote); // 默认发送到远程地址
}

// 可以通过get_sockinfo获取到目的地址等mbufinfo
int fnp_recvfrom(int fd, uint8_t* buf, int buf_len, fsockaddr_t* peer)
{
  fsocket_t* socket = frontend_get_fsocket(fd);
  if (unlikely(socket == NULL))
    return FNP_ERR_BAD_FD;
  if (unlikely(socket->fin_received))
    return FNP_ERR_EOF;

  // 当前批次数据已经接收完毕, 需要再从ring里取数据
  if (unlikely(frontend->recv_mbufs_counter[fd].index == frontend->recv_mbufs_counter[fd].total))
  {
    while ((frontend->recv_mbufs_counter[fd].total = fnp_ring_dequeue_burst(
      socket->rx, (void**)frontend->recv_mbufs[fd], RECV_BATCH_SIZE)) == 0)
    {
      if (unlikely(socket->receive_fin))
      {
        // 再次确认数据已接收完毕
        if (fnp_ring_empty(socket->rx))
        {
          socket->fin_received = 1;
          return FNP_ERR_EOF;
        }
      }
    }
    frontend->recv_mbufs_counter[fd].index = 0;
  }
  struct rte_mbuf* m = frontend->recv_mbufs[fd][frontend->recv_mbufs_counter[fd].index++];

  u8* data = rte_pktmbuf_mtod(m, u8*);
  int data_len = rte_pktmbuf_data_len(m);
  if (unlikely(data_len > buf_len))
    data_len = buf_len;
  // 复制数据到buf, memcpy比rte_memcpy的性能要好很多
  memcpy(buf, data, data_len);

  if (likely(peer != NULL))
  {
    fmbuf_info_t* info = get_fmbuf_info(m);
    fsockaddr_copy(peer, &info->remote);
  }

  fnp_free_mbuf(m);
  return data_len;
}

int fnp_recv(int fd, uint8_t* buf, int buf_len)
{
  return fnp_recvfrom(fd, buf, buf_len, NULL);
}
