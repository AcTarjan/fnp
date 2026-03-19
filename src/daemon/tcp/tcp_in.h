#ifndef FNP_TCP_IN_H
#define FNP_TCP_IN_H


void tcp_recv_init();

int tcp_deliver_data_to_app(fsocket_t* socket, struct rte_mbuf* data);

void tcp_handle_fin(tcp_sock_t* sock);

void tcp_socket_recv(fsocket_t* socket, struct rte_mbuf* m);


#endif // FNP_TCP_IN_H
