#ifndef SOCKET_H
#define SOCKET_H

#include <arpa/inet.h>

// 套接字相关函数声明
int create_socket(int is_udp);

void set_sockaddr(struct sockaddr_in *addr, char *ip, int port);

void set_sockopt(int sockfd);

void bind_socket(int sockfd, char *ip, int port);

void connect_socket(int sockfd, char *ip, int port);

#endif /* SOCKET_H */
