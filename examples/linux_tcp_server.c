#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include "../inc/fnp.h"
#include "exp_common.h"


void *handle_connection(void *newsockfd) {
    char buffer[2000];
    int n;

    int64_t count = 0;
    while (1) {
        n = read(*(int *) newsockfd, buffer, 2000);
        if (n < 0) {
            perror("ERROR reading from socket");
            pthread_exit(NULL);
        }
        count += n;
        if (count > 1000000) {
            showBw(count);
            count = 0;
        }
    }

//    printf("Here is the message: %s\n",buffer);
    close(*(int*)newsockfd);

    return NULL;
}

int main(int argc, char *argv[])
{
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    pthread_t thread_id;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        return 1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 18888;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = fnp_ipv4_ston("192.168.11.22");
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        return 1;
    }

    listen(sockfd,5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("ERROR on accept");
            return 1;
        }
        printf("recv a new connection\n");

        if (pthread_create(&thread_id, NULL, handle_connection, &newsockfd) < 0) {
            perror("could not create thread");
            return 1;
        }
    }

    close(sockfd);
    return 0;
}