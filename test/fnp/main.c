#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_arp.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "fnp.h"

#define UDP_DEMO_DEFAULT_FNP_IP "192.168.66.88"
#define UDP_DEMO_DEFAULT_KERNEL_IP "192.168.66.66"
#define UDP_DEMO_DEFAULT_SERVER_PORT 16666
#define UDP_DEMO_DEFAULT_CLIENT_PORT 18888
#define DEMO_DEFAULT_TUN_DEV "tun0"
#define DEMO_DEFAULT_TUN_LOCAL_IP "10.77.0.2"
#define DEMO_DEFAULT_TAP_DEV "tap0"
#define DEMO_DEFAULT_TAP_LOCAL_IP "10.88.0.2"
#define DEMO_DEFAULT_TAP_LOCAL_MAC "02:00:00:00:10:02"
#define DEMO_MAX_PAYLOAD 2048

static void format_ipv4(u32 ip_be, char *buf, size_t buf_len)
{
    struct in_addr addr = {.s_addr = ip_be};
    if (inet_ntop(AF_INET, &addr, buf, buf_len) == NULL)
    {
        snprintf(buf, buf_len, "0.0.0.0");
    }
}

static void print_sockaddr(const char *prefix, const fsockaddr_t *addr)
{
    char ip_text[INET_ADDRSTRLEN] = {0};
    format_ipv4(addr->ip, ip_text, sizeof(ip_text));
    printf("%s%s:%u\n", prefix, ip_text, rte_be_to_cpu_16(addr->port));
}

static int parse_mac(const char *text, struct rte_ether_addr *mac)
{
    unsigned int bytes[RTE_ETHER_ADDR_LEN];
    if (text == NULL || mac == NULL)
    {
        return -1;
    }

    if (sscanf(text, "%x:%x:%x:%x:%x:%x",
               &bytes[0], &bytes[1], &bytes[2],
               &bytes[3], &bytes[4], &bytes[5]) != RTE_ETHER_ADDR_LEN)
    {
        return -1;
    }

    for (int i = 0; i < RTE_ETHER_ADDR_LEN; ++i)
    {
        mac->addr_bytes[i] = (u8)bytes[i];
    }

    return 0;
}

static void format_mac(const struct rte_ether_addr *mac, char *buf, size_t buf_len)
{
    if (mac == NULL)
    {
        snprintf(buf, buf_len, "00:00:00:00:00:00");
        return;
    }

    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->addr_bytes[0], mac->addr_bytes[1], mac->addr_bytes[2],
             mac->addr_bytes[3], mac->addr_bytes[4], mac->addr_bytes[5]);
}

static u16 ipv4_header_len(const struct rte_ipv4_hdr *hdr)
{
    return (u16)((hdr->version_ihl & 0x0f) * 4);
}

static int build_udp_conf(fnp_udp_socket_conf_t *conf,
                          const char *local_ip, int local_port,
                          const char *remote_ip, int remote_port)
{
    memset(conf, 0, sizeof(*conf));
    int ret = fsockaddr_init(&conf->local, FSOCKADDR_IPV4, local_ip, local_port);
    if (ret != FNP_OK)
    {
        return ret;
    }

    if (remote_ip != NULL)
    {
        ret = fsockaddr_init(&conf->remote, FSOCKADDR_IPV4, remote_ip, remote_port);
        if (ret != FNP_OK)
        {
            return ret;
        }
    }

    return FNP_OK;
}

static int build_tun_conf(fnp_tun_socket_conf_t *conf, const char *dev_name)
{
    if (conf == NULL || dev_name == NULL)
    {
        return FNP_ERR_PARAM;
    }

    memset(conf, 0, sizeof(*conf));
    snprintf(conf->dev_name, sizeof(conf->dev_name), "%s", dev_name);
    return FNP_OK;
}

static int build_tap_conf(fnp_tap_socket_conf_t *conf, const char *dev_name)
{
    if (conf == NULL || dev_name == NULL)
    {
        return FNP_ERR_PARAM;
    }

    memset(conf, 0, sizeof(*conf));
    snprintf(conf->dev_name, sizeof(conf->dev_name), "%s", dev_name);
    return FNP_OK;
}

static fnp_mbuf_t *alloc_packet_mbuf(const u8 *data, int len)
{
    fnp_mbuf_t *m = fnp_alloc_mbuf();
    if (m == NULL)
    {
        return NULL;
    }

    memcpy(fnp_mbuf_data(m), data, (size_t)len);
    fnp_mbuf_append_data(m, len);
    return m;
}

static int build_ipv4_udp_packet(u8 *buf, int buf_len,
                                 u32 src_ip_be, u16 src_port_be,
                                 u32 dst_ip_be, u16 dst_port_be,
                                 const u8 *payload, int payload_len)
{
    int total_len = (int)sizeof(struct rte_ipv4_hdr) + (int)sizeof(struct rte_udp_hdr) + payload_len;
    if (buf == NULL || payload == NULL || payload_len < 0 || buf_len < total_len)
    {
        return -1;
    }

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)buf;
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(buf + sizeof(*ip));
    u8 *data = buf + sizeof(*ip) + sizeof(*udp);

    memcpy(data, payload, (size_t)payload_len);

    memset(ip, 0, sizeof(*ip));
    ip->version_ihl = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = src_ip_be;
    ip->dst_addr = dst_ip_be;
    ip->total_length = rte_cpu_to_be_16((u16)total_len);

    memset(udp, 0, sizeof(*udp));
    udp->src_port = src_port_be;
    udp->dst_port = dst_port_be;
    udp->dgram_len = rte_cpu_to_be_16((u16)(sizeof(*udp) + payload_len));
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    return total_len;
}

static int build_ether_ipv4_udp_packet(u8 *buf, int buf_len,
                                       const struct rte_ether_addr *src_mac,
                                       const struct rte_ether_addr *dst_mac,
                                       u32 src_ip_be, u16 src_port_be,
                                       u32 dst_ip_be, u16 dst_port_be,
                                       const u8 *payload, int payload_len)
{
    int ip_len = build_ipv4_udp_packet(buf + sizeof(struct rte_ether_hdr),
                                       buf_len - (int)sizeof(struct rte_ether_hdr),
                                       src_ip_be, src_port_be,
                                       dst_ip_be, dst_port_be,
                                       payload, payload_len);
    if (ip_len < 0)
    {
        return -1;
    }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)buf;
    rte_ether_addr_copy(src_mac, &eth->src_addr);
    rte_ether_addr_copy(dst_mac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    return (int)sizeof(*eth) + ip_len;
}

static void udp_server_handler(fnp_socket_t *socket, fnp_mbuf_t *m, void *arg)
{
    (void)arg;

    fnp_mbuf_info_t *info = fnp_get_mbuf_info(m);
    int len = fnp_get_mbuf_len(m);
    const u8 *data = fnp_mbuf_data(m);

    char peer_ip[INET_ADDRSTRLEN] = {0};
    format_ipv4(info->remote.ip, peer_ip, sizeof(peer_ip));
    printf("udp server recv %d bytes from %s:%u: %.*s\n",
           len,
           peer_ip,
           rte_be_to_cpu_16(info->remote.port),
           len,
           (const char *)data);

    fnp_mbuf_t *reply = fnp_alloc_mbuf();
    if (reply == NULL)
    {
        fprintf(stderr, "fail to alloc reply mbuf\n");
        return;
    }

    memcpy(fnp_mbuf_data(reply), data, (size_t)len);
    fnp_mbuf_append_data(reply, len);

    int ret = fnp_socket_sendto(socket, reply, &info->remote);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fail to send echo reply: %d\n", ret);
        fnp_free_mbuf(reply);
    }
}

static int run_udp_server(const char *local_ip, int local_port)
{
    fnp_udp_socket_conf_t conf;
    int ret = build_udp_conf(&conf, local_ip, local_port, NULL, 0);
    if (ret != FNP_OK)
    {
        return ret;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_udp, &conf, &socket);
    if (ret != FNP_OK)
    {
        return ret;
    }

    print_sockaddr("udp server listen on ", &conf.local);
    int epfd = fnp_epoll_create();
    if (epfd < 0)
    {
        fnp_socket_close(socket);
        return epfd;
    }

    ret = fnp_epoll_add(epfd, socket, udp_server_handler, NULL);
    if (ret != FNP_OK)
    {
        fnp_epoll_destroy(epfd);
        fnp_socket_close(socket);
        return ret;
    }

    while (1)
    {
        ret = fnp_epoll_wait(epfd, -1, 64);
        if (ret < 0)
        {
            break;
        }
    }

    fnp_epoll_destroy(epfd);
    fnp_socket_close(socket);
    return ret;
}

static int run_udp_client(const char *local_ip, int local_port,
                          const char *remote_ip, int remote_port,
                          const char *message, int count)
{
    fnp_udp_socket_conf_t conf;
    int ret = build_udp_conf(&conf, local_ip, local_port, remote_ip, remote_port);
    if (ret != FNP_OK)
    {
        return ret;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_udp, &conf, &socket);
    if (ret != FNP_OK)
    {
        return ret;
    }

    print_sockaddr("udp client local  ", &conf.local);
    print_sockaddr("udp client remote ", &conf.remote);

    char payload[DEMO_MAX_PAYLOAD] = {0};
    char reply[DEMO_MAX_PAYLOAD + 1] = {0};
    for (int i = 0; i < count; ++i)
    {
        int payload_len;
        if (count > 1)
        {
            payload_len = snprintf(payload, sizeof(payload), "%s #%d", message, i + 1);
        }
        else
        {
            payload_len = snprintf(payload, sizeof(payload), "%s", message);
        }
        if (payload_len < 0 || payload_len >= (int)sizeof(payload))
        {
            fnp_socket_close(socket);
            return FNP_ERR_PARAM;
        }

        fnp_mbuf_t *m = fnp_alloc_mbuf();
        if (m == NULL)
        {
            fnp_socket_close(socket);
            return FNP_ERR_MBUF_ALLOC;
        }

        memcpy(fnp_mbuf_data(m), payload, (size_t)payload_len);
        fnp_mbuf_append_data(m, payload_len);
        ret = fnp_socket_send(socket, m);
        if (ret != FNP_OK)
        {
            fnp_free_mbuf(m);
            fnp_socket_close(socket);
            return ret;
        }

        fsockaddr_t peer = {0};
        ret = fnp_socket_recvfrom(socket, (u8 *)reply, DEMO_MAX_PAYLOAD, &peer);
        if (ret < 0)
        {
            fnp_socket_close(socket);
            return ret;
        }
        reply[ret] = '\0';
        char peer_ip[INET_ADDRSTRLEN] = {0};
        format_ipv4(peer.ip, peer_ip, sizeof(peer_ip));
        printf("udp client recv %d bytes from %s:%u: %s\n",
               ret, peer_ip, rte_be_to_cpu_16(peer.port), reply);
    }

    fnp_socket_close(socket);
    return FNP_OK;
}

static int run_tun_serve(const char *dev_name, const char *service_ip_text)
{
    fnp_tun_socket_conf_t conf;
    int ret = build_tun_conf(&conf, dev_name);
    if (ret != FNP_OK)
    {
        return ret;
    }

    u32 service_ip_be = fnp_ipv4_ston(service_ip_text);
    if (service_ip_be == 0)
    {
        return FNP_ERR_PARAM;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_tun, &conf, &socket);
    if (ret != FNP_OK)
    {
        return ret;
    }

    printf("tun serve on dev=%s service_ip=%s\n", conf.dev_name, service_ip_text);
    u8 packet[DEMO_MAX_PAYLOAD];
    while (1)
    {
        ret = fnp_socket_recv(socket, packet, sizeof(packet));
        if (ret < (int)(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)))
        {
            continue;
        }

        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)packet;
        if ((ip->version_ihl >> 4) != 4 || ip->next_proto_id != IPPROTO_UDP)
        {
            continue;
        }

        u16 ip_hdr_len = ipv4_header_len(ip);
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(packet + ip_hdr_len);
        int payload_len = ret - (int)ip_hdr_len - (int)sizeof(*udp);
        if (payload_len < 0 || ip->dst_addr != service_ip_be)
        {
            continue;
        }

        char src_ip[INET_ADDRSTRLEN] = {0};
        char dst_ip[INET_ADDRSTRLEN] = {0};
        format_ipv4(ip->src_addr, src_ip, sizeof(src_ip));
        format_ipv4(ip->dst_addr, dst_ip, sizeof(dst_ip));
        printf("tun recv udp %s:%u -> %s:%u, %d bytes: %.*s\n",
               src_ip, rte_be_to_cpu_16(udp->src_port),
               dst_ip, rte_be_to_cpu_16(udp->dst_port),
               payload_len, payload_len, (char *)(packet + ip_hdr_len + sizeof(*udp)));

        u8 reply_packet[DEMO_MAX_PAYLOAD];
        int reply_len = build_ipv4_udp_packet(reply_packet, sizeof(reply_packet),
                                              ip->dst_addr, udp->dst_port,
                                              ip->src_addr, udp->src_port,
                                              packet + ip_hdr_len + sizeof(*udp), payload_len);
        if (reply_len < 0)
        {
            continue;
        }

        fnp_mbuf_t *reply = alloc_packet_mbuf(reply_packet, reply_len);
        if (reply == NULL)
        {
            continue;
        }

        ret = fnp_socket_send(socket, reply);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "tun send reply failed: %d\n", ret);
            fnp_free_mbuf(reply);
        }
    }
}

static int send_tap_arp_reply(fnp_socket_t *socket,
                              const struct rte_ether_addr *local_mac,
                              u32 local_ip_be,
                              const struct rte_ether_addr *remote_mac,
                              u32 remote_ip_be)
{
    u8 frame[sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)] = {0};
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)frame;
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(frame + sizeof(*eth));

    rte_ether_addr_copy(local_mac, &eth->src_addr);
    rte_ether_addr_copy(remote_mac, &eth->dst_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);

    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(u32);
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    rte_ether_addr_copy(local_mac, &arp->arp_data.arp_sha);
    arp->arp_data.arp_sip = local_ip_be;
    rte_ether_addr_copy(remote_mac, &arp->arp_data.arp_tha);
    arp->arp_data.arp_tip = remote_ip_be;

    fnp_mbuf_t *m = alloc_packet_mbuf(frame, (int)sizeof(frame));
    if (m == NULL)
    {
        return FNP_ERR_MBUF_ALLOC;
    }

    int ret = fnp_socket_send(socket, m);
    if (ret != FNP_OK)
    {
        fnp_free_mbuf(m);
    }
    return ret;
}

static int run_tap_serve(const char *dev_name, const char *service_mac_text, const char *service_ip_text)
{
    fnp_tap_socket_conf_t conf;
    int ret = build_tap_conf(&conf, dev_name);
    if (ret != FNP_OK)
    {
        return ret;
    }

    struct rte_ether_addr service_mac;
    if (parse_mac(service_mac_text, &service_mac) != 0)
    {
        return FNP_ERR_PARAM;
    }

    u32 service_ip_be = fnp_ipv4_ston(service_ip_text);
    if (service_ip_be == 0)
    {
        return FNP_ERR_PARAM;
    }

    fnp_socket_t *socket = NULL;
    ret = fnp_socket_create(fsocket_type_tap, &conf, &socket);
    if (ret != FNP_OK)
    {
        return ret;
    }

    printf("tap serve on dev=%s service_mac=%s service_ip=%s\n",
           conf.dev_name, service_mac_text, service_ip_text);

    u8 frame[DEMO_MAX_PAYLOAD];
    while (1)
    {
        ret = fnp_socket_recv(socket, frame, sizeof(frame));
        if (ret < (int)sizeof(struct rte_ether_hdr))
        {
            continue;
        }

        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)frame;
        u16 ether_type = rte_be_to_cpu_16(eth->ether_type);
        if (ether_type == RTE_ETHER_TYPE_ARP)
        {
            if (ret < (int)(sizeof(*eth) + sizeof(struct rte_arp_hdr)))
            {
                continue;
            }

            struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(frame + sizeof(*eth));
            if (rte_be_to_cpu_16(arp->arp_opcode) != RTE_ARP_OP_REQUEST ||
                arp->arp_data.arp_tip != service_ip_be)
            {
                continue;
            }

            send_tap_arp_reply(socket, &service_mac, service_ip_be, &arp->arp_data.arp_sha, arp->arp_data.arp_sip);
            continue;
        }

        if (ether_type != RTE_ETHER_TYPE_IPV4 ||
            ret < (int)(sizeof(*eth) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)))
        {
            continue;
        }

        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(frame + sizeof(*eth));
        if ((ip->version_ihl >> 4) != 4 || ip->next_proto_id != IPPROTO_UDP || ip->dst_addr != service_ip_be)
        {
            continue;
        }

        u16 ip_hdr_len = ipv4_header_len(ip);
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)((u8 *)ip + ip_hdr_len);
        int payload_len = ret - (int)sizeof(*eth) - (int)ip_hdr_len - (int)sizeof(*udp);
        if (payload_len < 0)
        {
            continue;
        }

        char src_ip[INET_ADDRSTRLEN] = {0};
        char src_mac[32] = {0};
        format_ipv4(ip->src_addr, src_ip, sizeof(src_ip));
        format_mac(&eth->src_addr, src_mac, sizeof(src_mac));
        printf("tap recv udp %s/%s:%u -> %s:%u, %d bytes: %.*s\n",
               src_mac, src_ip, rte_be_to_cpu_16(udp->src_port), service_ip_text,
               rte_be_to_cpu_16(udp->dst_port), payload_len, payload_len, (char *)((u8 *)udp + sizeof(*udp)));

        u8 reply_frame[DEMO_MAX_PAYLOAD];
        int reply_len = build_ether_ipv4_udp_packet(reply_frame, sizeof(reply_frame),
                                                    &service_mac, &eth->src_addr,
                                                    ip->dst_addr, udp->dst_port,
                                                    ip->src_addr, udp->src_port,
                                                    (u8 *)udp + sizeof(*udp), payload_len);
        if (reply_len < 0)
        {
            continue;
        }

        fnp_mbuf_t *reply = alloc_packet_mbuf(reply_frame, reply_len);
        if (reply == NULL)
        {
            continue;
        }

        ret = fnp_socket_send(socket, reply);
        if (ret != FNP_OK)
        {
            fprintf(stderr, "tap send reply failed: %d\n", ret);
            fnp_free_mbuf(reply);
        }
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s udp-server [local_ip] [local_port]\n"
            "  %s udp-client [local_ip] [local_port] [remote_ip] [remote_port] [message] [count]\n"
            "  %s tun-serve [dev_name] [service_ip]\n"
            "  %s tap-serve [dev_name] [service_mac] [service_ip]\n",
            prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    int ret = fnp_init(0, NULL, 0);
    if (ret != FNP_OK)
    {
        fprintf(stderr, "fnp_init failed: %d\n", ret);
        return 1;
    }

    if (strcmp(argv[1], "udp-server") == 0)
    {
        const char *local_ip = argc > 2 ? argv[2] : UDP_DEMO_DEFAULT_FNP_IP;
        int local_port = argc > 3 ? atoi(argv[3]) : UDP_DEMO_DEFAULT_SERVER_PORT;
        return run_udp_server(local_ip, local_port);
    }

    if (strcmp(argv[1], "udp-client") == 0)
    {
        const char *local_ip = argc > 2 ? argv[2] : UDP_DEMO_DEFAULT_FNP_IP;
        int local_port = argc > 3 ? atoi(argv[3]) : UDP_DEMO_DEFAULT_CLIENT_PORT;
        const char *remote_ip = argc > 4 ? argv[4] : UDP_DEMO_DEFAULT_KERNEL_IP;
        int remote_port = argc > 5 ? atoi(argv[5]) : UDP_DEMO_DEFAULT_SERVER_PORT;
        const char *message = argc > 6 ? argv[6] : "hello-from-fnp";
        int count = argc > 7 ? atoi(argv[7]) : 1;
        return run_udp_client(local_ip, local_port, remote_ip, remote_port, message, count);
    }

    if (strcmp(argv[1], "tun-serve") == 0)
    {
        const char *dev_name = argc > 2 ? argv[2] : DEMO_DEFAULT_TUN_DEV;
        const char *service_ip = argc > 3 ? argv[3] : DEMO_DEFAULT_TUN_LOCAL_IP;
        return run_tun_serve(dev_name, service_ip);
    }

    if (strcmp(argv[1], "tap-serve") == 0)
    {
        const char *dev_name = argc > 2 ? argv[2] : DEMO_DEFAULT_TAP_DEV;
        const char *service_mac = argc > 3 ? argv[3] : DEMO_DEFAULT_TAP_LOCAL_MAC;
        const char *service_ip = argc > 4 ? argv[4] : DEMO_DEFAULT_TAP_LOCAL_IP;
        return run_tap_serve(dev_name, service_mac, service_ip);
    }

    usage(argv[0]);
    return 1;
}
