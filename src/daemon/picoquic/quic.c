#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"
#include "picoquic_sample.h"
#include "fnp_socket.h"
#include "fnp_context.h"
#include "udp.h"

picoquic_quic_t *quic;
picoquic_cnx_t *conns[10];
int conn_num = 0;

void init_quic_layer()
{
    // 初始化quic上下文
    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection.
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    char const *ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const *token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;
    uint64_t current_time = picoquic_current_time();
    quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL,
                           NULL, NULL, NULL, current_time, NULL,
                           ticket_store_filename, NULL, 0);
    if (quic == NULL)
    {
        fprintf(stderr, "Could not create quic context\n");
        return -1;
    }

    // 加载token
    if (picoquic_load_retry_tokens(quic, token_store_filename) != 0)
    {
        fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
    }

    picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);
    picoquic_set_key_log_file_from_env(quic);
    // picoquic_set_qlog(quic, qlog_dir);
    picoquic_set_log_level(quic, 1);

    faddr_t local, remote;
    init_faddr(&local, "192.168.11.222", 6666);
    init_faddr(&remote, "192.168.11.88", 16666);

    quic_create_client(&local, &remote);
}

int handle_quic(picoquic_cnx_t *conn)
{
    int ret = 0;
    picoquic_quic_t *quic = conn->quic;
    fsocket_t *socket = conn->socket;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t *last_cnx = NULL;

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    int64_t delta_t = 0;
    unsigned char received_ecn;
    faddr_t raddr;
    uint64_t current_time = picoquic_current_time();
    uint64_t next_send_time = current_time + PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX;

    // 接收数据
    // picoquic_select_ex阻塞，有超时时间
    // bytes_recv = picoquic_select_ex(s_socket, nb_sockets,
    //     &addr_from,
    //     &addr_to, &if_index_to, &received_ecn,
    //     buffer, sizeof(buffer),
    //     delta_t, &socket_rank, &current_time);
    struct rte_mbuf *m = udp_recv_data(socket, &raddr);
    if (m != NULL)
    {

        uint8_t *data = rte_pktmbuf_mtod(m, uint8_t *);
        int bytes_recv = rte_pktmbuf_data_len(m);
        // 设置addr_from和addr_to
        ((struct sockaddr_in *)&addr_to)->sin_port = socket->lport;
        ((struct sockaddr_in *)&addr_to)->sin_addr.s_addr = socket->lip;
        ((struct sockaddr_in *)&addr_from)->sin_port = raddr.port;
        ((struct sockaddr_in *)&addr_from)->sin_addr.s_addr = raddr.ip;

        /* quic协议处理接收到的数据包 */
        picoquic_incoming_packet_ex(quic, data,
                                    (size_t)bytes_recv, (struct sockaddr *)&addr_from,
                                    (struct sockaddr *)&addr_to, 0, received_ecn,
                                    &last_cnx, current_time);
        free_mbuf(m);
    }

    // 发送数据
    if (1) // 不到发送的时间，继续循环
    {
        // next_send_time = current_time + PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX;

        size_t bytes_sent = 0;

        while (ret == 0)
        {
            struct sockaddr_storage peer_addr;
            struct sockaddr_storage local_addr;
            faddr_t send_addr;
            size_t send_buffer_size = 1536;
            size_t send_length = 0;
            size_t send_msg_size = 0;
            void *send_msg_ptr = NULL;
            int if_index = 0;
            int sock_ret = 0;
            int sock_err = 0;

            // 发送数据
            struct rte_mbuf *m = alloc_mbuf();
            u8 *buf = rte_pktmbuf_mtod(m, uint8_t *);
            ret = picoquic_prepare_next_packet_ex(quic, current_time,
                                                  buf, send_buffer_size, &send_length,
                                                  &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                                                  send_msg_ptr);

            if (ret != 0 || send_length <= 0)
            {
                free_mbuf(m);
                break;
            }
            bytes_sent += send_length;
            rte_pktmbuf_append(m, send_length);
            send_addr.ip = ((struct sockaddr_in *)&peer_addr)->sin_addr.s_addr;
            send_addr.port = ((struct sockaddr_in *)&peer_addr)->sin_port;

            // sock_ret = picoquic_sendmsg(send_socket,
            //                             (struct sockaddr *)&peer_addr, (struct sockaddr *)&local_addr, if_index,
            //                             (const char *)send_buffer, (int)send_length, (int)send_msg_size, &sock_err);
            sock_ret = udp_sendto(socket, m, &send_addr);
            // TODO: 后续有对发送失败的处理，现在暂时删除
        }
    }
}

// 创建一个QUIC服务端
int quic_create_server(faddr_t *local)
{
}

int sample_client_callback(picoquic_cnx_t *cnx,
                           uint64_t stream_id, uint8_t *bytes, size_t length,
                           picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
    int ret = 0;

    switch (fin_or_event)
    {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        if (ret == 0 && length > 0)
        {
            bytes[length] = '\0'; // 最后一个字节为'\0'，表示字符串结束
            printf("Received %d bytes on stream %d: %s\n", length, (int)stream_id, bytes);
        }

        if (ret == 0 && fin_or_event == picoquic_callback_stream_fin)
        {
            printf("Received FIN on stream %d\n", (int)stream_id);
            ret = picoquic_close(cnx, 0);
        }
        break;
    case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
        /* Mark stream as abandoned, close the file, etc. */
        picoquic_reset_stream(cnx, stream_id, 0);
    /* Fall through */
    case picoquic_callback_stream_reset: /* Server reset stream #x */
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close:             /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        fprintf(stdout, "Connection closed.\n");
        /* Mark the connection as completed */
        /* Remove the application callback */
        picoquic_set_callback(cnx, NULL, NULL);
        break;
    case picoquic_callback_version_negotiation:
        /* The client did not get the right version.
         * TODO: some form of negotiation?
         */
        fprintf(stdout, "Received a version negotiation request:");
        for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4)
        {
            uint32_t vn = 0;
            for (int i = 0; i < 4; i++)
            {
                vn <<= 8;
                vn += bytes[byte_index + i];
            }
            fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
        }
        fprintf(stdout, "\n");
        break;
    case picoquic_callback_stream_gap:
        /* This callback is never used. */
        break;
    case picoquic_callback_prepare_to_send:
        /* Active sending API */
        fprintf(stdout, "send data to server.\n");
        picoquic_add_to_stream(cnx, stream_id, "Hello, server!", 14, 0);
        break;
    case picoquic_callback_almost_ready:
        fprintf(stdout, "Connection to the server completed, almost ready.\n");
        break;
    case picoquic_callback_ready:
        /* TODO: Check that the transport parameters are what the sample expects */
        fprintf(stdout, "Connection to the server confirmed.\n");
        break;
    default:
        /* unexpected -- just ignore. */
        break;
    }

    return ret;
}

// 创建一个QUIC客户端连接
// local: 本地地址，可以为NULL
// remote: 远程地址, 不能为空
int quic_create_client(faddr_t *local, faddr_t *remote)
{
    fsockaddr_t addr;
    init_fsockaddr(&addr, IPPROTO_UDP, local, remote);
    fsocket_t *socket = create_socket(&addr, 0);
    if (socket == NULL)
    {
        printf("create socket failed\n");
        return -1;
    }
    // socket->handler = handle_quic;

    int ret = 0;
    char const *sni = PICOQUIC_SAMPLE_SNI;
    picoquic_cnx_t *cnx = NULL;
    uint64_t current_time = picoquic_current_time();
    printf("Starting connection to %d, port %d\n", remote->ip, remote->port);

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = remote->ip;
    server_address.sin_port = remote->port;
    // 创建quic连接
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                              (struct sockaddr *)&server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);
    if (cnx == NULL)
    {
        fprintf(stderr, "Could not create connection context\n");
        return -1;
    }
    cnx->socket = socket;

    /* Set the client callback context */
    picoquic_set_callback(cnx, sample_client_callback, NULL);
    /* Client connection parameters could be set here, before starting the connection. */
    ret = picoquic_start_client_cnx(cnx);
    if (ret < 0)
    {
        fprintf(stderr, "Could not activate connection\n");
        return -1;
    }

    conns[conn_num] = cnx;
    conn_num++;

    /* Printing out the initial CID, which is used to identify log files */
    picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
    printf("Initial connection ID: ");
    for (uint8_t i = 0; i < icid.id_len; i++)
    {
        printf("%02x", icid.id[i]);
    }
    printf("\n");
}

void quic_loop()
{
    for (int i = 0; i < conn_num; i++)
        handle_quic(conns[i]); // 处理连接
}