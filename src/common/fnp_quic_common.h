#ifndef FNP_QUIC_COMMON_H
#define FNP_QUIC_COMMON_H

#include "fnp_cc.h"

typedef struct fnp_quic_config
{
    char* cert_filename; // 证书文件, 服务端必须
    char* key_filename; // 私钥文件, 服务端必须
    char* cert_root_filename; // 证书链文件, 可选
    congestion_algorithm_id_t congestion_algo; //拥塞控制算法
    char* sni; // 服务器名称指示, 客户端指定请求的目标域名
    char* alpn; //  服务端和客户端支持的应用层协议
    int max_nb_connections; // 1
    char* qlog_dir; // qlog目录, 用于记录调试信息, maybe null
    char* key_log_filename; //用于wireshark解包
    char* token_store_filename;
    char* ticket_filename;
    const u8* ticket_encryption_key; // NULL
    int ticket_encryption_key_length; // 0
    u8* reset_seed; // 16字节长度

    int local_cid_length; // 8
} fnp_quic_config_t;

void fnp_quic_set_certificates(
    fnp_quic_config_t* config,
    const char* cert_filename,
    const char* key_filename,
    const char* cert_root_filename
);

#endif //FNP_QUIC_COMMON_H
