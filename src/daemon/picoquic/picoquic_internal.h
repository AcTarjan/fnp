#ifndef PICOQUIC_INTERNAL_H
#define PICOQUIC_INTERNAL_H

#include "quic_common.h"
#ifdef __cplusplus
extern "C"
{
#endif


/*
 * Efficient range operations that assume range containing bitfields.
 * Namely, it assumes max&min==min, min&bits==0, max&bits==bits.
 */
#define PICOQUIC_IN_RANGE(v, min, max) (((v) & ~((min) ^ (max))) == (min))
// Is v between min and max and has all given bits set/clear?
#define PICOQUIC_BITS_SET_IN_RANGE(v, min, max, bits) (((v) & ~((min) ^ (max) ^ (bits))) == ((min) ^ (bits)))
#define PICOQUIC_BITS_CLEAR_IN_RANGE(v, min, max, bits) (((v) & ~((min) ^ (max) ^ (bits))) == (min))

/*
 * Supported versions
 */
#define PICOQUIC_V1_VERSION 0x00000001
#define PICOQUIC_V2_VERSION 0x6b3343cf

#define PICOQUIC_INTEROP_VERSION_INDEX 0
#define PICOQUIC_INTEROP_VERSION_LATEST PICOQUIC_V2_VERSION

typedef struct st_picoquic_version_parameters_t
{
    uint32_t version;
    size_t version_aead_key_length;
    uint8_t* version_aead_key;
    size_t version_retry_key_length;
    uint8_t* version_retry_key;
    char* tls_prefix_label;
    char* tls_traffic_update_label;
    uint32_t packet_type_version;
    uint32_t* upgrade_from;
} picoquic_version_parameters_t;

extern const picoquic_version_parameters_t picoquic_supported_versions[];
extern const size_t picoquic_nb_supported_versions;

int picoquic_get_version_index(uint32_t proposed_version);


/* Packet header structure.
 * This structure is used internally when parsing or
 * formatting the header of a Quic packet.
 */
struct st_quic_stream_data_t;

typedef struct st_picoquic_packet_header_t
{
    quic_connection_id_t dest_cnx_id;
    quic_connection_id_t srce_cnx_id;
    uint32_t pn;
    uint32_t vn;
    picoquic_packet_type_enum ptype;
    uint64_t pnmask;
    uint64_t pn64;
    int version_index;
    picoquic_epoch_enum epoch;
    picoquic_packet_context_enum pc;

    unsigned int key_phase : 1;
    unsigned int spin : 1;
    unsigned int has_spin_bit : 1;
    unsigned int has_reserved_bit_set : 1;
    unsigned int has_loss_bits : 1;
    unsigned int loss_bit_Q : 1;
    unsigned int loss_bit_L : 1;
    unsigned int quic_bit_is_zero : 1;

    size_t token_length;
    const uint8_t* token_bytes;

    // quic_cnx_t* cnx;
    struct st_picoquic_local_cnxid_t* lcid; // maybe NULL

    u64 current_time;
    u64 receive_time; //用于记录缓存的数据包的接收时间
    struct rte_mbuf* mbuf;
    quic_packet_t* packet; //解密后数据包, 包括header + payload
    fsockaddr_t local;
    fsockaddr_t remote; //目前只支持ipv4
    u8* data; //解密前的原始数据
    int max_data_len; //数据包的长度
    int offset; //payload距离data的偏移量
    int payload_length; // 解密后,payload_length标识解密后的数据长度
    int iface_id;
    u8 ecn;
} quic_packet_header;

/* There are two loss bits in the packet header. On is used
 * to report errors, the other to build an observable square
 * wave, of half period Q defined below.
 */
#define PICOQUIC_LOSS_BIT_Q_HALF_PERIOD 64

/*
 * Management of the spin bit in the packet header.
 * We envisage different spin bit policies, and implement
 * each policy by 2 function pointers for processing incoming and
 * outgoing packets.
 */
typedef void (*picoquic_spinbit_incoming_fn)(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_header* ph);
typedef uint8_t (*picoquic_spinbit_outgoing_fn)(quic_cnx_t* cnx);

typedef struct st_picoquic_spinbit_def_t
{
    picoquic_spinbit_incoming_fn spinbit_incoming;
    picoquic_spinbit_outgoing_fn spinbit_outgoing;
} picoquic_spinbit_def_t;

extern picoquic_spinbit_def_t picoquic_spin_function_table[];


/* Handling of stateless packets */
picoquic_stateless_packet_t* picoquic_create_stateless_packet(quic_context_t* quic);
void picoquic_enqueue_stateless_packet(quic_context_t* quic, picoquic_stateless_packet_t* sp);
picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(quic_context_t* quic);
void picoquic_free_stateless_packet(picoquic_stateless_packet_t* sp);


quic_packet_t* quic_create_packet(int size);
void picoquic_recycle_packet(quic_packet_t* packet);
size_t picoquic_pad_to_policy(quic_cnx_t* cnx, uint8_t* bytes, size_t length, uint32_t max_length);

/* Definition of the token register used to prevent repeated usage of
 * the same new token, retry token, or session ticket.
 */

typedef struct st_picoquic_registered_token_t
{
    picosplay_node_t registered_token_node;
    uint64_t token_time;
    uint64_t token_hash; /* The last 8 bytes of the token, normally taken from AEAD checksum */
    int count;
} picoquic_registered_token_t;


int picoquic_store_ticket(quic_context_t* quic,
                          char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
                          uint32_t version, const uint8_t* ip_addr, uint8_t ip_addr_length,
                          const uint8_t* ip_addr_client, uint8_t ip_addr_client_length,
                          uint8_t* ticket, uint16_t ticket_length, picoquic_tp_t const* tp);
picoquic_stored_ticket_t* picoquic_get_stored_ticket(quic_context_t* quic,
                                                     char const* sni, uint16_t sni_length,
                                                     char const* alpn, uint16_t alpn_length, uint32_t version,
                                                     int need_unused, uint64_t ticket_id);
int picoquic_get_ticket(quic_context_t* quic,
                        char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
                        uint32_t version,
                        uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t* tp, int mark_used);
int picoquic_get_ticket_and_version(quic_context_t* quic,
                                    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
                                    uint32_t version, uint32_t* ticket_version,
                                    uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t* tp, int mark_used);
int picoquic_save_tickets(const picoquic_stored_ticket_t* first_ticket,
                          uint64_t current_time, char const* ticket_file_name);
int picoquic_load_tickets(quic_context_t* quic, char const* ticket_file_name);
void picoquic_free_tickets(picoquic_stored_ticket_t** pp_first_ticket);
void picoquic_seed_ticket(quic_cnx_t* cnx, picoquic_path_t* path_x);


int picoquic_store_token(quic_context_t* quic,
                         char const* sni, uint16_t sni_length,
                         uint8_t const* ip_addr, uint8_t ip_addr_length,
                         uint8_t const* token, uint16_t token_length);
int picoquic_get_token(quic_context_t* quic,
                       char const* sni, uint16_t sni_length,
                       uint8_t const* ip_addr, uint8_t ip_addr_length,
                       uint8_t** token, uint16_t* token_length, int mark_used);

int picoquic_save_tokens(quic_context_t* quic,
                         char const* token_file_name);
int picoquic_load_tokens(quic_context_t* quic, char const* token_file_name);
void picoquic_free_tokens(picoquic_stored_token_t** pp_first_token);

/* Remember the tickets issued by a server, and the last
 * congestion control parameters for the corresponding connection
 */


int picoquic_remember_issued_ticket(quic_context_t* quic,
                                    uint64_t ticket_id,
                                    uint64_t rtt,
                                    uint64_t cwin,
                                    const uint8_t* ip_addr,
                                    uint8_t ip_addr_length);

picoquic_issued_ticket_t* picoquic_retrieve_issued_ticket(quic_context_t* quic,
                                                          uint64_t ticket_id);


void picoquic_set_default_congestion_algorithm(quic_context_t* quic, congestion_algorithm_id_t algo_id);

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch);

int picoquic_registered_token_check_reuse(quic_context_t* quic, const uint8_t* token, size_t token_length,
                                          uint64_t expiry_time);

void picoquic_registered_token_clear(quic_context_t* quic, uint64_t expiry_time_max);


// 00 客户端双向 01客户端单向 10服务端双向 11服务端单向
#define IS_CLIENT_STREAM_ID(id) (unsigned int)(((id) & 1) == 0)
#define IS_BIDIR_STREAM_ID(id) (unsigned int)(((id) & 2) == 0)
#define IS_LOCAL_STREAM_ID(id, client_mode) (unsigned int)(((id) ^ (client_mode)) & 1)
#define STREAM_ID_FROM_RANK(rank, client_mode, is_unidir) ((((uint64_t)(rank) - (uint64_t)1) << 2) | (((uint64_t)is_unidir) << 1) | ((uint64_t)(client_mode ^ 1)))
#define STREAM_RANK_FROM_ID(id) ((id + 4) >> 2)
#define STREAM_TYPE_FROM_ID(id) ((id) & 3)
#define NEXT_STREAM_ID_FOR_TYPE(id) ((id) + 4)

int quic_recv_stream_data(quic_stream_t* stream,
                          uint8_t* bytes, size_t length, int fin);

/* Load the stash of retry tokens. */
int picoquic_load_token_file(quic_context_t* quic, char const* token_file_name);

/* Init of transport parameters */
void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode);

int quic_init_context(quic_context_t* quic, fnp_quic_config_t* conf, u64 current_time);

/* Registration of per path connection ID in server context */
int picoquic_register_cnx_id(quic_context_t* quic, quic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid);

/* Register or update default address and reset secret */
int picoquic_register_net_secret(quic_cnx_t* cnx);

/* Registration of initial connection ID and peer IP */
int picoquic_register_net_icid(quic_cnx_t* cnx);

void picoquic_create_random_cnx_id(quic_context_t* quic, quic_connection_id_t* cnx_id, uint8_t id_length);

void picoquic_create_local_cnx_id(quic_context_t* quic, quic_connection_id_t* cnx_id, uint8_t id_length,
                                  quic_connection_id_t cnx_id_remote);

/* Management of address tuples */
picoquic_tuple_t* picoquic_create_tuple(picoquic_path_t* path_x, fsockaddr_t* local_addr,
                                        fsockaddr_t* peer_addr, int if_index);
void picoquic_delete_demoted_tuples(quic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time);
void picoquic_delete_tuple(picoquic_path_t* path_x, picoquic_tuple_t* tuple);
/* Management of path */
int picoquic_create_path(quic_cnx_t* cnx, uint64_t start_time,
                         const fsockaddr_t* local, const fsockaddr_t* remote, int if_index,
                         uint64_t unique_path_id);
void picoquic_register_path(quic_cnx_t* cnx, picoquic_path_t* path_x);
int picoquic_find_incoming_path(quic_cnx_t* cnx, quic_packet_header* ph, int* p_path_id,
                                int* path_is_not_allocated);
/* Prepare packet containing only path control frames. */
int picoquic_prepare_path_control_packet(quic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_tuple_t* tuple,
                                         quic_packet_t* packet, uint64_t current_time, uint8_t* send_buffer,
                                         int* send_length, uint64_t* next_wake_time);
uint8_t* picoquic_prepare_path_challenge_frames(quic_cnx_t* cnx, picoquic_path_t* path_x,
                                                picoquic_packet_context_enum pc, int is_nominal_ack_path,
                                                uint8_t* bytes_next, uint8_t* bytes_max,
                                                int* more_data, int* is_pure_ack, int* is_challenge_padding_needed,
                                                uint64_t current_time, uint64_t* next_wake_time);
void picoquic_select_next_path_tuple(quic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time,
                                     picoquic_path_t** next_path, picoquic_tuple_t** next_tuple);
int picoquic_renew_connection_id(quic_cnx_t* cnx, int path_id);
void picoquic_delete_path(quic_cnx_t* cnx, int path_index);
void picoquic_demote_path(quic_cnx_t* cnx, int path_index, uint64_t current_time, uint64_t reason,
                          char const* phrase);
void picoquic_queue_retransmit_on_ack(quic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time);
void picoquic_delete_abandoned_paths(quic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time);
void picoquic_set_tuple_challenge(picoquic_tuple_t* tuple, uint64_t current_time, int use_constant_challenges);
void picoquic_set_path_challenge(quic_cnx_t* cnx, int path_id, uint64_t current_time);
int picoquic_find_path_by_address(quic_cnx_t* cnx, const fsockaddr_t* addr_local,
                                  const fsockaddr_t* addr_peer, int* partial_match);
int picoquic_find_path_by_unique_id(quic_cnx_t* cnx, uint64_t unique_path_id);
int picoquic_check_cid_for_new_tuple(quic_cnx_t* cnx, uint64_t unique_path_id);
int picoquic_assign_peer_cnxid_to_tuple(quic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_tuple_t* tuple);
// int picoquic_assign_peer_cnxid_to_path(picoquic_cnx_t* cnx, int path_id);
void picoquic_reset_path_mtu(picoquic_path_t* path_x);
int picoquic_get_path_id_from_unique(quic_cnx_t* cnx, uint64_t unique_path_id);

picoquic_remote_cnxid_stash_t* picoquic_find_or_create_remote_cnxid_stash(
    quic_cnx_t* cnx, uint64_t unique_path_id, int do_create);

/* Management of the CNX-ID stash */
int picoquic_init_cnxid_stash(quic_cnx_t* cnx);

uint64_t picoquic_add_remote_cnxid_to_stash(quic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* remote_cnxid_stash,
                                            uint64_t retire_before_next, const uint64_t sequence,
                                            const uint8_t cid_length, const uint8_t* cnxid_bytes,
                                            const uint8_t* secret_bytes, picoquic_remote_cnxid_t** pstashed);

uint64_t picoquic_stash_remote_cnxid(quic_cnx_t* cnx, uint64_t retire_before_next,
                                     const uint64_t unique_path_id, const uint64_t sequence, const uint8_t cid_length,
                                     const uint8_t* cnxid_bytes,
                                     const uint8_t* secret_bytes, picoquic_remote_cnxid_t** pstashed);

picoquic_remote_cnxid_t* picoquic_remove_cnxid_from_stash(quic_cnx_t* cnx,
                                                          picoquic_remote_cnxid_stash_t* remote_cnxid_stash,
                                                          picoquic_remote_cnxid_t* removed,
                                                          picoquic_remote_cnxid_t* previous);

picoquic_remote_cnxid_t* picoquic_remove_stashed_cnxid(quic_cnx_t* cnx, uint64_t unique_path_id,
                                                       picoquic_remote_cnxid_t* removed,
                                                       picoquic_remote_cnxid_t* previous);

picoquic_remote_cnxid_t* picoquic_get_cnxid_from_stash(picoquic_remote_cnxid_stash_t* stash);
picoquic_remote_cnxid_t* picoquic_obtain_stashed_cnxid(quic_cnx_t* cnx, uint64_t unique_path_id);
void picoquic_dereference_stashed_cnxid(quic_cnx_t* cnx, picoquic_path_t* path_x, int is_deleting_cnx);
uint64_t picoquic_remove_not_before_from_stash(quic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash,
                                               uint64_t not_before, uint64_t current_time);
void picoquic_delete_remote_cnxid_stash(quic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash);

uint64_t picoquic_remove_not_before_cid(quic_cnx_t* cnx, uint64_t unique_path_id, uint64_t not_before,
                                        uint64_t current_time);
int picoquic_renew_path_connection_id(quic_cnx_t* cnx, picoquic_path_t* path_x);

/* handling of retransmission queue */
void picoquic_enqueue_for_retransmit(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_t* packet,
                                     size_t length, uint64_t current_time);
quic_packet_t* picoquic_dequeue_retransmit_packet(quic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
                                                  quic_packet_t* p, int should_free);
void picoquic_dequeue_retransmitted_packet(quic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
                                           quic_packet_t* p);

/* Reset the connection context, e.g. after retry */
int picoquic_reset_cnx(quic_cnx_t* cnx, uint64_t current_time);

/* Reset packet context */
void picoquic_reset_packet_context(quic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx);

/* Notify error on connection */
int picoquic_connection_error(quic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type);
int picoquic_connection_error_ex(quic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type,
                                 char const* local_reason);

void picoquic_connection_disconnect(quic_cnx_t* cnx);

/* Connection context retrieval functions */
quic_cnx_t* picoquic_cnx_by_id(quic_context_t* quic, quic_connection_id_t cnx_id,
                               struct st_picoquic_local_cnxid_t** l_cid_sequence);
quic_cnx_t* picoquic_cnx_by_net(quic_context_t* quic, const fsockaddr_t* addr);
quic_cnx_t* picoquic_cnx_by_icid(quic_context_t* quic, quic_connection_id_t* icid,
                                 const fsockaddr_t* addr);
quic_cnx_t* picoquic_cnx_by_secret(quic_context_t* quic, const uint8_t* reset_secret, const fsockaddr_t* addr);

/* Pacing implementation */
void picoquic_pacing_init(picoquic_pacing_t* pacing, uint64_t current_time);
int picoquic_is_pacing_blocked(picoquic_pacing_t* pacing);
int picoquic_is_authorized_by_pacing(picoquic_pacing_t* pacing, uint64_t current_time, uint64_t* next_time,
                                     unsigned int packet_train_mode, quic_context_t* quic);
void picoquic_update_pacing_parameters(picoquic_pacing_t* pacing, double pacing_rate, uint64_t quantum, size_t send_mtu,
                                       uint64_t smoothed_rtt,
                                       picoquic_path_t* signalled_path);
void picoquic_update_pacing_window(picoquic_pacing_t* pacing, int slow_start, uint64_t cwin, size_t send_mtu,
                                   uint64_t smoothed_rtt, picoquic_path_t* signalled_path);
void picoquic_update_pacing_data_after_send(picoquic_pacing_t* pacing, size_t length, size_t send_mtu,
                                            uint64_t current_time);

/* Reset the pacing data after CWIN is updated */
void picoquic_update_pacing_data(quic_cnx_t* cnx, picoquic_path_t* path_x, int slow_start);
void picoquic_update_pacing_after_send(picoquic_path_t* path_x, size_t length, uint64_t current_time);
int picoquic_is_sending_authorized_by_pacing(quic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time,
                                             uint64_t* next_time);
/* Reset pacing data if congestion algorithm computes it directly */
void picoquic_update_pacing_rate(quic_cnx_t* cnx, picoquic_path_t* path_x, double pacing_rate, uint64_t quantum);
/* Manage path quality updates */
void picoquic_refresh_path_quality_thresholds(picoquic_path_t* path_x);
int picoquic_issue_path_quality_update(quic_cnx_t* cnx, picoquic_path_t* path_x);

/* Next time is used to order the list of available connections,
 * so ready connections are polled first */
void picoquic_reinsert_by_wake_time(quic_context_t* quic, quic_cnx_t* cnx, uint64_t next_time);

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0]) << 8) | (uint16_t)((b)[1]))
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b)) << 8) | (uint32_t)((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | (uint32_t)PICOPARSE_16((b) + 2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b)) << 32) | (uint64_t)PICOPARSE_32((b) + 4))

/* Integer formatting functions */
void picoformat_16(uint8_t* bytes, uint16_t n16);
void picoformat_24(uint8_t* bytes, uint32_t n24);
void picoformat_32(uint8_t* bytes, uint32_t n32);
void picoformat_64(uint8_t* bytes, uint64_t n64);

size_t picoquic_varint_encode(uint8_t* bytes, size_t max_bytes, uint64_t n64);
void picoquic_varint_encode_16(uint8_t* bytes, uint16_t n16);
size_t picoquic_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64);
const uint8_t* picoquic_frames_varint_decode(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
const uint8_t* picoquic_frames_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max);
size_t picoquic_varint_skip(const uint8_t* bytes);

size_t picoquic_encode_varint_length(uint64_t n64);
size_t picoquic_decode_varint_length(uint8_t byte);

/* Packet parsing */

picoquic_packet_type_enum picoquic_parse_long_packet_type(uint8_t flags, int version_index);

size_t picoquic_create_long_header(picoquic_packet_type_enum packet_type,
                                   quic_connection_id_t* dest_cnx_id, quic_connection_id_t* srce_cnx_id,
                                   int do_grease_quic_bit, uint32_t version, int version_index,
                                   uint64_t sequence_number,
                                   size_t retry_token_length, uint8_t* retry_token,
                                   uint8_t* bytes, size_t* pn_offset, size_t* pn_length);

size_t picoquic_create_packet_header(
    quic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_path_t* path_x,
    picoquic_tuple_t* tuple,
    size_t header_length,
    uint8_t* bytes,
    size_t* pn_offset,
    size_t* pn_length);

size_t picoquic_predict_packet_header_length(
    quic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    picoquic_packet_context_t* pkt_ctx);

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length);

int picoquic_get_checksum_length(quic_cnx_t* cnx, picoquic_epoch_enum is_cleartext_mode);

void picoquic_protect_packet_header(uint8_t* send_buffer, size_t pn_offset, uint8_t first_mask, void* pn_enc);

size_t picoquic_protect_packet(quic_cnx_t* cnx, picoquic_packet_type_enum ptype, uint8_t* bytes,
                               uint64_t sequence_number, size_t length, size_t header_length, uint8_t* send_buffer,
                               size_t send_buffer_max, void* aead_context, void* pn_enc,
                               picoquic_path_t* path_x, picoquic_tuple_t* tuple, uint64_t current_time);

uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);
int picoquic_remove_header_protection_inner(
    quic_packet_header* ph, void* pn_enc,
    unsigned int is_loss_bit_enabled_incoming,
    uint64_t sack_list_last);
size_t picoquic_pad_to_target_length(uint8_t* bytes, size_t length, size_t target);

int picoquic_finalize_and_protect_packet(quic_cnx_t* cnx, quic_packet_t* packet,
                                         uint8_t* send_buffer, picoquic_path_t* path_x, uint64_t current_time);

void picoquic_implicit_handshake_ack(quic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t current_time);
void picoquic_false_start_transition(quic_cnx_t* cnx, uint64_t current_time);
void picoquic_client_almost_ready_transition(quic_cnx_t* cnx);
void picoquic_ready_state_transition(quic_cnx_t* cnx, uint64_t current_time);

/* Shortcuts to packet numbers, last ack, last ack time.
 */
uint64_t picoquic_get_sequence_number(quic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc);

uint64_t picoquic_get_ack_number(quic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc);

quic_packet_t* picoquic_get_last_packet(quic_cnx_t* cnx, picoquic_path_t* path_x,
                                        picoquic_packet_context_enum pc);

/* handling of ACK logic */
void picoquic_init_ack_ctx(quic_cnx_t* cnx, picoquic_ack_context_t* ack_ctx);

int picoquic_is_ack_needed(quic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time,
                           picoquic_packet_context_enum pc, int is_opportunistic);

int picoquic_is_pn_already_received(quic_cnx_t* cnx, picoquic_packet_context_enum pc,
                                    picoquic_local_cnxid_t* l_cid, uint64_t pn64);
int picoquic_record_pn_received(quic_cnx_t* cnx, picoquic_packet_context_enum pc,
                                picoquic_local_cnxid_t* l_cid, uint64_t pn64, uint64_t current_microsec);

void picoquic_sack_select_ack_ranges(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* first_sack,
                                     int max_ranges, int is_opportunistic, int* nb_sent_max, int* nb_sent_max_skip);

int picoquic_update_sack_list(picoquic_sack_list_t* sack,
                              uint64_t pn64_min, uint64_t pn64_max, uint64_t current_time);
/* Check whether the data fills a hole. returns 0 if it does, -1 otherwise. */
int picoquic_check_sack_list(picoquic_sack_list_t* sack,
                             uint64_t pn64_min, uint64_t pn64_max);

picoquic_sack_item_t* picoquic_process_ack_of_ack_range(picoquic_sack_list_t* first_sack,
                                                        picoquic_sack_item_t* previous, uint64_t start_of_range,
                                                        uint64_t end_of_range);
void picoquic_update_ack_horizon(picoquic_sack_list_t* sack_list, uint64_t current_time);

/* Return the first ACK item in the list */
picoquic_sack_item_t* picoquic_sack_first_item(picoquic_sack_list_t* sack_list);
picoquic_sack_item_t* picoquic_sack_last_item(picoquic_sack_list_t* sack_list);
picoquic_sack_item_t* picoquic_sack_next_item(picoquic_sack_item_t* sack);
picoquic_sack_item_t* picoquic_sack_previous_item(picoquic_sack_item_t* sack);
int picoquic_sack_insert_item(picoquic_sack_list_t* sack_list, uint64_t range_min,
                              uint64_t range_max, uint64_t current_time);

int picoquic_sack_list_is_empty(picoquic_sack_list_t* sack_list);

picoquic_ack_context_t* picoquic_ack_ctx_from_cnx_context(quic_cnx_t* cnx, picoquic_packet_context_enum pc,
                                                          picoquic_local_cnxid_t* l_cid);

picoquic_sack_list_t* picoquic_sack_list_from_cnx_context(quic_cnx_t* cnx, picoquic_packet_context_enum pc,
                                                          picoquic_local_cnxid_t* l_cid);

uint64_t picoquic_sack_list_first(picoquic_sack_list_t* first_sack);

uint64_t picoquic_sack_list_last(picoquic_sack_list_t* first_sack);

picoquic_sack_item_t* picoquic_sack_list_first_range(picoquic_sack_list_t* first_sack);

void picoquic_sack_list_init(picoquic_sack_list_t* first_sack);

int picoquic_sack_list_reset(picoquic_sack_list_t* first_sack,
                             uint64_t range_min, uint64_t range_max, uint64_t current_time);

void picoquic_sack_list_free(picoquic_sack_list_t* first_sack);

uint64_t picoquic_sack_item_range_start(picoquic_sack_item_t* sack_item);

uint64_t picoquic_sack_item_range_end(picoquic_sack_item_t* sack_item);

int picoquic_sack_item_nb_times_sent(picoquic_sack_item_t* sack_item, int is_opportunistic);

void picoquic_sack_item_record_sent(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* sack_item,
                                    int is_opportunistic);
void picoquic_sack_item_record_reset(picoquic_sack_list_t* sack_list, picoquic_sack_item_t* sack_item);

size_t picoquic_sack_list_size(picoquic_sack_list_t* first_sack);

void picoquic_record_ack_packet_data(picoquic_packet_data_t* packet_data, quic_packet_t* acked_packet);

void picoquic_init_packet_ctx(quic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx, picoquic_packet_context_enum pc);

/*
 * Process ack of ack
 */
int picoquic_process_ack_of_ack_frame(
    picoquic_sack_list_t* first_sack, uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn);

/* Computation of ack delay max and ack gap, based on RTT and Data Rate.
 * If ACK Frequency extension is used, this function will compute the values
 * that will be sent to the peer. Otherwise, they computes the values used locally.
 */
void picoquic_compute_ack_gap_and_delay(quic_cnx_t* cnx, uint64_t rtt, uint64_t remote_min_ack_delay,
                                        uint64_t data_rate, uint64_t* ack_gap, uint64_t* ack_delay_max);

/* seed the rtt and bandwidth discovery */
void picoquic_seed_bandwidth(quic_cnx_t* cnx, uint64_t rtt_min, uint64_t cwin,
                             const uint8_t* ip_addr, uint8_t ip_addr_length);

/* Management of timers, rtt, etc. */
uint64_t picoquic_current_retransmit_timer(quic_cnx_t* cnx, picoquic_path_t* path_x);

/* Update the path RTT upon receiving an explict or implicit acknowledgement */
void picoquic_update_path_rtt(quic_cnx_t* cnx, picoquic_path_t* old_path, picoquic_path_t* path_x, int epoch,
                              uint64_t send_time, uint64_t current_time, uint64_t ack_delay, uint64_t time_stamp);

/* stream management */
static inline quic_stream_data_t* quic_get_stream_data(struct rte_mbuf* m)
{
    return m == NULL ? NULL : (quic_stream_data_t*)rte_mbuf_to_priv(m);
}

quic_stream_data_t* quic_stream_first_incoming_data(quic_stream_t* stream);
void quic_stream_enqueue_incoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data);
void quic_stream_dequeue_incoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data);
quic_stream_data_t* quic_stream_first_outcoming_data(quic_stream_t* stream);
void quic_stream_enqueue_outcoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data);
void quic_stream_dequeue_outcoming_data(quic_stream_t* stream, quic_stream_data_t* stream_data);

quic_stream_t* picoquic_create_stream(quic_cnx_t* cnx, uint64_t stream_id);
quic_stream_t* picoquic_create_missing_streams(quic_cnx_t* cnx, uint64_t stream_id, int is_remote);
int picoquic_is_stream_closed(quic_stream_t* stream, int client_mode);
int picoquic_delete_stream_if_closed(quic_cnx_t* cnx, quic_stream_t* stream);

void picoquic_update_stream_initial_remote(quic_cnx_t* cnx);

void picoquic_insert_output_stream(quic_cnx_t* cnx, quic_stream_t* stream);
void picoquic_remove_output_stream(quic_cnx_t* cnx, quic_stream_t* stream);
void picoquic_reorder_output_stream(quic_cnx_t* cnx, quic_stream_t* stream);
quic_stream_t* picoquic_first_stream(quic_cnx_t* cnx);
quic_stream_t* picoquic_last_stream(quic_cnx_t* cnx);
quic_stream_t* picoquic_next_stream(quic_stream_t* stream);
quic_stream_t* picoquic_find_stream(quic_cnx_t* cnx, uint64_t stream_id);
void picoquic_add_output_streams(quic_cnx_t* cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir);
quic_stream_t* picoquic_find_ready_stream_path(quic_cnx_t* cnx, picoquic_path_t* path_x);
quic_stream_t* quic_find_ready_stream(quic_cnx_t* cnx);
int picoquic_is_tls_stream_ready(quic_cnx_t* cnx);
const uint8_t* picoquic_decode_stream_frame(quic_cnx_t* cnx, quic_packet_t* packet,
                                            const uint8_t* bytes, const uint8_t* bytes_max,
                                            uint64_t current_time);
uint8_t* picoquic_format_stream_frame(quic_cnx_t* cnx, quic_stream_t* stream,
                                      uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);

void picoquic_update_max_stream_ID_local(quic_cnx_t* cnx, quic_stream_t* stream);

/* Handling of retransmission of frames.
 * When a packet is deemed lost, the code looks at the frames that it contained and
 * calls "picoquic_check_frame_needs_repeat" to see whether a given frame needs to
 * be retransmitted. This is different from checking whether a frame needs to be acked.
 * For example, a "MAX DATA" frame needs to be acked, but it will only be retransmitted
 * if it was not superceded by a similar frame carrying a larger max value.
 *
 * May have to split a retransmitted stream frame if it does not fit in the new packet size */
int picoquic_check_frame_needs_repeat(quic_cnx_t* cnx, const uint8_t* bytes,
                                      size_t bytes_max, picoquic_packet_type_enum p_type,
                                      int* no_need_to_repeat, int* do_not_detect_spurious, int* is_preemptive_needed);
uint8_t* picoquic_format_available_stream_frames(quic_cnx_t* cnx, picoquic_path_t* path_x,
                                                 uint8_t* bytes_next, uint8_t* bytes_max,
                                                 uint64_t current_priority, int* more_data,
                                                 int* is_pure_ack, int* stream_tried_and_failed, int* ret);

/* Handling of stream_data_frames that need repeating.
 */
// void picoquic_queue_data_repeat_init(picoquic_cnx_t* cnx);
// void picoquic_queue_data_repeat_packet(
//     picoquic_cnx_t* cnx, quic_packet_t* packet);
// void picoquic_dequeue_data_repeat_packet(
//     picoquic_cnx_t* cnx, quic_packet_t* packet);
// quic_packet_t* picoquic_first_data_repeat_packet(picoquic_cnx_t* cnx);
uint8_t* picoquic_copy_stream_frame_for_retransmit(
    quic_cnx_t* cnx, quic_packet_t* packet,
    uint8_t* bytes_next, uint8_t* bytes_max);
uint8_t* picoquic_copy_stream_frames_for_retransmit(quic_cnx_t* cnx,
                                                    uint8_t* bytes_next, uint8_t* bytes_max, uint64_t current_priority,
                                                    int* more_data, int* is_pure_ack);
/* Processing of packets considered lost: queueing frames
 * that need to be repeated as "misc" frames, setting the
 * flag `add_to_data_repeat_queue` if the packet contains stream
 * frames that need to be queued.
 */
int quic_copy_frames_before_retransmit(quic_packet_t* packet, quic_packet_t* old_p,
                                       quic_cnx_t* cnx,
                                       int* packet_is_pure_ack,
                                       int* do_not_detect_spurious);

int picoquic_retransmit_needed(quic_cnx_t* cnx, picoquic_packet_context_enum pc, picoquic_path_t* path_x,
                               quic_packet_t* packet, uint64_t current_time, uint64_t* next_wake_time);

void picoquic_set_ack_needed(quic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc,
                             picoquic_path_t* path_x, int is_immediate_ack_required);

/* If the packet contained an ACK frame, perform the ACK of ACK pruning logic.
 * Record stream data as acknowledged, signal datagram frames as acknowledged.
 */
void picoquic_process_ack_of_frames(quic_cnx_t* cnx, quic_packet_t* p,
                                    int is_spurious, uint64_t current_time);

/* Coding and decoding of frames */
typedef struct st_picoquic_stream_data_buffer_argument_t
{
    uint8_t* bytes; /* Points to the beginning of the encoding of the stream frame */
    size_t byte_index; /* Current index position after encoding type, stream-id and offset */
    size_t byte_space; /* Number of bytes available in the packet after the current index */
    size_t allowed_space; /* Maximum number of bytes that the application is authorized to write */
    size_t length; /* number of bytes that the application commits to write */
    int is_fin; /* Whether this is the end of the stream */
    int is_still_active; /* whether the stream is still considered active after this call */
    uint8_t* app_buffer; /* buffer provided to the application. */
} picoquic_stream_data_buffer_argument_t;

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes);

uint8_t* picoquic_format_stream_frame_header(uint8_t* bytes, uint8_t* bytes_max, uint64_t stream_id, uint64_t offset);

int picoquic_parse_stream_header(
    const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed);

int picoquic_parse_ack_header(
    uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* path_id, uint64_t* largest,
    uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent);
const uint8_t* picoquic_decode_crypto_hs_frame(quic_cnx_t* cnx,
                                               quic_packet_t* packet,
                                               const uint8_t* bytes, const uint8_t* bytes_max,
                                               int epoch);
uint8_t* picoquic_format_crypto_hs_frame(quic_stream_t* stream, uint8_t* bytes, uint8_t* bytes_max,
                                         int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_ack_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                   uint64_t current_time, picoquic_packet_context_enum pc, int is_opportunistic);
uint8_t* picoquic_format_connection_close_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                                int* is_pure_ack);
uint8_t* picoquic_format_application_close_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max,
                                                 int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_required_max_stream_data_frames(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max,
                                                         int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_max_data_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                        int* is_pure_ack, uint64_t maxdata_increase);
uint8_t* picoquic_format_max_stream_data_frame(quic_cnx_t* cnx, quic_stream_t* stream, uint8_t* bytes,
                                               uint8_t* bytes_max, int* more_data, int* is_pure_ack,
                                               uint64_t new_max_data);
uint8_t* picoquic_format_max_streams_frame_if_needed(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max,
                                                     int* more_data, int* is_pure_ack);

void quic_init_stream_tree(picosplay_tree_t* stream_tree);
void quic_init_stream_data_tree(picosplay_tree_t* stream_data_tree);
quic_stream_data_t* quic_create_stream_data_from_packet(quic_packet_t* packet, int offset, int data_len);
quic_stream_t* quic_find_or_create_remote_stream(quic_cnx_t* cnx, uint64_t stream_id);
void picoquic_stream_data_node_recycle(quic_stream_data_t* stream_data);
quic_stream_data_t* quic_stream_data_alloc();
void picoquic_clear_stream(quic_stream_t* stream);
void picoquic_delete_stream(quic_cnx_t* cnx, quic_stream_t* stream);
quic_stream_t* quic_create_remote_stream(quic_cnx_t* cnx, uint64_t stream_id);
picoquic_local_cnxid_list_t* picoquic_find_or_create_local_cnxid_list(quic_cnx_t* cnx, uint64_t unique_path_id,
                                                                      int do_create);
picoquic_local_cnxid_t* picoquic_create_local_cnxid(quic_cnx_t* cnx,
                                                    uint64_t unique_path_id, quic_connection_id_t* suggested_value,
                                                    uint64_t current_time);
int picoquic_demote_local_cnxid_list(quic_cnx_t* cnx, uint64_t unique_path_id,
                                     uint64_t reason, uint64_t current_time);
void picoquic_delete_local_cnxid(quic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid);
void picoquic_delete_local_cnxid_list(quic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list);
void picoquic_delete_local_cnxid_lists(quic_cnx_t* cnx);
void picoquic_retire_local_cnxid(quic_cnx_t* cnx, uint64_t unique_path_id, uint64_t sequence);
void picoquic_check_local_cnxid_ttl(quic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list,
                                    uint64_t current_time, uint64_t* next_wake_time);
picoquic_local_cnxid_t* picoquic_find_local_cnxid(quic_cnx_t* cnx, uint64_t unique_path_id,
                                                  quic_connection_id_t* cnxid);
uint8_t* picoquic_format_path_challenge_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
                                              uint64_t challenge);
uint8_t* picoquic_format_path_response_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
                                             uint64_t challenge);
int picoquic_should_repeat_path_response_frame(quic_cnx_t* cnx, const uint8_t* bytes, size_t bytes_max);
uint8_t* picoquic_format_new_connection_id_frame(quic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list,
                                                 uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
                                                 picoquic_local_cnxid_t* l_cid);
uint8_t* picoquic_format_blocked_frames(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                        int* is_pure_ack);
int picoquic_queue_retire_connection_id_frame(quic_cnx_t* cnx, uint64_t unique_path_id, uint64_t sequence);
int picoquic_queue_new_token_frame(quic_cnx_t* cnx, uint8_t* token, size_t token_length);
uint8_t* picoquic_format_one_blocked_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                           int* is_pure_ack, quic_stream_t* stream);
uint8_t* picoquic_format_first_misc_or_dg_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
                                                picoquic_misc_frame_header_t* misc_frame,
                                                picoquic_misc_frame_header_t** first,
                                                picoquic_misc_frame_header_t** last);
picoquic_misc_frame_header_t* picoquic_find_first_misc_frame(quic_cnx_t* cnx, picoquic_packet_context_enum pc);
uint8_t* picoquic_format_misc_frames_in_context(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max,
                                                int* more_data, int* is_pure_ack, picoquic_packet_context_enum pc);
int picoquic_queue_misc_or_dg_frame(quic_cnx_t* cnx, picoquic_misc_frame_header_t** first,
                                    picoquic_misc_frame_header_t** last, const uint8_t* bytes, size_t length,
                                    int is_pure_ack, picoquic_packet_context_enum pc);
void picoquic_purge_misc_frames_after_ready(quic_cnx_t* cnx);
void picoquic_delete_misc_or_dg(picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last,
                                picoquic_misc_frame_header_t* frame);
void picoquic_clear_ack_ctx(picoquic_ack_context_t* ack_ctx);
void picoquic_reset_ack_context(picoquic_ack_context_t* ack_ctx);
int quic_enqueue_handshake_done_frame(quic_cnx_t* cnx);
uint8_t* picoquic_format_first_datagram_frame(quic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data,
                                              int* is_pure_ack);

int picoquic_decode_frames(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_t* packet,
                           int epoch, fsockaddr_t* addr_from, fsockaddr_t* addr_to, uint64_t pn64,
                           int path_is_not_allocated, uint64_t current_time);

uint8_t* picoquic_format_observed_address_frame(
    uint8_t* bytes, const uint8_t* bytes_max, uint64_t ftype,
    uint64_t sequence_number, uint8_t* addr, uint16_t port, int* more_data);

void picoquic_update_peer_addr(picoquic_path_t* path_x, const fsockaddr_t* peer_addr);

int picoquic_skip_frame(const uint8_t* bytes, size_t bytes_max, size_t* consumed, int* pure_ack);
const uint8_t* picoquic_skip_path_abandon_frame(const uint8_t* bytes, const uint8_t* bytes_max);
const uint8_t* picoquic_skip_path_available_or_backup_frame(const uint8_t* bytes, const uint8_t* bytes_max);

/* Internal only API, notify that next path is now allowed. */
void picoquic_test_and_signal_new_path_allowed(quic_cnx_t* cnx);

int picoquic_decode_closing_frames(quic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, int* closing_received);

void picoquic_process_sooner_packets(quic_cnx_t* cnx, uint64_t current_time);
void picoquic_delete_sooner_packets(quic_cnx_t* cnx);

/* handling of transport extensions.
 */

const uint8_t* picoquic_process_tp_version_negotiation(const uint8_t* bytes, const uint8_t* bytes_max,
                                                       int extension_mode, uint32_t envelop_vn, uint32_t* negotiated_vn,
                                                       int* negotiated_index,
                                                       uint64_t* vn_error);

int picoquic_prepare_transport_extensions(quic_cnx_t* cnx, int extension_mode,
                                          uint8_t* bytes, size_t bytes_max, size_t* consumed);

int picoquic_receive_transport_extensions(quic_cnx_t* cnx, int extension_mode,
                                          uint8_t* bytes, size_t bytes_max, size_t* consumed);

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length, int is_pure_ack,
                                                         picoquic_packet_context_enum pc);

quic_stream_t* quic_create_local_stream(quic_cnx_t* cnx, bool is_unidir, int priority);

quic_stream_t* quic_find_or_create_local_stream(quic_cnx_t* cnx, uint64_t stream_id);

/* Supported version upgrade.
 * Upgrades are only supported between compatible versions.
 *
 * When upgrading, there may be a need to update more than the version field. For example,
 * there may be a need to update encryption contexts if they were computed differently,
 * or to revisit some default options.
 *
 * The function takes three arguments: connection context, old version index and new version index.
 * The return code is zero if the upgrade was done, -1 if it could not be.
 * If the function is called with a null connection context, it returns 0 if the
 * upgrade is possible, -1 if it is not.
 */
int picoquic_process_version_upgrade(quic_cnx_t* cnx, int old_version_index, int new_version_index);

int picoquic_prepare_packet(quic_cnx_t* cnx, u64 current_time, fsockaddr_t* local, fsockaddr_t* remote,
                            uint8_t* send_buffer, int* send_length);

void quic_handle_incoming_udp_mbuf(quic_context_t* quic, struct rte_mbuf* m, u64 receive_time, u64 current_time);

quic_cnx_t* quic_find_cnx(quic_context_t* quic, quic_packet_header* ph);

int picoquic_incoming_not_decrypted(quic_cnx_t* cnx, quic_packet_header* ph);

int picoquic_queue_retry_packet(quic_context_t* quic, quic_packet_header* ph);
#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
