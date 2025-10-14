#include "quic_conn.h"
#include "quic_packet.h"
#include "picoquic_internal.h"
#include "hash.h"
#include "tls_api.h"
#include "picoquic_unified_log.h"
#include "../../common/fnp_socket.h"
#include "fnp_error.h"


/* The initial CID and the reset secret are tracked in specific tables:
 *
 * - quic->table_cnx_by_icid: keyed by client address and initial CID. Created
 *   when the connection for the specified initial CID and address is created
 *   by the server (or the peer receiving the connection in P2P cases)
 * - quic->table_cnx_by_secret: keyed by peer address and reset secret for
 *   the default path of the connection (cnx->path[0]).
 *
 * In both cases, the address is that associated to the default path. The
 * path can be updated after migration, either by an address change or by
 * a change of CID and secret while keeping the address constant.
 *
 * If either the default address or the default reset secret changes, the
 * old table entry is updated to track the new address and secret. The
 * entry is kept up to date until the connection closes.
 *
 * Migration can only happen after a connection is established, but
 * packets could still arrive after that, maybe due to network delays.
 * In order to keep the design simple, the ICID entry is created once, and
 * kept for the duration of the connection.
 *
 * To facilitate management, the hash table keys are remembered in the
 * connection context as:
 *
 * - cnx->reset_secret_key
 * - cnx->net_icid_key
 */

int picoquic_register_net_icid(quic_cnx_t* cnx)
{
    int ret = 0;
    picohash_item* item;
    fsockaddr_copy(&cnx->registered_icid_addr, (fsockaddr_t*)&cnx->path[0]->first_tuple->peer_addr);
    item = picohash_retrieve(cnx->quic->table_cnx_by_icid, cnx);

    if (item != NULL)
    {
        ret = -1;
    }
    else
    {
        ret = picohash_insert(cnx->quic->table_cnx_by_icid, cnx);
    }
    return ret;
}

void picoquic_unregister_net_icid(quic_cnx_t* cnx)
{
    if (cnx->registered_icid_item.key != 0)
    {
        picohash_delete_item(cnx->quic->table_cnx_by_icid, &cnx->registered_icid_item, 0);
        memset(&cnx->registered_icid_addr, 0, sizeof(fsockaddr_t));
        memset(&cnx->registered_icid_item, 0, sizeof(picohash_item));
    }
}

void picoquic_unregister_net_secret(quic_cnx_t* cnx)
{
    if (cnx->registered_secret_addr.family != FSOCKADDR_NONE)
    {
        picohash_delete_key(cnx->quic->table_cnx_by_secret, cnx, 0);
        memset(&cnx->registered_secret_addr, 0, sizeof(fsockaddr_t));
        memset(&cnx->registered_reset_secret, 0, sizeof(PICOQUIC_RESET_SECRET_SIZE));
    }
}

int picoquic_register_net_secret(quic_cnx_t* cnx)
{
    int ret = 0;

    picohash_item* item;
    picoquic_unregister_net_secret(cnx);
    fsockaddr_copy(&cnx->registered_secret_addr, (fsockaddr_t*)&cnx->path[0]->first_tuple->peer_addr);
    memcpy(&cnx->registered_reset_secret, cnx->path[0]->first_tuple->p_remote_cnxid->reset_secret,
           PICOQUIC_RESET_SECRET_SIZE);

    item = picohash_retrieve(cnx->quic->table_cnx_by_secret, cnx);
    if (item != NULL)
    {
        ret = -1;
    }
    else
    {
        ret = picohash_insert(cnx->quic->table_cnx_by_secret, cnx);
    }
    return ret;
}

/* Connection management */

quic_cnx_t* picoquic_get_first_cnx(quic_context_t* quic)
{
    return quic->cnx_list;
}

quic_cnx_t* picoquic_get_next_cnx(quic_cnx_t* cnx)
{
    return cnx->next_in_table;
}

static void picoquic_remove_cnx_from_list(quic_cnx_t* cnx)
{
    if (cnx->next_in_table == NULL)
    {
        cnx->quic->cnx_last = cnx->previous_in_table;
    }
    else
    {
        cnx->next_in_table->previous_in_table = cnx->previous_in_table;
    }

    if (cnx->previous_in_table == NULL)
    {
        cnx->quic->cnx_list = cnx->next_in_table;
    }
    else
    {
        cnx->previous_in_table->next_in_table = cnx->next_in_table;
    }

    picoquic_unregister_net_icid(cnx);
    picoquic_unregister_net_secret(cnx);

    cnx->quic->current_number_connections--;
}

/* Management of the list of connections, sorted by wake time */

static void* picoquic_wake_list_node_value(picosplay_node_t* cnx_wake_node)
{
    return (cnx_wake_node == NULL)
               ? NULL
               : (void*)((char*)cnx_wake_node - offsetof(struct st_quic_cnx_t, cnx_wake_node));
}

static int64_t picoquic_wake_list_compare(void* l, void* r)
{
    const uint64_t ltime = ((quic_cnx_t*)l)->next_wake_time;
    const uint64_t rtime = ((quic_cnx_t*)r)->next_wake_time;
    if (ltime < rtime)
        return -1;
    if (ltime > rtime)
        return 1;
    return 0;
}

static picosplay_node_t* picoquic_wake_list_create_node(void* v_cnx)
{
    return &((quic_cnx_t*)v_cnx)->cnx_wake_node;
}

static void picoquic_wake_list_delete_node(void* tree, picosplay_node_t* node)
{
    memset(node, 0, sizeof(picosplay_node_t));
}

void picoquic_wake_list_init(quic_context_t* quic)
{
    picosplay_init_tree(&quic->cnx_wake_tree, picoquic_wake_list_compare,
                        picoquic_wake_list_create_node, picoquic_wake_list_delete_node, picoquic_wake_list_node_value);
}

static void picoquic_remove_cnx_from_wake_list(quic_cnx_t* cnx)
{
    picosplay_delete_hint(&cnx->quic->cnx_wake_tree, &cnx->cnx_wake_node);
}

static void picoquic_insert_cnx_by_wake_time(quic_context_t* quic, quic_cnx_t* cnx)
{
    picosplay_insert(&quic->cnx_wake_tree, cnx);
}

void picoquic_reinsert_by_wake_time(quic_context_t* quic, quic_cnx_t* cnx, uint64_t next_time)
{
    picoquic_remove_cnx_from_wake_list(cnx);
    cnx->next_wake_time = next_time;
    picoquic_insert_cnx_by_wake_time(quic, cnx);
}

quic_cnx_t* picoquic_get_earliest_cnx_to_wake(quic_context_t* quic, uint64_t max_wake_time)
{
    quic_cnx_t* cnx = (quic_cnx_t*)picoquic_wake_list_node_value(picosplay_first(&quic->cnx_wake_tree));
    if (cnx != NULL && max_wake_time != 0 && cnx->next_wake_time > max_wake_time)
    {
        cnx = NULL;
    }

    return cnx;
}

static void picoquic_insert_cnx_in_list(quic_context_t* quic, quic_cnx_t* cnx)
{
    if (quic->cnx_list != NULL)
    {
        quic->cnx_list->previous_in_table = cnx;
        cnx->next_in_table = quic->cnx_list;
    }
    else
    {
        quic->cnx_last = cnx;
        cnx->next_in_table = NULL;
    }
    quic->cnx_list = cnx;
    cnx->previous_in_table = NULL;
    quic->current_number_connections++;
}


int quic_init_cnx(quic_cnx_t* cnx, quic_context_t* quic,
                  quic_connection_id_t initial_cid, quic_connection_id_t remote_cid,
                  const fsockaddr_t* local, const fsockaddr_t* remote,
                  uint64_t start_time, uint32_t preferred_version, char client_mode)
{
    // 初始化fsocket
    fsocket_t* socket = &cnx->socket;
    socket->frontend_id = quic->socket.frontend_id;
    socket->worker_id = quic->socket.worker_id;
    socket->proto = fnp_protocol_quic;
    fsockaddr_copy(&socket->local, local);
    fsockaddr_copy(&socket->remote, remote);

    int ret;
    cnx->quic = quic;
    cnx->start_time = start_time;
    cnx->phase_delay = INT64_MAX;
    cnx->client_mode = client_mode;
    if (client_mode)
    {
        if (picoquic_is_connection_id_null(&initial_cid))
        {
            picoquic_create_random_cnx_id(quic, &initial_cid, quic->local_cnxid_length);
        }
    }
    cnx->initial_cnxid = initial_cid;
    FNP_INFO("start to create quic connection, initial_cnxid: ");
    for (uint8_t i = 0; i < initial_cid.id_len; i++)
    {
        printf("%02x", initial_cid.id[i]);
    }
    FNP_INFO("\n");

    cnx->pmtud_policy = quic->default_pmtud_policy;
    /* Create the connection ID number 0 */
    picoquic_local_cnxid_t* lcid0 = picoquic_create_local_cnxid(cnx, 0, NULL, start_time);

    /* Initialize path updates and quality updates before creating the first path */
    cnx->are_path_callbacks_enabled = quic->are_path_callbacks_enabled;
    cnx->rtt_update_delta = quic->rtt_update_delta;
    cnx->pacing_rate_update_delta = quic->pacing_rate_update_delta;

    /* Initialize the connection ID stash */
    ret = picoquic_create_path(cnx, start_time, local, remote, 0, 0);
    if (ret != 0 || lcid0 == NULL)
    {
        return -1;
    }

    /* Should return 0, since this is the first path */
    ret = picoquic_init_cnxid_stash(cnx);
    if (ret != 0)
    {
        return -1;
    }

    cnx->next_wake_time = start_time;
    SET_LAST_WAKE(quic, PICOQUIC_QUICCTX);
    picoquic_insert_cnx_in_list(quic, cnx);
    picoquic_insert_cnx_by_wake_time(quic, cnx);

    /* Do not require verification for default path */
    cnx->path[0]->first_tuple->p_local_cnxid = lcid0;
    cnx->path[0]->first_tuple->challenge_verified = 1;

    cnx->high_priority_stream_id = UINT64_MAX;
    for (int i = 0; i < 4; i++)
    {
        cnx->next_stream_id[i] = i;
    }
    picoquic_pacing_init(&cnx->priority_bypass_pacing, start_time);
    picoquic_register_path(cnx, cnx->path[0]);

    fnp_memcpy(&cnx->local_parameters, &quic->default_tp, sizeof(picoquic_tp_t));
    /* If the default parameters include preferred address, document it */
    if (cnx->local_parameters.prefered_address.is_defined)
    {
        /* Create an additional CID -- always for path 0, even if multipath */
        picoquic_local_cnxid_t* cnxid1 = picoquic_create_local_cnxid(cnx, 0, NULL, start_time);
        if (cnxid1 != NULL)
        {
            /* copy the connection ID into the local parameter */
            cnx->local_parameters.prefered_address.connection_id = cnxid1->cnx_id;
            /* Create the reset secret */
            (void)picoquic_create_cnxid_reset_secret(cnx->quic, &cnxid1->cnx_id,
                                                     cnx->local_parameters.prefered_address.statelessResetToken);
        }
    }

    /* Apply the defined MTU MAX if specified and not set in defaults. */
    if (cnx->local_parameters.max_packet_size == 0 && cnx->quic->mtu_max > 0)
    {
        cnx->local_parameters.max_packet_size = cnx->quic->mtu_max -
            PICOQUIC_MTU_OVERHEAD(remote);
    }

    /* If local connection ID size is null, don't allow migration */
    if (!cnx->client_mode && quic->local_cnxid_length == 0)
    {
        cnx->local_parameters.migration_disabled = 1;
    }

    /* Initialize local flow control variables to advertised values */
    cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
    cnx->max_stream_id_bidir_local = STREAM_ID_FROM_RANK(
        cnx->local_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
    cnx->max_stream_id_bidir_local_computed = STREAM_TYPE_FROM_ID(cnx->max_stream_id_bidir_local);
    cnx->max_stream_id_unidir_local = STREAM_ID_FROM_RANK(
        cnx->local_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
    cnx->max_stream_id_unidir_local_computed = STREAM_TYPE_FROM_ID(cnx->max_stream_id_unidir_local);

    /* Initialize padding policy to default for context */
    cnx->padding_multiple = quic->padding_multiple_default;
    cnx->padding_minsize = quic->padding_minsize_default;

    /* Initialize spin policy, ensure that at least 1/8th of connections do not spin */
    cnx->spin_policy = quic->default_spin_policy;
    if (cnx->spin_policy == picoquic_spinbit_basic)
    {
        uint8_t rand256 = (uint8_t)picoquic_public_random_64();
        if (rand256 < PICOQUIC_SPIN_RESERVE_MOD_256)
        {
            cnx->spin_policy = picoquic_spinbit_null;
        }
    }
    else if (cnx->spin_policy == picoquic_spinbit_on)
    {
        /* Option used in test to avoid randomizing spin bit on/off */
        cnx->spin_policy = picoquic_spinbit_basic;
    }

    cnx->sni = fnp_string_duplicate(quic->default_sni);
    cnx->alpn = fnp_string_duplicate(quic->default_alpn);

    cnx->is_preemptive_repeat_enabled = quic->is_preemptive_repeat_enabled;

    /* Initialize key rotation interval to default value */
    cnx->crypto_epoch_length_max = quic->crypto_epoch_length_max;

    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++)
    {
        quic_init_stream_data_tree(&cnx->tls_stream[epoch].tx_stream_data_tree);
    }

    /* Perform different initializations for clients and servers */
    if (cnx->client_mode)
    {
        if (preferred_version == 0)
        {
            cnx->proposed_version = picoquic_supported_versions[0].version;
            cnx->version_index = 0;
        }
        else
        {
            cnx->version_index = picoquic_get_version_index(preferred_version);
            if (cnx->version_index < 0)
            {
                cnx->version_index = PICOQUIC_INTEROP_VERSION_INDEX;
                if ((preferred_version & 0x0A0A0A0A) == 0x0A0A0A0A)
                {
                    /* This is a hack, to allow greasing the cnx ID */
                    cnx->proposed_version = preferred_version;
                }
                else
                {
                    cnx->proposed_version = picoquic_supported_versions[PICOQUIC_INTEROP_VERSION_INDEX].version;
                }
            }
            else
            {
                cnx->proposed_version = preferred_version;
            }
        }

        cnx->cnx_state = picoquic_state_client_init;

        if (!quic->is_cert_store_not_empty)
        {
            /* The open SSL certifier always fails if no certificate is stored, so we just use a NULL verifier */
            picoquic_log_app_message(cnx, "No root crt list specified -- certificate will not be verified.\n");

            picoquic_set_null_verifier(quic);
        }
    }
    else
    {
        cnx->is_half_open = 1;
        cnx->quic->current_number_half_open += 1;
        if (cnx->quic->current_number_half_open > cnx->quic->max_half_open_before_retry)
        {
            cnx->quic->check_token = 1;
        }
        cnx->cnx_state = picoquic_state_server_init;
        cnx->initial_cnxid = initial_cid;
        cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id = remote_cid;

        cnx->version_index = picoquic_get_version_index(preferred_version);
        if (cnx->version_index < 0)
        {
            /* TODO: this is an internal error condition, should not happen */
            cnx->version_index = 0;
            cnx->proposed_version = picoquic_supported_versions[0].version;
        }
        else
        {
            cnx->proposed_version = preferred_version;
        }
    }

    for (picoquic_packet_context_enum pc = 0;
         pc < picoquic_nb_packet_context; pc++)
    {
        picoquic_init_ack_ctx(cnx, &cnx->ack_ctx[pc]);
        picoquic_init_packet_ctx(cnx, &cnx->pkt_ctx[pc], pc);
    }
    /* Initialize the ACK behavior. By default, picoquic abides with the recommendation to send
     * ACK immediately if packets are received out of order (ack_ignore_order_remote = 0),
     * but this behavior creates too many ACKS on high speed links, so picoquic will request
     * the peer to not do that if the "delayed ACK" extension is available (ack_ignore_order_local = 1)
     */
    cnx->ack_ignore_order_local = 1;
    cnx->ack_ignore_order_remote = 0;

    cnx->latest_progress_time = start_time;
    cnx->latest_receive_time = start_time;

    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++)
    {
        cnx->tls_stream[epoch].stream_id = 0;
        cnx->tls_stream[epoch].consumed_offset = 0;
        cnx->tls_stream[epoch].fin_offset = 0;
        cnx->tls_stream[epoch].stream_node.left = NULL;
        cnx->tls_stream[epoch].stream_node.parent = NULL;
        cnx->tls_stream[epoch].stream_node.right = NULL;
        cnx->tls_stream[epoch].sent_offset = 0;
        cnx->tls_stream[epoch].socket.local_error = 0;
        cnx->tls_stream[epoch].socket.remote_error = 0;
        cnx->tls_stream[epoch].maxdata_local = UINT64_MAX;
        cnx->tls_stream[epoch].maxdata_remote = UINT64_MAX;

        // quic_init_stream_data_tree(&cnx->tls_stream[epoch].tx_stream_data_tree);
        quic_init_stream_data_tree(&cnx->tls_stream[epoch].rx_stream_data_tree);
        picoquic_sack_list_init(&cnx->tls_stream[epoch].sack_list);
        /* No need to reset the state flags, as they are not used for the crypto stream */
    }

    cnx->ack_frequency_sequence_local = UINT64_MAX;
    cnx->ack_gap_local = 2;
    cnx->ack_frequency_delay_local = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
    cnx->ack_frequency_sequence_remote = UINT64_MAX;
    cnx->ack_gap_remote = 2;
    cnx->ack_delay_remote = PICOQUIC_ACK_DELAY_MIN;
    cnx->max_ack_delay_remote = cnx->ack_delay_remote;
    cnx->max_ack_gap_remote = cnx->ack_gap_remote;
    cnx->max_ack_delay_local = cnx->ack_frequency_delay_local;
    cnx->max_ack_gap_local = cnx->ack_gap_local;
    cnx->min_ack_delay_remote = cnx->ack_delay_remote;
    cnx->min_ack_delay_local = cnx->ack_frequency_delay_local;

    quic_init_stream_tree(&cnx->stream_tree);
    // quic_init_stream_tree(&cnx->output_stream_tree);


    init_congestion_algorithm(&cnx->cc_algo, cnx->quic->default_congestion_alg, start_time);

    /* Only initialize TLS after all parameters have been set */
    if (picoquic_tlscontext_create(quic, cnx, start_time) != 0)
    {
        /* Cannot just do partial creation! */
        return -1;
    }

    if (picoquic_setup_initial_traffic_keys(cnx))
    {
        /* Cannot initialize aead for initial packets */
        return -1;
    }

    if (!client_mode && quic->local_cnxid_length > 0)
    {
        if (picoquic_register_net_icid(cnx) != 0)
        {
            DBG_PRINTF("%s", "Could not register the ICID in table.\n");
            return -1;
        }
    }

    if (quic->use_unique_log_names)
    {
        picoquic_crypto_random(quic, &cnx->log_unique, sizeof(cnx->log_unique));
    }

    if (!cnx->client_mode)
    {
        // 加入quic的cnx队列中
        picoquic_log_new_connection(cnx);
    }

    return FNP_OK;
}

// 创建服务端接收到的cnx
quic_cnx_t* picoquic_create_server_cnx(quic_context_t* quic,
                                       quic_connection_id_t initial_cid, quic_connection_id_t remote_cid,
                                       const fsockaddr_t* local, const fsockaddr_t* remote,
                                       uint64_t start_time, uint32_t preferred_version)
{
    quic_cnx_t* cnx = fnp_malloc(sizeof(quic_cnx_t));
    if (cnx == NULL)
        return NULL;

    int ret = quic_init_cnx(cnx, quic, initial_cid, remote_cid, local, remote,
                            start_time, preferred_version, 0);
    if (ret != 0)
    {
        picoquic_delete_cnx(cnx);
        return NULL;
    }

    return cnx;
}


int picoquic_start_client_cnx(quic_cnx_t* cnx)
{
    int ret = 0;

    if (cnx->cnx_state != picoquic_state_client_init ||
        cnx->tls_stream[0].sent_offset > 0 ||
        quic_stream_first_outcoming_data(&cnx->tls_stream[0]) != NULL)
    {
        DBG_PRINTF("%s", "picoquic_start_client_cnx called twice.");
        return -1;
    }

    picoquic_log_new_connection(cnx);

    ret = picoquic_initialize_tls_stream(cnx, picoquic_get_quic_time(cnx->quic));
    /* A remote session ticket may have been loaded as part of initializing TLS,
     * and remote parameters may have been initialized to the initial value
     * of the previous session. Apply these new parameters. */
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_id_bidir_remote =
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
    cnx->max_stream_id_unidir_remote =
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
    cnx->max_stream_data_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_data_local = cnx->local_parameters.initial_max_stream_data_bidi_local;

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

quic_cnx_t* quic_create_client_cnx(quic_context_t* quic, fsockaddr_t* remote)
{
    printf("start to create quic connection\n");
    quic_cnx_t* cnx = fnp_zmalloc(sizeof(quic_cnx_t));
    if (cnx == NULL)
        return NULL;


    fsockaddr_t* local = &quic->socket.local;
    uint64_t current_time = picoquic_current_time();
    int ret = quic_init_cnx(cnx, quic, picoquic_null_connection_id, picoquic_null_connection_id,
                            local, remote, current_time, 0, 1);
    if (ret != FNP_OK)
    {
        picoquic_delete_cnx(cnx);
        return NULL;
    }

    ret = picoquic_start_client_cnx(cnx);
    if (ret != FNP_OK)
    {
        /* Cannot just do partial initialization! */
        picoquic_delete_cnx(cnx);
        return NULL;
    }

    return cnx;
}


void picoquic_delete_remote_cnxid_stashes(quic_cnx_t* cnx)
{
    while (cnx->first_remote_cnxid_stash != NULL)
    {
        picoquic_delete_remote_cnxid_stash(cnx, cnx->first_remote_cnxid_stash);
    }
}

void picoquic_delete_cnx(quic_cnx_t* cnx)
{
    if (cnx == NULL)
    {
        return;
    }
    FNP_INFO("start to delete quic connection, initial_cnxid: ");
    for (uint8_t i = 0; i < cnx->initial_cnxid.id_len; i++)
    {
        printf("%02x", cnx->initial_cnxid.id[i]);
    }
    FNP_INFO("\n");
    if (cnx->memlog_call_back != NULL)
    {
        cnx->memlog_call_back(cnx, NULL, cnx->memlog_ctx, 1, 0);
    }
    if (cnx->quic->perflog_fn != NULL)
    {
        (void)(cnx->quic->perflog_fn)(cnx->quic, cnx, 0);
    }

    picoquic_log_close_connection(cnx);

    if (cnx->is_half_open && cnx->quic->current_number_half_open > 0)
    {
        cnx->quic->current_number_half_open--;
        cnx->is_half_open = 0;
    }

    if (cnx->cnx_state < picoquic_state_disconnected)
    {
        /* Give the application a chance to clean up its state */
        picoquic_connection_disconnect(cnx);
    }

    fnp_string_free(cnx->alpn);
    fnp_string_free(cnx->sni);

    if (cnx->retry_token != NULL)
    {
        free(cnx->retry_token);
        cnx->retry_token = NULL;
    }

    picoquic_delete_sooner_packets(cnx);

    picoquic_remove_cnx_from_list(cnx);
    picoquic_remove_cnx_from_wake_list(cnx);

    for (int i = 0; i < PICOQUIC_NUMBER_OF_EPOCHS; i++)
    {
        picoquic_crypto_context_free(&cnx->crypto_context[i]);
    }

    picoquic_crypto_context_free(&cnx->crypto_context_new);
    picoquic_crypto_context_free(&cnx->crypto_context_old);

    for (picoquic_packet_context_enum pc = 0;
         pc < picoquic_nb_packet_context; pc++)
    {
        picoquic_reset_packet_context(cnx, &cnx->pkt_ctx[pc]);
        picoquic_reset_ack_context(&cnx->ack_ctx[pc]);
    }

    while (cnx->first_misc_frame != NULL)
    {
        picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, cnx->first_misc_frame);
    }

    while (cnx->first_datagram != NULL)
    {
        picoquic_delete_misc_or_dg(&cnx->first_datagram, &cnx->last_datagram, cnx->first_datagram);
    }

    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++)
    {
        picoquic_clear_stream(&cnx->tls_stream[epoch]);
    }

    picosplay_empty_tree(&cnx->stream_tree);

    if (cnx->tls_ctx != NULL)
    {
        picoquic_tlscontext_free(cnx->tls_ctx);
        cnx->tls_ctx = NULL;
    }

    if (cnx->path != NULL)
    {
        while (cnx->nb_paths > 0)
        {
            picoquic_dereference_stashed_cnxid(cnx, cnx->path[cnx->nb_paths - 1], 1);
            picoquic_delete_path(cnx, cnx->nb_paths - 1);
        }

        fnp_free(cnx->path);
        cnx->path = NULL;
    }

    picoquic_delete_local_cnxid_lists(cnx);
    picoquic_delete_remote_cnxid_stashes(cnx);

    picoquic_unregister_net_icid(cnx);
    picoquic_unregister_net_secret(cnx);

    fnp_free(cnx);
}


uint64_t picoquic_get_next_wake_time(quic_context_t* quic, uint64_t current_time)
{
    uint64_t wake_time = UINT64_MAX;

    if (quic->pending_stateless_packet != NULL)
    {
        wake_time = current_time;
    }
    else
    {
        quic_cnx_t* cnx_wake_first = (quic_cnx_t*)picoquic_wake_list_node_value(
            picosplay_first(&quic->cnx_wake_tree));

        if (cnx_wake_first != NULL)
        {
            wake_time = cnx_wake_first->next_wake_time;
        }
    }

    return wake_time;
}
