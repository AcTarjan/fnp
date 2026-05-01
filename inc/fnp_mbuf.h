#ifndef FNP_MBUF_H
#define FNP_MBUF_H

#include <rte_mbuf.h>
#include "fnp_sockaddr.h"

typedef struct rte_mbuf fnp_mbuf_t;

#define FNP_GTPU_MAX_EXT_BYTES 96u
#define FNP_MBUF_GTPU_F_MSG_TYPE 0x0001u
#define FNP_MBUF_GTPU_F_SEQ 0x0002u
#define FNP_MBUF_GTPU_F_NPDU 0x0004u
#define FNP_MBUF_GTPU_F_EXT 0x0008u
#define FNP_MBUF_GTPU_F_QFI 0x0010u
#define FNP_MBUF_GTPU_F_RQI 0x0020u
#define FNP_MBUF_GTPU_F_NR_PDCP_SN 0x0040u

typedef struct
{
    fsockaddr_t local;
    fsockaddr_t remote;
    u16 gtpu_flags;
    u8 gtpu_msg_type;
    u8 gtpu_next_ext_type;
    u16 gtpu_seq_num;
    u8 gtpu_npdu_num;
    u8 gtpu_qfi;
    u8 gtpu_rqi;
    u8 gtpu_ext_len;
    u32 gtpu_nr_pdcp_pdu_sn;
    u8 gtpu_ext_data[FNP_GTPU_MAX_EXT_BYTES];
} fnp_mbuf_info_t;

#ifdef __cplusplus
static_assert(sizeof(fnp_mbuf_info_t) <= FNP_MBUFPOOL_PRIV_SIZE, "fnp_mbuf_info_t exceeds mbuf private area");
#else
_Static_assert(sizeof(fnp_mbuf_info_t) <= FNP_MBUFPOOL_PRIV_SIZE, "fnp_mbuf_info_t exceeds mbuf private area");
#endif

static inline fnp_mbuf_info_t *fnp_get_mbuf_info(fnp_mbuf_t *m)
{
    return (fnp_mbuf_info_t *)rte_mbuf_to_priv(m);
}

fnp_mbuf_t *fnp_alloc_mbuf();

void fnp_free_mbuf(fnp_mbuf_t *m);

void fnp_free_mbuf_bulk(fnp_mbuf_t **m, u32 count);

static inline i32 fnp_get_mbuf_len(fnp_mbuf_t *m)
{
    return rte_pktmbuf_data_len(m);
}

static inline u8 *fnp_mbuf_data(fnp_mbuf_t *m)
{
    return rte_pktmbuf_mtod(m, u8 *);
}

static inline void fnp_mbuf_append_data(fnp_mbuf_t *m, i32 len)
{
    rte_pktmbuf_append(m, len);
}

#endif // FNP_MBUF_H
