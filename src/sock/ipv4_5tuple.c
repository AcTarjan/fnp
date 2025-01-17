#include "ipv4_5tuple.h"

#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_vect.h>

#define L3FWD_HASH_ENTRIES	1024

#define ALL_32_BITS 0xffffffff
#define BIT_8_TO_15 0x0000ff00
static rte_xmm_t mask0 = {
    .u32 = {BIT_8_TO_15, ALL_32_BITS, ALL_32_BITS, ALL_32_BITS}
};

#if defined(__SSE2__)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
    __m128i data = _mm_loadu_si128((__m128i *)(key));

    return _mm_and_si128(data, mask);
}
#elif defined(__ARM_NEON)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
    int32x4_t data = vld1q_s32((int32_t *)key);

    return vandq_s32(data, mask);
}
#elif defined(__ALTIVEC__)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
    xmm_t data = vec_ld(0, (xmm_t *)(key));

    return vec_and(data, mask);
}
#elif defined(RTE_ARCH_RISCV)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
    xmm_t data = vect_load_128(key);

    return vect_and(data, mask);
}
#elif defined(RTE_ARCH_LOONGARCH)
static inline xmm_t
em_mask_key(void *key, xmm_t mask)
{
    xmm_t data = vect_load_128(key);

    return vect_and(data, mask);
}
#else
#error No vector engine (SSE, NEON, ALTIVEC) available, check your toolchain
#endif


union ipv4_5tuple_host {
    struct {
        uint8_t  pad0;
        uint8_t  proto;
        uint16_t pad1;
        uint32_t remote_ip;
        uint32_t local_ip;
        uint16_t remote_port;
        uint16_t local_port;
    };
    xmm_t xmm;
};

#define XMM_NUM_IN_IPV6_5TUPLE 3
union ipv6_5tuple_host {
    struct {
        uint16_t pad0;
        uint8_t  proto;
        uint8_t  pad1;
        uint8_t  ip_src[IPV6_ADDR_LEN];
        uint8_t  ip_dst[IPV6_ADDR_LEN];
        uint16_t port_src;
        uint16_t port_dst;
        uint64_t reserve;
    };
    xmm_t xmm[XMM_NUM_IN_IPV6_5TUPLE];
};

static inline uint32_t ipv4_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv4_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->remote_port;

#ifdef EM_HASH_CRC
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(k->ip_src, init_val);
	init_val = rte_hash_crc_4byte(k->ip_dst, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash_1word(k->remote_ip, init_val);
	init_val = rte_jhash_1word(k->local_ip, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif

	return init_val;
}

static inline uint32_t ipv6_hash_crc(const void *data, __rte_unused uint32_t data_len,
		uint32_t init_val)
{
	const union ipv6_5tuple_host *k;
	uint32_t t;
	const uint32_t *p;
#ifdef EM_HASH_CRC
	const uint32_t  *ip_src0, *ip_src1, *ip_src2, *ip_src3;
	const uint32_t  *ip_dst0, *ip_dst1, *ip_dst2, *ip_dst3;
#endif

	k = data;
	t = k->proto;
	p = (const uint32_t *)&k->port_src;

#ifdef EM_HASH_CRC
	ip_src0 = (const uint32_t *) k->ip_src;
	ip_src1 = (const uint32_t *)(k->ip_src+4);
	ip_src2 = (const uint32_t *)(k->ip_src+8);
	ip_src3 = (const uint32_t *)(k->ip_src+12);
	ip_dst0 = (const uint32_t *) k->ip_dst;
	ip_dst1 = (const uint32_t *)(k->ip_dst+4);
	ip_dst2 = (const uint32_t *)(k->ip_dst+8);
	ip_dst3 = (const uint32_t *)(k->ip_dst+12);
	init_val = rte_hash_crc_4byte(t, init_val);
	init_val = rte_hash_crc_4byte(*ip_src0, init_val);
	init_val = rte_hash_crc_4byte(*ip_src1, init_val);
	init_val = rte_hash_crc_4byte(*ip_src2, init_val);
	init_val = rte_hash_crc_4byte(*ip_src3, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst0, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst1, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst2, init_val);
	init_val = rte_hash_crc_4byte(*ip_dst3, init_val);
	init_val = rte_hash_crc_4byte(*p, init_val);
#else
	init_val = rte_jhash_1word(t, init_val);
	init_val = rte_jhash(k->ip_src,
			sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash(k->ip_dst,
			sizeof(uint8_t) * IPV6_ADDR_LEN, init_val);
	init_val = rte_jhash_1word(*p, init_val);
#endif
	return init_val;
}

static void convert_ipv4_5tuple(struct ipv4_5tuple *key1,
        union ipv4_5tuple_host *key2)
{
    key2->local_ip = key1->local_ip;
    key2->remote_ip = key1->remote_ip;
    key2->local_port = key1->local_port;
    key2->remote_port = key1->remote_port;
    key2->proto = key1->proto;
    key2->pad0 = 0;
    key2->pad1 = 0;
}

static void convert_ipv6_5tuple(struct ipv6_5tuple *key1,
        union ipv6_5tuple_host *key2)
{
    uint32_t i;

    for (i = 0; i < 16; i++) {
        key2->ip_dst[i] = key1->ip_dst[i];
        key2->ip_src[i] = key1->ip_src[i];
    }
    key2->port_dst = rte_cpu_to_be_16(key1->port_dst);
    key2->port_src = rte_cpu_to_be_16(key1->port_src);
    key2->proto = key1->proto;
    key2->pad0 = 0;
    key2->pad1 = 0;
    key2->reserve = 0;
}

struct rte_hash* create_ipv4_5tuple_hash(const int socket_id)
{
	char name[64];
	snprintf(name, sizeof(name), "ipv4_hash_%d", socket_id);
	struct rte_hash_parameters params = {
		.name = name,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(union ipv4_5tuple_host),
		.hash_func = ipv4_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = socket_id,
	};

	/* create ipv4 hash */
	return rte_hash_create(&params);
}

int ipv4_5tuple_add(struct rte_hash* hash, ipv4_5tuple_t *key, void* value)
{
	union ipv4_5tuple_host key2;

	convert_ipv4_5tuple(key, &key2);
	return rte_hash_add_key_data(hash, (const void *)&key2, value);
}

int ipv4_5tuple_remove(struct rte_hash* hash, ipv4_5tuple_t *key)
{
	union ipv4_5tuple_host key2;

	convert_ipv4_5tuple(key, &key2);
	return rte_hash_del_key(hash, (const void *)&key2);
}

bool ipv4_5tuple_lookup(struct rte_hash* hash, ipv4_5tuple_t *key)
{
	union ipv4_5tuple_host key2;
	convert_ipv4_5tuple(key, &key2);

	return rte_hash_lookup(hash, (const void *)&key2) >= 0;
}

int ipv4_5tuple_get_value(struct rte_hash* hash, void *ipv4_hdr, void** value)
{
	union ipv4_5tuple_host key;

	ipv4_hdr = (uint8_t *)ipv4_hdr + offsetof(struct rte_ipv4_hdr, time_to_live);

	/*
	 * Get 5 tuple: dst port, src port, dst IP address,
	 * src IP address and protocol.
	 */
	key.xmm = em_mask_key(ipv4_hdr, mask0.x);

	//先根据5元组查询连接是否存在
	if (rte_hash_lookup_data(hash, (const void *)&key, value) < 0)
	{
		key.remote_ip = 0;
		key.remote_port = 0;
		//查询是否有监听的端口
		return rte_hash_lookup_data(hash, (const void *)&key, value);
	}


	/* Find destination port */
	return 0;
}

struct rte_hash* setup_ipv6_hash(const int socketid)
{
	struct rte_hash_parameters ipv6_l3fwd_hash_params = {
		.name = NULL,
		.entries = L3FWD_HASH_ENTRIES,
		.key_len = sizeof(union ipv6_5tuple_host),
		.hash_func = ipv6_hash_crc,
		.hash_func_init_val = 0,
	};
	/* create ipv6 hash */
	// snprintf(s, sizeof(s), "ipv6_l3fwd_hash_%d", socketid);
	// ipv6_l3fwd_hash_params.name = s;
	// ipv6_l3fwd_hash_params.socket_id = socketid;
	// ipv6_l3fwd_em_lookup_struct[socketid] =
	// 	rte_hash_create(&ipv6_l3fwd_hash_params);
	// if (ipv6_l3fwd_em_lookup_struct[socketid] == NULL)
	// 	rte_exit(EXIT_FAILURE,
	// 		"Unable to create the l3fwd hash on socket %d\n",
	// 		socketid);
	//
	// /*
	//  * Use data from ipv4/ipv6 l3fwd config file
	//  * directly to initialize the hash table.
	//  */
	// if (ipv6 == 0) {
	// 	/* populate the ipv4 hash */
	// 	populate_ipv4_flow_into_table(
	// 		ipv4_l3fwd_em_lookup_struct[socketid]);
	// } else {
	// 	/* populate the ipv6 hash */
	// 	populate_ipv6_flow_into_table(
	// 		ipv6_l3fwd_em_lookup_struct[socketid]);
	// }
	return NULL;
}
