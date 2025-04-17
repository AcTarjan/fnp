#include "picoquic_internal.h"
#include "tls_api.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif

/*
 * Two procedures defining the spin bit basic variant 
 */
void picoquic_spinbit_basic_incoming(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_header* ph)
{
    path_x->current_spin = ph->spin ^ cnx->client_mode;
}

uint8_t picoquic_spinbit_basic_outgoing(quic_cnx_t* cnx)
{
    uint8_t spin_bit = (uint8_t)((cnx->path[0]->current_spin) << 5);

    return spin_bit;
}

/*
 * Two procedures defining the null spin bit variant
 */

void picoquic_spinbit_null_incoming(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_header* ph)
{
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(path_x);
    UNREFERENCED_PARAMETER(ph);
}

uint8_t picoquic_spinbit_null_outgoing(quic_cnx_t* cnx)
{
    UNREFERENCED_PARAMETER(cnx);
    return 0;
}

/*
 * Two procedures defining the null spin bit randomized variant
 */

void picoquic_spinbit_random_incoming(quic_cnx_t* cnx, picoquic_path_t* path_x, quic_packet_header* ph)
{
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(path_x);
    UNREFERENCED_PARAMETER(ph);
}

uint8_t picoquic_spinbit_random_outgoing(quic_cnx_t* cnx)
{
    UNREFERENCED_PARAMETER(cnx);
    return (uint8_t)(picoquic_public_random_64() & 0x20);
}

/*
 * Table of spin bit functions
 */
picoquic_spinbit_def_t picoquic_spin_function_table[] = {
    {picoquic_spinbit_basic_incoming, picoquic_spinbit_basic_outgoing},
    {picoquic_spinbit_random_incoming, picoquic_spinbit_random_outgoing},
    {picoquic_spinbit_null_incoming, picoquic_spinbit_null_outgoing}
};
