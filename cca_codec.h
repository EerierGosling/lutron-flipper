#pragma once
/*
 * Lutron CCA (Clear Connect Type A) codec — pure C, no Flipper dependencies.
 *
 * Ported from firmware/src/cca/{cca_crc.h,cca_n81.h,cca_decoder.h,cca_tx_builder.h}
 * in the lutron-protocols repo so it can be unit-tested on a host machine.
 *
 * On-air framing (bit-level, MSB-first in the CC1101 FIFO):
 *   [32-bit 1010 preamble][N81 0xFF][N81 0xFA][N81 0xDE][N81 payload...][zeros]
 * N81 = start bit 0, 8 data bits LSB-first, stop bit 1 (10 bits per byte).
 * Payload = packet bytes followed by a CRC-16 (poly 0xCA0F, big-endian).
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CCA_MAX_PKT 64 /* longest decoded packet we keep */
#define CCA_RX_LEN 80 /* fixed-length RX capture, covers 24- and 53-byte packets */
#define CCA_STD_LEN 24 /* 22 data + 2 CRC */
#define CCA_PAIR_LEN 53 /* 51 data + 2 CRC */
#define CCA_ENC_MAX 96 /* encoded bytes for a 53-byte packet is 76 */

typedef struct {
    uint8_t raw[CCA_MAX_PKT];
    uint8_t len;
    bool crc_ok;
    uint8_t n81_errors;
    uint8_t type; /* raw[0] */
    uint8_t seq; /* raw[1] */
    uint8_t format; /* raw[7] */
    bool has_format;
} CcaPacket;

/* CRC-16, poly 0xCA0F, init 0, no reflection. */
uint16_t cca_crc16(const uint8_t* data, size_t len);

/* Writes the big-endian CRC of pkt[0..len) at pkt[len], pkt[len+1]. */
void cca_append_crc(uint8_t* pkt, size_t len);

/* Encodes payload (packet + CRC) to the on-air bitstream. Returns byte count, 0 on overflow. */
size_t cca_n81_encode(const uint8_t* payload, size_t len, uint8_t* out, size_t out_size);

/* Decodes a raw FIFO capture. Returns true if a packet (CRC-valid or best effort) was found. */
bool cca_decode(const uint8_t* fifo, size_t len, CcaPacket* pkt);

/* Level helpers: 0..100 percent <-> 16-bit Lutron level (0x0000..0xFEFF). */
uint16_t cca_pct_to_level16(uint8_t pct);
uint8_t cca_level16_to_pct(uint16_t level16);

/*
 * Bridge SET_LEVEL, format 0x0E, 22 bytes (CRC not included).
 * src: the 4 bytes a hub puts at packet offset 2..5 (copied verbatim).
 * tgt: the 4 bytes a hub puts at packet offset 9..12 (the light's load ID, verbatim).
 * fade_qs: fade time in quarter seconds. type_byte: 0x81, 0x82 or 0x83.
 * Byte 1 (sequence) is left zero for the caller to fill.
 */
size_t cca_build_set_level(
    uint8_t* pkt,
    const uint8_t src[4],
    const uint8_t tgt[4],
    uint16_t level16,
    uint8_t fade_qs,
    uint8_t type_byte);

/*
 * Vive hub level command, format 0x0E, 22 bytes (CRC not included).
 * hub: the 4 bytes the hub puts at offset 2..5 (verbatim). zone: 1-byte zone ID at offset 12,
 * followed by the constant 0xEF. type_byte: 0x89, 0x8A or 0x8B.
 * Ported from cca_build_vive_level in firmware/src/cca/cca_tx_builder.h.
 */
size_t cca_build_vive_level(
    uint8_t* pkt,
    const uint8_t hub[4],
    uint8_t zone,
    uint16_t level16,
    uint8_t fade_qs,
    uint8_t type_byte);

/*
 * Vive raise/lower. hold_start=true builds the format 0x09 hold-start packet (required first),
 * false builds the format 0x0B dim-step packet. Direction: raise=true -> 0x03, false -> 0x02.
 */
size_t cca_build_vive_dim(
    uint8_t* pkt,
    const uint8_t hub[4],
    uint8_t zone,
    bool raise,
    bool hold_start,
    uint8_t type_byte);

/* Pico button press/release packets, 22 bytes each. */
size_t cca_build_button_short(
    uint8_t* pkt,
    const uint8_t device_id[4],
    uint8_t button,
    uint8_t action,
    uint8_t type_byte);

/*
 * Pico long-format (release) packet, format 0x0E, 22 bytes. Bytes 17-21 carry the button's
 * command: 40 00 <0x1E+button> 00 00 (preset) for ON / FAVORITE / OFF, and the dim class
 * 42 02 01 00 16 (RAISE, 0x05) or 42 02 00 00 43 (LOWER, 0x06), per the CCA reference.
 */
size_t cca_build_button_long(
    uint8_t* pkt,
    const uint8_t device_id[4],
    uint8_t button,
    uint8_t type_byte);

/* True for a Vive hub command (types 0x88-0x8B with 0xEF at byte 13 and a non-Pico frame). */
bool cca_is_vive_cmd(const CcaPacket* p);

/* True for a Caseta/RA3 bridge command (types 0x81-0x83, format 0x0E, non-Pico frame). */
bool cca_is_bridge_cmd(const CcaPacket* p);

/* One-line human summary, at most ~22 characters so it fits the Flipper screen.
 * Packets whose CRC failed are always labelled "BAD". */
void cca_describe(const CcaPacket* p, char* out, size_t out_size);

#ifdef __cplusplus
}
#endif
