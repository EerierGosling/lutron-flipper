/* Host-side tests for cca_codec.c. Build: cc -I.. -o codec_test codec_test.c ../cca_codec.c */
#include "../cca_codec.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int failures = 0;
#define CHECK(cond, ...)                                  \
    do {                                                  \
        if(!(cond)) {                                     \
            failures++;                                   \
            printf("FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                          \
            printf("\n");                                 \
        }                                                 \
    } while(0)

static size_t parse_hex(const char* s, uint8_t* out, size_t cap) {
    size_t n = 0;
    while(*s && n < cap) {
        while(*s == ' ') s++;
        if(!*s) break;
        unsigned v;
        if(sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

/* Shift a bitstream right by k bits into dst (dst must have len+1 bytes). */
static void shift_bits(const uint8_t* src, size_t len, int k, uint8_t* dst) {
    memset(dst, 0, len + 1);
    for(size_t bit = 0; bit < len * 8; bit++) {
        int v = (src[bit / 8] >> (7 - bit % 8)) & 1;
        size_t d = bit + (size_t)k;
        if(v) dst[d / 8] |= (uint8_t)(1 << (7 - d % 8));
    }
}

/* Simulate what the CC1101 hands us: leftover preamble bits, then the encoded stream, padded to 80. */
static void make_fifo(const uint8_t* enc, size_t enc_len, int shift, uint8_t* fifo) {
    uint8_t tmp[CCA_ENC_MAX + 4];
    memset(fifo, 0, CCA_RX_LEN);
    fifo[0] = 0xAA; /* residual preamble after the 0xAAAA hardware sync */
    shift_bits(enc, enc_len, shift, tmp);
    size_t n = enc_len + 1;
    if(n > CCA_RX_LEN - 1) n = CCA_RX_LEN - 1;
    memcpy(fifo + 1, tmp, n);
}

int main(void) {
    /* 1. CRC known-answer tests (same vectors as test/cca-ota-codec.test.ts) */
    {
        uint8_t v[] = {0x01, 0x00, 0x00};
        CHECK(cca_crc16(v, 3) == 0xCA0F, "crc [01 00 00] = %04X", cca_crc16(v, 3));
        CHECK(cca_crc16(v, 0) == 0, "crc empty");
    }

    /* 2. Real captured packets from the repo docs: CRC must verify at 24 bytes */
    const char* vectors[] = {
        "91 01 a1 ef fd 00 21 0c 00 06 fe 80 20 fe 06 01 00 01 00 02 cc cc 7b f3",
        "92 01 a1 ef fd 00 21 0e 00 06 fe 80 20 fe 06 00 02 20 00 00 00 1f 9e 83",
    };
    for(int i = 0; i < 2; i++) {
        uint8_t b[32];
        size_t n = parse_hex(vectors[i], b, sizeof(b));
        CHECK(n == 24, "vector %d length %zu", i, n);
        uint16_t crc = cca_crc16(b, 22);
        uint16_t want = (uint16_t)((b[22] << 8) | b[23]);
        CHECK(crc == want, "vector %d crc %04X want %04X", i, crc, want);

        /* Encode -> decode round trip through the full RX path */
        uint8_t enc[CCA_ENC_MAX];
        size_t enc_len = cca_n81_encode(b, 24, enc, sizeof(enc));
        CHECK(enc_len == 40, "vector %d enc len %zu", i, enc_len);
        for(int shift = 0; shift < 8; shift++) {
            uint8_t fifo[CCA_RX_LEN];
            make_fifo(enc, enc_len, shift, fifo);
            CcaPacket p;
            bool ok = cca_decode(fifo, CCA_RX_LEN, &p);
            CHECK(ok, "vector %d shift %d: no decode", i, shift);
            if(ok) {
                CHECK(p.crc_ok, "vector %d shift %d: crc_ok false", i, shift);
                CHECK(p.len == 24, "vector %d shift %d: len %u", i, shift, p.len);
                CHECK(memcmp(p.raw, b, 24) == 0, "vector %d shift %d: bytes differ", i, shift);
                CHECK(p.type == b[0] && p.format == b[7], "vector %d: type/format", i);
            }
        }
    }

    /* 3. Builder -> CRC -> encode -> decode round trip, plus describe() */
    {
        uint8_t src[4] = {0xA1, 0xEF, 0xFD, 0x00};
        uint8_t tgt[4] = {0x06, 0xFE, 0x80, 0x20};
        uint8_t pkt[CCA_MAX_PKT];
        size_t n = cca_build_set_level(pkt, src, tgt, cca_pct_to_level16(75), 4, 0x81);
        CHECK(n == 22, "build len %zu", n);
        pkt[1] = 0x16; /* seq: slot 6, retransmit 2 */
        cca_append_crc(pkt, 22);
        CHECK(pkt[6] == 0x21 && pkt[7] == 0x0E && pkt[13] == 0xFE && pkt[14] == 0x40 && pkt[15] == 0x02,
              "fixed bytes");
        CHECK(memcmp(pkt + 2, src, 4) == 0 && memcmp(pkt + 9, tgt, 4) == 0, "ids placed");
        CHECK(pkt[19] == 4, "fade");

        uint8_t enc[CCA_ENC_MAX];
        size_t enc_len = cca_n81_encode(pkt, 24, enc, sizeof(enc));
        uint8_t fifo[CCA_RX_LEN];
        make_fifo(enc, enc_len, 3, fifo);
        CcaPacket p;
        CHECK(cca_decode(fifo, CCA_RX_LEN, &p) && p.crc_ok && memcmp(p.raw, pkt, 24) == 0, "set_level roundtrip");
        char desc[32];
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strcmp(desc, "SET 75% >06FE8020") == 0, "describe: '%s'", desc);
        CHECK(cca_level16_to_pct(cca_pct_to_level16(75)) == 75, "level roundtrip 75");
        CHECK(cca_pct_to_level16(100) == 0xFEFF && cca_level16_to_pct(0xFEFF) == 100, "level 100");
        CHECK(cca_pct_to_level16(0) == 0 && cca_level16_to_pct(0) == 0, "level 0");

        /* Preamble bits should be alternating 1010.. and FF FA DE follows */
        CHECK(enc[0] == 0xAA && enc[1] == 0xAA && enc[2] == 0xAA && enc[3] == 0xAA, "preamble");
    }

    /* 4. Tolerant decode: corrupt one stop bit, expect CRC-driven recovery */
    {
        uint8_t b[32];
        parse_hex(vectors[0], b, sizeof(b));
        uint8_t enc[CCA_ENC_MAX];
        size_t enc_len = cca_n81_encode(b, 24, enc, sizeof(enc));
        /* payload starts at bit 62 (32 preamble + 30 sync); byte k occupies bits 62+10k..; stop bit at +9 */
        size_t stop_bit = 62 + 10 * 5 + 9;
        enc[stop_bit / 8] &= (uint8_t)~(1 << (7 - stop_bit % 8));
        uint8_t fifo[CCA_RX_LEN];
        make_fifo(enc, enc_len, 0, fifo);
        CcaPacket p;
        bool ok = cca_decode(fifo, CCA_RX_LEN, &p);
        CHECK(ok && p.crc_ok && memcmp(p.raw, b, 24) == 0, "stop-bit error recovered (ok=%d crc=%d)", ok, ok ? p.crc_ok : 0);
        /* Also corrupt a data bit in a different byte: two errors, still recoverable via CRC */
        size_t data_bit = 62 + 10 * 12 + 3;
        enc[data_bit / 8] ^= (uint8_t)(1 << (7 - data_bit % 8));
        make_fifo(enc, enc_len, 0, fifo);
        ok = cca_decode(fifo, CCA_RX_LEN, &p);
        CHECK(ok, "two-error decode returns something");
        if(ok && p.crc_ok) CHECK(memcmp(p.raw, b, 24) == 0, "two-error recovered to original");
    }

    /* 5. 53-byte packet path (pairing/config length) and encoded size */
    {
        uint8_t b[53];
        for(int i = 0; i < 51; i++) b[i] = (uint8_t)(0xA1 + i * 7);
        b[0] = 0xA1;
        cca_append_crc(b, 51);
        uint8_t enc[CCA_ENC_MAX];
        size_t enc_len = cca_n81_encode(b, 53, enc, sizeof(enc));
        CHECK(enc_len == 76, "53-byte enc len %zu", enc_len);
        uint8_t fifo[CCA_RX_LEN];
        make_fifo(enc, enc_len, 5, fifo);
        CcaPacket p;
        bool ok = cca_decode(fifo, CCA_RX_LEN, &p);
        CHECK(ok && p.crc_ok && p.len == 53 && memcmp(p.raw, b, 53) == 0, "53-byte roundtrip (ok=%d)", ok);
    }

    /* 6. Garbage must not decode as a CRC-valid packet */
    {
        uint8_t fifo[CCA_RX_LEN];
        srand(1);
        int false_ok = 0;
        for(int t = 0; t < 200; t++) {
            for(int i = 0; i < CCA_RX_LEN; i++) fifo[i] = (uint8_t)rand();
            CcaPacket p;
            if(cca_decode(fifo, CCA_RX_LEN, &p) && p.crc_ok) false_ok++;
        }
        CHECK(false_ok == 0, "random noise produced %d crc-valid packets", false_ok);
    }

    /* 7. Vive builders: level, hold-start, dim-step, detection and describe */
    {
        uint8_t hub[4] = {0x12, 0x34, 0x56, 0x78};
        uint8_t pkt[CCA_MAX_PKT];
        size_t n = cca_build_vive_level(pkt, hub, 0x38, cca_pct_to_level16(75), 4, 0x89);
        CHECK(n == 22, "vive build len %zu", n);
        CHECK(memcmp(pkt + 2, hub, 4) == 0 && pkt[7] == 0x0E && pkt[12] == 0x38 && pkt[13] == 0xEF &&
                  pkt[14] == 0x40 && pkt[15] == 0x02 && pkt[19] == 4,
              "vive level layout");
        pkt[1] = 0x08;
        cca_append_crc(pkt, 22);
        uint8_t enc[CCA_ENC_MAX];
        size_t enc_len = cca_n81_encode(pkt, 24, enc, sizeof(enc));
        uint8_t fifo[CCA_RX_LEN];
        make_fifo(enc, enc_len, 2, fifo);
        CcaPacket p;
        CHECK(cca_decode(fifo, CCA_RX_LEN, &p) && p.crc_ok && memcmp(p.raw, pkt, 24) == 0, "vive roundtrip");
        CHECK(cca_is_vive_cmd(&p) && !cca_is_bridge_cmd(&p), "vive detection");
        char desc[32];
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strcmp(desc, "VIVE 75% z38") == 0, "vive describe: '%s'", desc);

        n = cca_build_vive_dim(pkt, hub, 0x38, true, true, 0x8A);
        CHECK(n == 22 && pkt[7] == 0x09 && pkt[14] == 0x42 && pkt[15] == 0x00 && pkt[16] == 0x03 && pkt[13] == 0xEF,
              "vive hold-start layout");
        cca_append_crc(pkt, 22);
        enc_len = cca_n81_encode(pkt, 24, enc, sizeof(enc));
        make_fifo(enc, enc_len, 0, fifo);
        CHECK(cca_decode(fifo, CCA_RX_LEN, &p) && p.crc_ok && cca_is_vive_cmd(&p), "vive hold decode");
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strcmp(desc, "VIVE hold up z38") == 0, "vive hold describe: '%s'", desc);

        n = cca_build_vive_dim(pkt, hub, 0x05, false, false, 0x8B);
        CHECK(pkt[7] == 0x0B && pkt[15] == 0x02 && pkt[16] == 0x02, "vive dim-step layout");

        /* A Pico long-format packet (byte 8 = 0x03) must not be mistaken for a Vive command */
        uint8_t pico[24] = {0x89, 0x01, 0x06, 0xFD, 0xEF, 0xF4, 0x21, 0x0E, 0x03, 0x00, 0x02, 0x01,
                            0x06, 0xFD, 0xEF, 0xF4, 0x00, 0x40, 0x00, 0x20, 0x00, 0x00, 0, 0};
        cca_append_crc(pico, 22);
        enc_len = cca_n81_encode(pico, 24, enc, sizeof(enc));
        make_fifo(enc, enc_len, 1, fifo);
        CHECK(cca_decode(fifo, CCA_RX_LEN, &p) && p.crc_ok && !cca_is_vive_cmd(&p), "pico not vive");
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strcmp(desc, "BTN ON rel 06FDEFF4") == 0, "pico describe: '%s'", desc);

        uint8_t pico_off[CCA_MAX_PKT];
        n = cca_build_button_short(pico_off, hub, 0x04, 0x00, 0x88);
        CHECK(n == 22 && pico_off[10] == 0x04 && pico_off[11] == 0x00, "pico off press layout");
        n = cca_build_button_long(pico_off, hub, 0x04, 0x89);
        CHECK(n == 22 && pico_off[10] == 0x04 && pico_off[11] == 0x01 && pico_off[19] == 0x22,
              "pico off release layout");

        /* Bridge command detection still works */
        uint8_t src[4] = {0xA1, 0xEF, 0xFD, 0x00}, tgt[4] = {0x06, 0xFE, 0x80, 0x20};
        cca_build_set_level(pkt, src, tgt, 0x8000, 1, 0x82);
        cca_append_crc(pkt, 22);
        enc_len = cca_n81_encode(pkt, 24, enc, sizeof(enc));
        make_fifo(enc, enc_len, 4, fifo);
        CHECK(cca_decode(fifo, CCA_RX_LEN, &p) && cca_is_bridge_cmd(&p) && !cca_is_vive_cmd(&p), "bridge detection");
    }

    /* 8. Failed-CRC packets are labelled BAD, never as a protocol type */
    {
        CcaPacket p;
        memset(&p, 0, sizeof(p));
        p.raw[0] = 0xCC;
        p.len = 24;
        p.type = 0xCC;
        p.has_format = true;
        p.format = 0x0E;
        p.crc_ok = false;
        char desc[32];
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strcmp(desc, "BAD tCC len24") == 0, "bad describe: '%s'", desc);
        p.crc_ok = true;
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strncmp(desc, "TCC", 3) == 0, "0xCC with good crc is not a handshake: '%s'", desc);
        p.type = 0xC7;
        cca_describe(&p, desc, sizeof(desc));
        CHECK(strncmp(desc, "HS C7", 5) == 0, "C7 is a handshake: '%s'", desc);
    }

    if(failures == 0) printf("ALL CODEC TESTS PASSED\n");
    else printf("%d FAILURE(S)\n", failures);
    return failures ? 1 : 0;
}
