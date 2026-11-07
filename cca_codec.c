#include "cca_codec.h"
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ CRC */

static uint16_t crc_table[256];
static bool crc_table_ready = false;

static void crc_init(void) {
    if(crc_table_ready) return;
    for(int i = 0; i < 256; i++) {
        uint16_t crc = (uint16_t)(i << 8);
        for(int j = 0; j < 8; j++) {
            if(crc & 0x8000) {
                crc = (uint16_t)(((crc << 1) ^ 0xCA0F) & 0xFFFF);
            } else {
                crc = (uint16_t)((crc << 1) & 0xFFFF);
            }
        }
        crc_table[i] = crc;
    }
    crc_table_ready = true;
}

static uint16_t crc_from(const uint8_t* data, size_t len, uint16_t init) {
    crc_init();
    uint16_t crc = init;
    for(size_t i = 0; i < len; i++) {
        uint8_t upper = (uint8_t)(crc >> 8);
        crc = (uint16_t)((((crc << 8) & 0xFF00) + data[i]) ^ crc_table[upper]);
    }
    return crc;
}

uint16_t cca_crc16(const uint8_t* data, size_t len) {
    return crc_from(data, len, 0);
}

void cca_append_crc(uint8_t* pkt, size_t len) {
    uint16_t crc = cca_crc16(pkt, len);
    pkt[len] = (uint8_t)(crc >> 8);
    pkt[len + 1] = (uint8_t)(crc & 0xFF);
}

static const size_t CCA_LENGTHS[] = {CCA_STD_LEN, CCA_PAIR_LEN};
#define N_CCA_LENGTHS 2

/* Returns the matching packet length, or -1. */
static int crc_check_lengths(const uint8_t* bytes, size_t bytes_len) {
    for(size_t i = 0; i < N_CCA_LENGTHS; i++) {
        size_t len = CCA_LENGTHS[i];
        if(bytes_len < len) continue;
        size_t off = len - 2;
        uint16_t computed = cca_crc16(bytes, off);
        uint16_t received = (uint16_t)((bytes[off] << 8) | bytes[off + 1]);
        if(computed == received) return (int)len;
    }
    return -1;
}

/*
 * Brute-force up to two N81-corrupted bytes against the CRC. Mirrors cca_recover_n81_errors,
 * but only errors that fall inside the candidate packet length count: the bits after a
 * packet (trailing zeros, then noise) almost always produce framing errors too, and those
 * must not block recovery of the packet in front of them.
 */
#define ERR_POS_MAX 6

static int
    recover_n81_errors(uint8_t* bytes, size_t bytes_len, const uint8_t* err_pos, uint8_t n_errors) {
    if(n_errors == 0) return -1;
    uint8_t recorded = n_errors < ERR_POS_MAX ? n_errors : ERR_POS_MAX;

    for(size_t ci = 0; ci < N_CCA_LENGTHS; ci++) {
        size_t pkt_len = CCA_LENGTHS[ci];
        if(bytes_len < pkt_len) continue;
        size_t crc_off = pkt_len - 2;

        /* Unrecorded errors have later positions than the recorded ones; if the last
         * recorded one is still inside this packet we cannot know how many more are. */
        if(n_errors > ERR_POS_MAX && err_pos[ERR_POS_MAX - 1] < pkt_len) continue;

        uint8_t d_pos[2] = {0, 0}, c_pos[2] = {0, 0};
        uint8_t nd = 0, nc = 0;
        bool too_many = false;
        for(uint8_t e = 0; e < recorded; e++) {
            uint8_t pos = err_pos[e];
            if(pos >= pkt_len) continue;
            if(pos < crc_off) {
                if(nd < 2)
                    d_pos[nd++] = pos;
                else
                    too_many = true;
            } else {
                if(nc < 2)
                    c_pos[nc++] = pos;
                else
                    too_many = true;
            }
        }
        if(too_many) continue;

        if(nd + nc == 0) {
            if(crc_check_lengths(bytes, pkt_len) == (int)pkt_len) return (int)pkt_len;
            continue;
        }

        if(nd == 0) {
            uint16_t crc = cca_crc16(bytes, crc_off);
            bytes[crc_off] = (uint8_t)(crc >> 8);
            bytes[crc_off + 1] = (uint8_t)(crc & 0xFF);
            return (int)pkt_len;
        }

        if(nd == 1 && nc == 0) {
            uint16_t received = (uint16_t)((bytes[crc_off] << 8) | bytes[crc_off + 1]);
            uint8_t saved = bytes[d_pos[0]];
            for(int v = 0; v < 256; v++) {
                bytes[d_pos[0]] = (uint8_t)v;
                if(cca_crc16(bytes, crc_off) == received) return (int)pkt_len;
            }
            bytes[d_pos[0]] = saved;
        }

        if(nd == 1 && nc == 1) {
            bool hi_bad = (c_pos[0] == crc_off);
            uint8_t good = hi_bad ? bytes[crc_off + 1] : bytes[crc_off];
            uint8_t saved = bytes[d_pos[0]];
            for(int v = 0; v < 256; v++) {
                bytes[d_pos[0]] = (uint8_t)v;
                uint16_t computed = cca_crc16(bytes, crc_off);
                uint8_t check = hi_bad ? (uint8_t)(computed & 0xFF) : (uint8_t)(computed >> 8);
                if(check == good) {
                    bytes[crc_off] = (uint8_t)(computed >> 8);
                    bytes[crc_off + 1] = (uint8_t)(computed & 0xFF);
                    return (int)pkt_len;
                }
            }
            bytes[d_pos[0]] = saved;
        }

        if(nd == 2 && nc == 0) {
            uint16_t received = (uint16_t)((bytes[crc_off] << 8) | bytes[crc_off + 1]);
            uint8_t saved0 = bytes[d_pos[0]];
            uint8_t saved1 = bytes[d_pos[1]];
            for(int v0 = 0; v0 < 256; v0++) {
                bytes[d_pos[0]] = (uint8_t)v0;
                uint16_t partial = cca_crc16(bytes, d_pos[1]);
                for(int v1 = 0; v1 < 256; v1++) {
                    bytes[d_pos[1]] = (uint8_t)v1;
                    if(crc_from(bytes + d_pos[1], crc_off - d_pos[1], partial) == received) {
                        return (int)pkt_len;
                    }
                }
            }
            bytes[d_pos[0]] = saved0;
            bytes[d_pos[1]] = saved1;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ N81 bits */

static inline bool get_bit(const uint8_t* d, size_t len, size_t bit) {
    size_t b = bit / 8;
    if(b >= len) return false;
    return (d[b] >> (7 - (bit % 8))) & 1;
}

static inline void set_bit(uint8_t* d, size_t len, size_t bit, bool v) {
    size_t b = bit / 8;
    if(b >= len) return;
    uint8_t mask = (uint8_t)(1 << (7 - (bit % 8)));
    if(v)
        d[b] |= mask;
    else
        d[b] &= (uint8_t)~mask;
}

static bool n81_decode_byte(const uint8_t* bits, size_t len, size_t off, uint8_t* out) {
    if(off + 10 > len * 8) return false;
    if(get_bit(bits, len, off)) return false; /* start bit must be 0 */
    uint8_t v = 0;
    for(int i = 0; i < 8; i++) {
        if(get_bit(bits, len, off + 1 + (size_t)i)) v |= (uint8_t)(1 << i);
    }
    if(!get_bit(bits, len, off + 9)) return false; /* stop bit must be 1 */
    *out = v;
    return true;
}

static size_t
    n81_decode_strict(const uint8_t* bits, size_t len, size_t off, size_t max_bytes, uint8_t* out) {
    size_t total = len * 8;
    size_t n = 0;
    for(size_t i = 0; i < max_bytes; i++) {
        size_t pos = off + i * 10;
        if(pos + 10 > total) break;
        uint8_t b;
        if(!n81_decode_byte(bits, len, pos, &b)) break;
        out[n++] = b;
    }
    return n;
}

static size_t n81_decode_tolerant(
    const uint8_t* bits,
    size_t len,
    size_t off,
    size_t max_bytes,
    uint8_t* out,
    uint8_t* errors,
    uint8_t* err_pos,
    size_t err_pos_max) {
    size_t total = len * 8;
    size_t n = 0;
    *errors = 0;
    uint8_t consecutive = 0;
    for(size_t i = 0; i < max_bytes; i++) {
        size_t pos = off + i * 10;
        if(pos + 10 > total) break;
        uint8_t b;
        if(n81_decode_byte(bits, len, pos, &b)) {
            out[n++] = b;
            consecutive = 0;
        } else {
            if(*errors < err_pos_max) err_pos[*errors] = (uint8_t)n;
            out[n++] = 0xCC;
            if(*errors < 255) (*errors)++;
            if(++consecutive >= 3) break;
        }
    }
    return n;
}

/* Position-tracked decoder: re-finds the start bit within a small window per byte. */
static size_t n81_decode_tracked(
    const uint8_t* bits,
    size_t len,
    size_t off,
    size_t max_bytes,
    uint8_t* out,
    uint8_t* errors,
    uint8_t* err_pos,
    size_t err_pos_max) {
    size_t total = len * 8;
    size_t pos = off;
    size_t n = 0;
    *errors = 0;
    uint8_t consecutive = 0;

    while(n < max_bytes && pos + 10 <= total) {
        size_t search_end = pos + 4;
        if(search_end + 10 > total) search_end = total - 10;
        bool found = false;

        for(size_t s = pos; s <= search_end; s++) {
            if(get_bit(bits, len, s)) continue;
            uint8_t b;
            if(n81_decode_byte(bits, len, s, &b)) {
                out[n++] = b;
                pos = s + 10;
                found = true;
                consecutive = 0;
                break;
            }
            b = 0;
            for(int i = 0; i < 8; i++) {
                if(get_bit(bits, len, s + 1 + (size_t)i)) b |= (uint8_t)(1 << i);
            }
            if(*errors < err_pos_max) err_pos[*errors] = (uint8_t)n;
            out[n++] = b;
            if(*errors < 255) (*errors)++;
            consecutive++;
            pos = s + 10;
            found = true;
            break;
        }

        if(!found) {
            if(*errors < err_pos_max) err_pos[*errors] = (uint8_t)n;
            out[n++] = 0xCC;
            if(*errors < 255) (*errors)++;
            consecutive++;
            pos += 10;
        }
        if(consecutive >= 3) break;
    }
    return n;
}

static void n81_write_byte(uint8_t* bits, size_t len, size_t off, uint8_t v) {
    set_bit(bits, len, off, false);
    for(int i = 0; i < 8; i++) set_bit(bits, len, off + 1 + (size_t)i, (v >> i) & 1);
    set_bit(bits, len, off + 9, true);
}

size_t cca_n81_encode(const uint8_t* payload, size_t len, uint8_t* out, size_t out_size) {
    size_t total_bits = 32 + 30 + len * 10 + 16;
    size_t total_bytes = (total_bits + 7) / 8;
    if(total_bytes > out_size) return 0;
    memset(out, 0, total_bytes);

    size_t pos = 0;
    for(int i = 0; i < 32; i++) set_bit(out, total_bytes, pos + (size_t)i, (i % 2) == 0);
    pos += 32;
    n81_write_byte(out, total_bytes, pos, 0xFF);
    pos += 10;
    n81_write_byte(out, total_bytes, pos, 0xFA);
    pos += 10;
    n81_write_byte(out, total_bytes, pos, 0xDE);
    pos += 10;
    for(size_t i = 0; i < len; i++) {
        n81_write_byte(out, total_bytes, pos, payload[i]);
        pos += 10;
    }
    return total_bytes;
}

/* Finds FF FA DE (or FA DE) from start_bit; returns the bit offset of the payload or -1. */
static int n81_find_sync(const uint8_t* bits, size_t len, size_t start_bit, size_t max_search) {
    size_t total = len * 8;
    if(total < 50) return -1;
    size_t limit = max_search;
    if(limit > total - 30) limit = total > 30 ? total - 30 : 0;

    for(size_t p = start_bit; p < limit; p++) {
        uint8_t b1, b2, b3;
        bool ok1 = n81_decode_byte(bits, len, p, &b1);
        bool ok2 = n81_decode_byte(bits, len, p + 10, &b2);
        bool ok3 = n81_decode_byte(bits, len, p + 20, &b3);
        if(ok1 && ok2 && ok3 && b1 == 0xFF && b2 == 0xFA && b3 == 0xDE) return (int)(p + 30);
        if(ok1 && ok2 && b1 == 0xFA && b2 == 0xDE) return (int)(p + 20);
    }
    return -1;
}

/* ------------------------------------------------------------------ decoder */

#define MAX_DECODE_LEN 56
#define MAX_SYNC_SEARCH 500

static void fill_packet(CcaPacket* p, const uint8_t* bytes, size_t len, bool crc_ok, uint8_t errs) {
    memset(p, 0, sizeof(*p));
    size_t n = len < CCA_MAX_PKT ? len : CCA_MAX_PKT;
    memcpy(p->raw, bytes, n);
    p->len = (uint8_t)n;
    p->type = bytes[0];
    p->seq = bytes[1];
    p->crc_ok = crc_ok;
    p->n81_errors = errs;
    if(n > 7) {
        p->format = bytes[7];
        p->has_format = true;
    }
}

/* 5-byte XOR-encoded dimmer ACK: 0B seq (fmt^FE) (seq^26) (level^FE). */
static bool parse_dimmer_ack(const uint8_t* d, size_t n, CcaPacket* p) {
    if(n < 5 || d[0] != 0x0B) return false;
    if(d[3] != (uint8_t)(d[1] ^ 0x26)) return false;
    memset(p, 0, sizeof(*p));
    p->raw[0] = 0x0B;
    p->raw[1] = d[1];
    p->raw[2] = (uint8_t)(d[2] ^ 0xFE);
    p->raw[3] = d[3];
    p->raw[4] = (uint8_t)(d[4] ^ 0xFE);
    p->len = 5;
    p->type = 0x0B;
    p->seq = d[1];
    p->format = p->raw[2];
    p->has_format = true;
    p->crc_ok = true;
    return true;
}

bool cca_decode(const uint8_t* fifo, size_t len, CcaPacket* pkt) {
    if(len * 8 < 200) return false;

    size_t search_from = 0;
    bool have_ack = false;
    CcaPacket ack;

    uint8_t best[MAX_DECODE_LEN];
    size_t best_len = 0;
    uint8_t best_errors = 255;
    uint8_t best_err_pos[ERR_POS_MAX] = {0};

    uint8_t strict[MAX_DECODE_LEN];
    uint8_t tol[MAX_DECODE_LEN];
    uint8_t trk[MAX_DECODE_LEN];

    while(true) {
        int start = n81_find_sync(fifo, len, search_from, MAX_SYNC_SEARCH);
        if(start < 0) break;

        size_t strict_len = n81_decode_strict(fifo, len, (size_t)start, MAX_DECODE_LEN, strict);
        if(strict_len >= 10) {
            int m = crc_check_lengths(strict, strict_len);
            if(m > 0) {
                fill_packet(pkt, strict, (size_t)m, true, 0);
                return true;
            }
            if(strict_len > best_len) {
                memcpy(best, strict, strict_len);
                best_len = strict_len;
                best_errors = 0;
            }
        }

        uint8_t errors = 0, err_pos[ERR_POS_MAX] = {0};
        size_t tol_len = n81_decode_tolerant(
            fifo, len, (size_t)start, MAX_DECODE_LEN, tol, &errors, err_pos, ERR_POS_MAX);
        if(tol_len >= 10 && tol_len > strict_len) {
            int m = crc_check_lengths(tol, tol_len);
            if(m > 0) {
                fill_packet(pkt, tol, (size_t)m, true, errors);
                return true;
            }
            if(errors > 0) {
                m = recover_n81_errors(tol, tol_len, err_pos, errors);
                if(m > 0) {
                    fill_packet(pkt, tol, (size_t)m, true, errors);
                    return true;
                }
            }
            if(tol_len > best_len || (tol_len == best_len && errors < best_errors)) {
                memcpy(best, tol, tol_len);
                best_len = tol_len;
                best_errors = errors;
                memcpy(best_err_pos, err_pos, ERR_POS_MAX);
            }
        }

        uint8_t terr = 0, terr_pos[ERR_POS_MAX] = {0};
        size_t trk_len =
            n81_decode_tracked(fifo, len, (size_t)start, MAX_DECODE_LEN, trk, &terr, terr_pos, ERR_POS_MAX);
        if(trk_len >= 10 && trk_len > best_len) {
            int m = crc_check_lengths(trk, trk_len);
            if(m > 0) {
                fill_packet(pkt, trk, (size_t)m, true, terr);
                return true;
            }
            if(terr > 0) {
                m = recover_n81_errors(trk, trk_len, terr_pos, terr);
                if(m > 0) {
                    fill_packet(pkt, trk, (size_t)m, true, terr);
                    return true;
                }
            }
            if(trk_len > best_len || (trk_len == best_len && terr < best_errors)) {
                memcpy(best, trk, trk_len);
                best_len = trk_len;
                best_errors = terr;
                memcpy(best_err_pos, terr_pos, ERR_POS_MAX);
            }
        }

        if(!have_ack && strict_len >= 5 && strict[0] == 0x0B) {
            if(parse_dimmer_ack(strict, strict_len, &ack)) have_ack = true;
        }

        search_from = (size_t)start + 10;
    }

    if(have_ack) {
        *pkt = ack;
        return true;
    }

    if(best_len >= 10) {
        if(best_errors > 0) {
            int m = recover_n81_errors(best, best_len, best_err_pos, best_errors);
            if(m > 0) {
                fill_packet(pkt, best, (size_t)m, true, best_errors);
                return true;
            }
        }
        int m = crc_check_lengths(best, best_len);
        if(m > 0) {
            fill_packet(pkt, best, (size_t)m, true, best_errors);
        } else {
            fill_packet(pkt, best, best_len, false, best_errors);
        }
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------ levels + builder */

uint16_t cca_pct_to_level16(uint8_t pct) {
    if(pct >= 100) return 0xFEFF;
    if(pct == 0) return 0;
    return (uint16_t)((uint32_t)pct * 65279u / 100u);
}

uint8_t cca_level16_to_pct(uint16_t level16) {
    uint32_t v = ((uint32_t)level16 * 100u + 32639u) / 65279u;
    return v > 100 ? 100 : (uint8_t)v;
}

size_t cca_build_set_level(
    uint8_t* pkt,
    const uint8_t src[4],
    const uint8_t tgt[4],
    uint16_t level16,
    uint8_t fade_qs,
    uint8_t type_byte) {
    memset(pkt, 0, 22);
    pkt[0] = type_byte;
    pkt[1] = 0; /* sequence: filled by caller */
    memcpy(pkt + 2, src, 4);
    pkt[6] = 0x21; /* QS_PROTO_RADIO_TX */
    pkt[7] = 0x0E; /* QS_FMT_LEVEL */
    pkt[8] = 0x00; /* flags: normal (0x03 would mean Pico framing) */
    memcpy(pkt + 9, tgt, 4);
    pkt[13] = 0xFE; /* QS_ADDR_COMPONENT */
    pkt[14] = 0x40; /* QS_CLASS_LEVEL */
    pkt[15] = 0x02; /* QS_TYPE_EXECUTE */
    pkt[16] = (uint8_t)(level16 >> 8);
    pkt[17] = (uint8_t)(level16 & 0xFF);
    pkt[18] = 0x00;
    pkt[19] = fade_qs;
    return 22;
}

size_t cca_build_vive_level(
    uint8_t* pkt,
    const uint8_t hub[4],
    uint8_t zone,
    uint16_t level16,
    uint8_t fade_qs,
    uint8_t type_byte) {
    memset(pkt, 0, 22);
    pkt[0] = type_byte;
    memcpy(pkt + 2, hub, 4);
    pkt[6] = 0x21; /* QS_PROTO_RADIO_TX */
    pkt[7] = 0x0E; /* QS_FMT_LEVEL */
    pkt[8] = 0x00;
    pkt[12] = zone;
    pkt[13] = 0xEF; /* QS_ADDR_GROUP */
    pkt[14] = 0x40; /* QS_CLASS_LEVEL */
    pkt[15] = 0x02; /* QS_TYPE_EXECUTE */
    pkt[16] = (uint8_t)(level16 >> 8);
    pkt[17] = (uint8_t)(level16 & 0xFF);
    pkt[18] = 0x00;
    pkt[19] = fade_qs;
    return 22;
}

size_t cca_build_vive_dim(
    uint8_t* pkt,
    const uint8_t hub[4],
    uint8_t zone,
    bool raise,
    bool hold_start,
    uint8_t type_byte) {
    memset(pkt, 0, 22);
    pkt[0] = type_byte;
    memcpy(pkt + 2, hub, 4);
    pkt[6] = 0x21;
    pkt[7] = hold_start ? 0x09 : 0x0B; /* QS_FMT_CTRL / QS_FMT_DIM_STEP */
    pkt[12] = zone;
    pkt[13] = 0xEF;
    pkt[14] = 0x42; /* QS_CLASS_DIM */
    pkt[15] = hold_start ? 0x00 : 0x02; /* QS_TYPE_HOLD / QS_TYPE_STEP */
    pkt[16] = raise ? 0x03 : 0x02;
    return 22;
}

size_t cca_build_button_short(
    uint8_t* pkt,
    const uint8_t device_id[4],
    uint8_t button,
    uint8_t action,
    uint8_t type_byte) {
    memset(pkt, 0, 22);
    pkt[0] = type_byte;
    memcpy(pkt + 2, device_id, 4);
    pkt[6] = 0x21;
    pkt[7] = 0x04; /* QS_FMT_TAP */
    pkt[8] = 0x03; /* QS_PICO_FRAME */
    pkt[10] = button;
    pkt[11] = action;
    return 22;
}

size_t cca_build_button_long(
    uint8_t* pkt,
    const uint8_t device_id[4],
    uint8_t button,
    uint8_t type_byte) {
    memset(pkt, 0, 22);
    pkt[0] = type_byte;
    memcpy(pkt + 2, device_id, 4);
    pkt[6] = 0x21;
    pkt[7] = 0x0E; /* QS_FMT_LEVEL */
    pkt[8] = 0x03; /* QS_PICO_FRAME */
    pkt[10] = button;
    pkt[11] = 0x01; /* ACTION_RELEASE */
    memcpy(pkt + 12, device_id, 4);
    pkt[16] = 0x00;
    if(button == 0x05 || button == 0x06) {
        /* RAISE / LOWER: dim class, execute, direction, then the two trailing bytes real Picos
         * send (bytes 17-21 = 42 02 01 00 16 raise, 42 02 00 00 43 lower). Ported from
         * cca_build_button_long in lutron-protocols firmware/src/cca/cca_tx_builder.h. */
        pkt[17] = 0x42; /* QS_CLASS_DIM */
        pkt[18] = 0x02; /* QS_TYPE_EXECUTE */
        pkt[19] = button == 0x05 ? 0x01 : 0x00; /* direction: 1 raise, 0 lower */
        pkt[20] = 0x00;
        pkt[21] = button == 0x05 ? 0x16 : 0x43;
    } else {
        pkt[17] = 0x40; /* QS_CLASS_LEVEL */
        pkt[18] = 0x00; /* QS_TYPE_HOLD */
        pkt[19] = (uint8_t)(0x1E + button); /* QS_PRESET_BASE + button */
    }
    return 22;
}

bool cca_is_vive_cmd(const CcaPacket* p) {
    if(p->type < 0x88 || p->type > 0x8B || !p->has_format || p->len < 18) return false;
    /* Vive hub framing: byte 8 = 0x00 (Pico packets of the same types use 0x03) and the 0xEF
     * group marker right after the zone byte. Any format with that framing counts: real hubs
     * also send format 0x0A (bytes 14-17 = 47 06 FF 00, CC padding), which the repo's docs
     * do not describe, alongside the documented 0x0E level / 0x09 hold / 0x0B step. */
    return p->raw[8] == 0x00 && p->raw[13] == 0xEF;
}

bool cca_is_bridge_cmd(const CcaPacket* p) {
    if(p->type < 0x81 || p->type > 0x83 || !p->has_format || p->len < 18) return false;
    return p->format == 0x0E && p->raw[8] == 0x00;
}

/* ------------------------------------------------------------------ describe */

static const char* button_name(uint8_t b) {
    switch(b) {
    case 0x02:
        return "ON";
    case 0x03:
        return "FAV";
    case 0x04:
        return "OFF";
    case 0x05:
        return "RAISE";
    case 0x06:
        return "LOWER";
    case 0x08:
        return "B1";
    case 0x09:
        return "B2";
    case 0x0A:
        return "B3";
    case 0x0B:
        return "B4";
    case 0xFF:
        return "RESET";
    default:
        return "?";
    }
}

static void button_action(uint8_t action, char* out, size_t n) {
    switch(action) {
    case 0x00:
        snprintf(out, n, "prs");
        break;
    case 0x01:
        snprintf(out, n, "rel");
        break;
    default:
        snprintf(out, n, "a%02X", (unsigned)action);
        break;
    }
}

static bool is_handshake_type(uint8_t t) {
    /* dimmer = C1 + 6n, bridge = C2 + 6n, sensor echo = C5, container = C0 */
    if(t == 0xC0 || t == 0xC5) return true;
    if(t < 0xC1 || t > 0xE0) return false;
    uint8_t d = (uint8_t)(t - 0xC1);
    return (d % 6) == 0 || (d % 6) == 1;
}

static void hex4(const uint8_t* b, char* o) {
    snprintf(o, 9, "%02X%02X%02X%02X", b[0], b[1], b[2], b[3]);
}

void cca_describe(const CcaPacket* p, char* out, size_t n) {
    const uint8_t* r = p->raw ;
    uint8_t t = p->type;
    uint8_t f = p->has_format ? p->format : 0;
    char a[9];

    if(!p->crc_ok) {
        snprintf(out, n, "BAD t%02X len%u", (unsigned)t, (unsigned)p->len);
        return;
    }
    if(t == 0x0B) {
        snprintf(out, n, "ACK lvl=%u", (unsigned)r[4]);
        return;
    }
    if(cca_is_vive_cmd(p)) {
        /* Zone before hub: the hub ID is the part most likely to be clipped on screen. */
        hex4(r + 2, a);
        if(f == 0x0E) {
            uint16_t l16 = (uint16_t)((r[16] << 8) | r[17]);
            snprintf(
                out, n, "VIVE %u%% z%02X %s", (unsigned)cca_level16_to_pct(l16), (unsigned)r[12], a);
        } else if(f == 0x09 || f == 0x0B) {
            snprintf(out, n, "VIVE %s z%02X %s", r[16] == 0x03 ? "up" : "dn", (unsigned)r[12], a);
        } else {
            snprintf(out, n, "VIVE f%02X z%02X %s", (unsigned)f, (unsigned)r[12], a);
        }
        return;
    }
    if(t >= 0x80 && t <= 0x83) {
        if(f == 0x0E && p->len >= 18) {
            uint16_t l16 = (uint16_t)((r[16] << 8) | r[17]);
            if(r[8] == 0x03) {
                hex4(r + 2, a);
                snprintf(out, n, "PICO %u%% %s", (unsigned)cca_level16_to_pct(l16), a);
            } else {
                hex4(r + 9, a);
                snprintf(out, n, "SET %u%% >%s", (unsigned)cca_level16_to_pct(l16), a);
            }
            return;
        }
        if(f == 0x08 && p->len > 11) {
            hex4(r + 2, a);
            unsigned pct = ((unsigned)r[11] * 100u + 127u) / 254u;
            snprintf(out, n, "STATE %u%% %s", pct, a);
            return;
        }
        hex4(r + 2, a);
        snprintf(out, n, "CMD f%02X %s", (unsigned)f, a);
        return;
    }
    if(t >= 0x88 && t <= 0x8B) {
        char action[4];
        hex4(r + 2, a);
        button_action(r[11], action, sizeof(action));
        snprintf(
            out,
            n,
            "BTN %s %s %s",
            button_name(r[10]),
            action,
            a);
        return;
    }
    if(t >= 0x91 && t <= 0x93) {
        hex4(r + 2, a);
        snprintf(out, n, "BEACON %02X %s", (unsigned)t, a);
        return;
    }
    if(t >= 0xA0 && t <= 0xAF) {
        hex4(r + 2, a);
        snprintf(out, n, "CONFIG f%02X %s", (unsigned)f, a);
        return;
    }
    if(t >= 0xB0 && t <= 0xBF) {
        hex4(r + 2, a);
        snprintf(out, n, "PAIR %02X %s", (unsigned)t, a);
        return;
    }
    if(is_handshake_type(t)) {
        hex4(r + 2, a);
        snprintf(out, n, "HS %02X %s", (unsigned)t, a);
        return;
    }
    snprintf(out, n, "T%02X f%02X len%u", (unsigned)t, (unsigned)f, (unsigned)p->len);
}
