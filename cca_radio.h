#pragma once
/*
 * CC1101 packet-mode driver for Lutron CCA on the Flipper Zero's internal radio.
 *
 * The Flipper SDK does not export its cc1101_* driver to apps, but it does export
 * the Sub-GHz SPI bus handle and the furi_hal_subghz_* helpers. This module talks
 * to the chip over SPI directly, mirroring firmware/src/cca/cc1101.c from the
 * lutron-protocols repo:
 *
 *   RX: 2-FSK 62.5 kBaud, hardware sync on the 0xAAAA preamble (15/16 match),
 *       fixed 80-byte packets drained from the FIFO and handed to cca_decode().
 *   TX: no hardware preamble/sync; the N81-encoded bitstream (which already
 *       carries preamble + FF FA DE) is loaded into the FIFO verbatim.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

bool cca_radio_init(uint32_t freq_hz);
void cca_radio_deinit(void);
void cca_radio_set_frequency(uint32_t freq_hz);
uint8_t cca_radio_chip_version(void);

void cca_radio_start_rx(void);
void cca_radio_stop_rx(void);
bool cca_radio_rx_active(void);

/* Call every ~1 ms while RX is active. Returns true when a full capture is ready. */
bool cca_radio_poll_rx(uint8_t* out, size_t out_cap, size_t* out_len, int8_t* rssi);

/* Transmits an already-encoded bitstream (from cca_n81_encode). Resumes RX if it was active. */
bool cca_radio_transmit(const uint8_t* data, size_t len);

/* Counters for the status line. */
uint32_t cca_radio_overflows(void);
uint32_t cca_radio_timeouts(void);
