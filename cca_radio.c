#include "cca_radio.h"
#include "cca_codec.h"

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_spi.h>
#include <lib/drivers/cc1101_regs.h>
#include <string.h>

#define TAG "CcaRadio"

#define RX_PKT_LEN CCA_RX_LEN
#define ACCUM_TIMEOUT_MS 25

/* MARCSTATE values */
#define MARC_IDLE 0x01
#define MARC_RX 0x0D
#define MARC_RXFIFO_OVERFLOW 0x11
#define MARC_TX 0x13
#define MARC_TX_END 0x14
#define MARC_TXFIFO_UNDERFLOW 0x16

/*
 * Register table in furi_hal_subghz_load_custom_preset() format:
 * reg,value pairs, 0x00 0x00 terminator, then 8 PA table bytes.
 * Values from firmware/src/cca/cc1101.c (cc1101_init + cc1101_start_rx).
 * IOCFG2 (register 0x00) cannot appear here because 0x00 terminates the list.
 */
static const uint8_t cca_preset[] = {
    CC1101_IOCFG0,   0x06, /* GDO0: sync word received / end of packet */
    CC1101_FIFOTHR,  0x07,
    CC1101_SYNC1,    0xAA, /* preamble-as-sync for RX */
    CC1101_SYNC0,    0xAA,
    CC1101_PKTLEN,   RX_PKT_LEN,
    CC1101_PKTCTRL1, 0x00,
    CC1101_PKTCTRL0, 0x00, /* fixed length, no HW CRC, FIFO mode */
    CC1101_ADDR,     0x00,
    CC1101_CHANNR,   0x00,
    CC1101_FSCTRL1,  0x06,
    CC1101_FSCTRL0,  0x00,
    CC1101_FREQ2,    0x10, /* 433.602844 MHz; overwritten by set_frequency */
    CC1101_FREQ1,    0xAD,
    CC1101_FREQ0,    0x52,
    CC1101_MDMCFG4,  0x5B, /* 325 kHz RX BW, DRATE_E=11 */
    CC1101_MDMCFG3,  0x3B, /* 62.5 kBaud with MDMCFG4 */
    CC1101_MDMCFG2,  0x01, /* 2-FSK, 15/16 sync match */
    CC1101_MDMCFG1,  0x00,
    CC1101_MDMCFG0,  0x00,
    CC1101_DEVIATN,  0x45, /* 41.2 kHz */
    CC1101_MCSM1,    0x0F, /* CCA always, RXOFF=stay in RX, TXOFF=RX */
    CC1101_MCSM0,    0x18, /* FS_AUTOCAL on IDLE->RX/TX */
    CC1101_FOCCFG,   0x16,
    CC1101_BSCFG,    0x6C,
    CC1101_AGCCTRL2, 0x43,
    CC1101_AGCCTRL1, 0x40,
    CC1101_AGCCTRL0, 0x91,
    CC1101_WORCTRL,  0xFB,
    CC1101_FREND1,   0x56,
    CC1101_FREND0,   0x10,
    CC1101_FSCAL3,   0xEA,
    CC1101_FSCAL2,   0x2A,
    CC1101_FSCAL1,   0x00,
    CC1101_FSCAL0,   0x1F,
    CC1101_TEST2,    0xAC, /* improved RX sensitivity (DN505) */
    0x00,            0x00,
    0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* PA table: +10 dBm */
};

static const FuriHalSpiBusHandle* spi = &furi_hal_spi_bus_handle_subghz;

static bool initialized = false;
static bool rx_active = false;
static uint8_t chip_version = 0;

static uint8_t accum[RX_PKT_LEN + 4];
static size_t accum_len = 0;
static bool accum_active = false;
static uint32_t accum_start_ms = 0;
static int8_t accum_rssi = 0;

static uint32_t overflow_count = 0;
static uint32_t timeout_count = 0;

/* ------------------------------------------------------------------ SPI primitives */

static void wait_chip_ready(void) {
    /* CS is asserted by furi_hal_spi_acquire; MISO goes low once the chip is ready. */
    uint32_t guard = 0;
    while(furi_hal_gpio_read(spi->miso) && guard++ < 100000) {
    }
}

static uint8_t reg_write(uint8_t reg, uint8_t val) {
    uint8_t tx[2] = {reg, val};
    uint8_t rx[2] = {0, 0};
    furi_hal_spi_acquire(spi);
    wait_chip_ready();
    furi_hal_spi_bus_trx(spi, tx, rx, 2, CC1101_TIMEOUT);
    furi_hal_spi_release(spi);
    return rx[0];
}

static uint8_t status_read(uint8_t reg) {
    uint8_t tx[2] = {(uint8_t)(reg | CC1101_READ | CC1101_BURST), 0};
    uint8_t rx[2] = {0, 0};
    furi_hal_spi_acquire(spi);
    wait_chip_ready();
    furi_hal_spi_bus_trx(spi, tx, rx, 2, CC1101_TIMEOUT);
    furi_hal_spi_release(spi);
    return rx[1];
}

static uint8_t strobe(uint8_t s) {
    uint8_t tx[1] = {s};
    uint8_t rx[1] = {0};
    furi_hal_spi_acquire(spi);
    wait_chip_ready();
    furi_hal_spi_bus_trx(spi, tx, rx, 1, CC1101_TIMEOUT);
    furi_hal_spi_release(spi);
    return rx[0];
}

static void fifo_read(uint8_t* buf, size_t n) {
    uint8_t tx[RX_PKT_LEN + 1];
    uint8_t rx[RX_PKT_LEN + 1];
    if(n > RX_PKT_LEN) n = RX_PKT_LEN;
    memset(tx, 0, sizeof(tx));
    tx[0] = CC1101_FIFO | CC1101_READ | CC1101_BURST;
    furi_hal_spi_acquire(spi);
    wait_chip_ready();
    furi_hal_spi_bus_trx(spi, tx, rx, n + 1, CC1101_TIMEOUT);
    furi_hal_spi_release(spi);
    memcpy(buf, rx + 1, n);
}

static void fifo_write(const uint8_t* data, size_t n) {
    uint8_t tx[65];
    uint8_t rx[65];
    if(n > 64) n = 64;
    tx[0] = CC1101_FIFO | CC1101_BURST;
    memcpy(tx + 1, data, n);
    furi_hal_spi_acquire(spi);
    wait_chip_ready();
    furi_hal_spi_bus_trx(spi, tx, rx, n + 1, CC1101_TIMEOUT);
    furi_hal_spi_release(spi);
}

static uint8_t marc_state(void) {
    return status_read(CC1101_STATUS_MARCSTATE) & 0x1F;
}

/* RXBYTES can glitch mid-update; read until two consecutive reads agree. */
static uint8_t read_rxbytes_safe(void) {
    uint8_t a = status_read(CC1101_STATUS_RXBYTES);
    for(int i = 0; i < 4; i++) {
        uint8_t b = status_read(CC1101_STATUS_RXBYTES);
        if(a == b) return a;
        a = b;
    }
    return a;
}

static bool wait_marc(uint8_t state, uint32_t spins_10us) {
    for(uint32_t i = 0; i < spins_10us; i++) {
        if(marc_state() == state) return true;
        furi_delay_us(10);
    }
    return false;
}

static void go_idle(void) {
    strobe(CC1101_STROBE_SIDLE);
    wait_marc(MARC_IDLE, 500);
}

static int8_t read_rssi_dbm(void) {
    uint8_t raw = status_read(CC1101_STATUS_RSSI);
    if(raw >= 128) return (int8_t)(((int16_t)raw - 256) / 2 - 74);
    return (int8_t)(raw / 2 - 74);
}

/* ------------------------------------------------------------------ lifecycle */

bool cca_radio_init(uint32_t freq_hz) {
    furi_hal_subghz_reset();
    furi_hal_subghz_load_custom_preset(cca_preset);
    chip_version = status_read(CC1101_STATUS_VERSION);
    FURI_LOG_I(TAG, "CC1101 version 0x%02X", chip_version);
    initialized = (chip_version != 0x00 && chip_version != 0xFF);
    cca_radio_set_frequency(freq_hz);
    return initialized;
}

void cca_radio_deinit(void) {
    if(rx_active) cca_radio_stop_rx();
    furi_hal_subghz_idle();
    furi_hal_subghz_sleep();
    initialized = false;
}

uint8_t cca_radio_chip_version(void) {
    return chip_version;
}

void cca_radio_set_frequency(uint32_t freq_hz) {
    bool was_rx = rx_active;
    if(was_rx) cca_radio_stop_rx();
    furi_hal_subghz_idle();
    uint32_t real = furi_hal_subghz_set_frequency_and_path(freq_hz);
    FURI_LOG_I(TAG, "freq %lu -> %lu", (unsigned long)freq_hz, (unsigned long)real);
    if(was_rx) cca_radio_start_rx();
}

/* ------------------------------------------------------------------ RX */

static void rx_config_regs(void) {
    reg_write(CC1101_SYNC1, 0xAA);
    reg_write(CC1101_SYNC0, 0xAA);
    reg_write(CC1101_MDMCFG2, 0x01); /* 2-FSK, 15/16 sync match */
    reg_write(CC1101_PKTCTRL0, 0x00); /* fixed length */
    reg_write(CC1101_PKTCTRL1, 0x00);
    reg_write(CC1101_PKTLEN, RX_PKT_LEN);
    reg_write(CC1101_FIFOTHR, 0x07);
    reg_write(CC1101_IOCFG0, 0x06);
    reg_write(CC1101_MCSM1, 0x0F);
}

void cca_radio_start_rx(void) {
    if(!initialized) return;
    go_idle();
    strobe(CC1101_STROBE_SFRX);
    rx_config_regs();
    accum_len = 0;
    accum_active = false;
    strobe(CC1101_STROBE_SRX);
    rx_active = true;
}

void cca_radio_stop_rx(void) {
    go_idle();
    strobe(CC1101_STROBE_SFRX);
    accum_len = 0;
    accum_active = false;
    rx_active = false;
}

bool cca_radio_rx_active(void) {
    return rx_active;
}

static void restart_rx(void) {
    go_idle();
    strobe(CC1101_STROBE_SFRX);
    accum_len = 0;
    accum_active = false;
    strobe(CC1101_STROBE_SRX);
}

bool cca_radio_poll_rx(uint8_t* out, size_t out_cap, size_t* out_len, int8_t* rssi) {
    if(!rx_active) return false;

    uint8_t rxbytes = read_rxbytes_safe();
    if(rxbytes & 0x80) {
        overflow_count++;
        restart_rx();
        return false;
    }
    uint8_t avail = rxbytes & 0x7F;

    if(avail > 0) {
        if(!accum_active) {
            accum_active = true;
            accum_start_ms = furi_get_tick();
            accum_len = 0;
            accum_rssi = read_rssi_dbm();
        }
        size_t space = sizeof(accum) - accum_len;
        size_t to_read = avail < space ? avail : space;
        if(to_read > 0) {
            fifo_read(accum + accum_len, to_read);
            accum_len += to_read;
        }
    }

    if(!accum_active) return false;

    if(accum_len >= RX_PKT_LEN) {
        size_t n = accum_len < out_cap ? accum_len : out_cap;
        memcpy(out, accum, n);
        *out_len = n;
        *rssi = accum_rssi;
        /* RXOFF_MODE = stay in RX: the radio is already hunting for the next sync. */
        accum_len = 0;
        accum_active = false;
        return true;
    }

    if((furi_get_tick() - accum_start_ms) > ACCUM_TIMEOUT_MS) {
        timeout_count++;
        restart_rx();
    }
    return false;
}

uint32_t cca_radio_overflows(void) {
    return overflow_count;
}

uint32_t cca_radio_timeouts(void) {
    return timeout_count;
}

/* ------------------------------------------------------------------ TX */

bool cca_radio_transmit(const uint8_t* data, size_t len) {
    if(!initialized || len == 0) return false;
    bool was_rx = rx_active;

    go_idle();
    strobe(CC1101_STROBE_SFRX);

    /* Land in IDLE after TX so RX registers can be rewritten safely. */
    reg_write(CC1101_MCSM1, 0x0C);
    reg_write(CC1101_MDMCFG2, 0x00); /* no HW sync: the bitstream carries its own */
    strobe(CC1101_STROBE_SFTX);

    bool started;
    if(len <= 64) {
        reg_write(CC1101_PKTCTRL0, 0x00);
        reg_write(CC1101_PKTLEN, (uint8_t)len);
        fifo_write(data, len);
        started = furi_hal_subghz_tx(); /* STX, honours the Flipper's region policy */
    } else {
        reg_write(CC1101_PKTCTRL0, 0x02); /* infinite length, refill as we go */
        fifo_write(data, 64);
        size_t written = 64;
        started = furi_hal_subghz_tx();
        uint32_t t0 = furi_get_tick();
        while(started && written < len) {
            uint8_t txb = status_read(CC1101_STATUS_TXBYTES);
            if(txb & 0x80) break; /* underflow */
            if((txb & 0x7F) < 48) {
                size_t chunk = (len - written < 16) ? (len - written) : 16;
                fifo_write(data + written, chunk);
                written += chunk;
            }
            if(furi_get_tick() - t0 > 100) break;
            furi_delay_us(10);
        }
    }

    bool finished = false;
    if(started) {
        for(uint32_t i = 0; i < 20000; i++) {
            uint8_t s = marc_state();
            if(s == MARC_IDLE) {
                finished = true;
                break;
            }
            if(s == MARC_TXFIFO_UNDERFLOW) {
                /* Infinite-length mode ends with an underflow once the FIFO drains. */
                finished = (len > 64);
                break;
            }
            furi_delay_us(10);
        }
    }

    uint8_t s = marc_state();
    if(s == MARC_TXFIFO_UNDERFLOW || s == MARC_RXFIFO_OVERFLOW) {
        strobe(CC1101_STROBE_SIDLE);
        wait_marc(MARC_IDLE, 500);
        if(s == MARC_TXFIFO_UNDERFLOW) strobe(CC1101_STROBE_SFTX);
        if(s == MARC_RXFIFO_OVERFLOW) strobe(CC1101_STROBE_SFRX);
    }
    reg_write(CC1101_MCSM1, 0x0F);

    if(was_rx) {
        rx_config_regs();
        accum_len = 0;
        accum_active = false;
        strobe(CC1101_STROBE_SRX);
        rx_active = true;
    }
    if(!started) FURI_LOG_W(TAG, "TX refused (region lock?)");
    return started && finished;
}
