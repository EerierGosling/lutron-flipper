/*
 * Lutron CCA for Flipper Zero
 *
 * Runs the internal CC1101 in packet mode (not the stock async pulse-timing path,
 * which cannot resolve CCA's 16 us bits) to sniff, decode, learn IDs from, and
 * transmit Lutron Clear Connect Type A packets at 433 MHz.
 *
 * Supports two addressing schemes, selected in Settings -> System:
 *   Vive        - hub ID (bytes 2..5) + 1-byte zone (byte 12, followed by 0xEF), types 0x89-0x8B
 *   Caseta/RA3  - hub ID (bytes 2..5) + 4-byte target load ID (bytes 9..12), types 0x81-0x83
 *
 * Screens:
 *   Sniff / Learn  - live decoded packets; OK on a packet copies its IDs/zone into settings
 *   Control        - named light sets (each a list of Vive hub + zone pairs); pick a set,
 *                    then on / off / level / raise / lower every light in it at once
 *   Control adv.   - single zone/target: level / on / off, raise / lower, Pico buttons, batches
 *   Settings       - system, hub ID, target ID, zone, channel, TX slot, repeats, logging
 */
#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/byte_input.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/text_input.h>
#include <gui/modules/widget.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>
#include <stdio.h>
#include <string.h>

#include "cca_codec.h"
#include "cca_radio.h"

#define TAG "LutronCCA"
#define CONFIG_PATH APP_DATA_PATH("config.txt")
#define LOG_PATH APP_DATA_PATH("rx_log.txt")
#define RAW_EXPORT_PATH APP_DATA_PATH("raw_export.txt")
#define CONFIG_MAGIC "Lutron CCA Config"
#define CONFIG_VERSION 1

#define MAX_TARGETS 8
#define MAX_PICO_OFF_IDS 20
#define MAX_PAIRS 16
#define MAX_TX_PHASES (MAX_PAIRS * 2) /* set raise/lower: a hold and a step phase per light */
#define PAIRS_ADD_INDEX 0xFF
#define MAX_SETS 10
#define SET_NAME_LEN 20
#define SETS_NEW_INDEX 0xFE
#define SNIFF_RING 24
#define FRAME_MS 75

/* Edit this list to add the Pico IDs that belong to your lights. */
/* Placeholder IDs so the list is never empty (an empty list does not compile). Replace them
 * with the Pico IDs shown in Sniff (`BTN ... <id>`). Keep real IDs out of public commits:
 * CCA has no encryption, so a Pico ID is all anyone needs to impersonate that Pico. */
static const uint8_t PICO_OFF_IDS[][4] = {
    {0x01, 0x23, 0x45, 0x67},
    {0x89, 0xAB, 0xCD, 0xEF},
};
#define PICO_OFF_ID_COUNT (sizeof(PICO_OFF_IDS) / sizeof(PICO_OFF_IDS[0]))

typedef enum {
    ViewIdMenu,
    ViewIdSniff,
    ViewIdControl,
    ViewIdSettings,
    ViewIdByteInput,
    ViewIdAbout,
    ViewIdPairs,
    ViewIdPairEdit,
    ViewIdPairHub,
    ViewIdPairZone,
    ViewIdSets,
    ViewIdSetControl,
    ViewIdSetName,
    ViewIdConfirm,
} ViewId;

typedef enum {
    MenuSniff,
    MenuControl,
    MenuSettings,
    MenuAbout,
    MenuSets,
} MenuIndex;

typedef enum {
    CtrlZone,
    CtrlTarget,
    CtrlLevel,
    CtrlFade,
    CtrlSendLevel,
    CtrlSendOn,
    CtrlSendOff,
    CtrlPicoOn,
    CtrlPicoOff,
    CtrlPicoOffBatch,
    CtrlPicoOffStop,
    CtrlTargetOffBatch,
    CtrlTargetOffStop,
    CtrlRaise,
    CtrlLower,
} ControlIndex;

typedef enum {
    SetSystem,
    SetHub,
    SetZone,
    SetTarget,
    SetPico,
    SetChannel,
    SetSlot,
    SetRepeats,
    SetLog,
    SetShowBad,
    SetClearDevices,
    SetExportRaw,
} SettingsIndex;

/* Light set control screen rows, in display order */
typedef enum {
    SetCtlName,
    SetCtlOn,
    SetCtlOff,
    SetCtlLevel,
    SetCtlFade,
    SetCtlSendLevel,
    SetCtlRaise,
    SetCtlLower,
    SetCtlLights,
    SetCtlRename,
    SetCtlDelete,
} SetCtlIndex;

typedef enum {
    SystemVive = 0,
    SystemBridge = 1,
} SystemType;

static const char* const SYSTEM_NAMES[] = {"Vive", "Caseta/RA3"};

#define VIVE_HOLD_REPEATS 6
#define VIVE_STEP_REPEATS 12

static const uint8_t CHANNELS[] = {5, 14, 17, 20, 23, 26, 29, 32, 38, 41, 44, 47, 50, 53, 56};
#define N_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))
#define DEFAULT_CHANNEL_IDX 5 /* channel 26 */

static const uint8_t FADE_QS[] = {1, 4, 8, 20, 40};
static const char* const FADE_NAMES[] = {"0.25s", "1s", "2s", "5s", "10s"};
#define N_FADES (sizeof(FADE_QS) / sizeof(FADE_QS[0]))

typedef struct {
    uint8_t hub[4]; /* Vive hub ID, packet bytes 2..5 */
    uint8_t zone; /* Vive zone, packet byte 12 */
} VivePair;

typedef struct {
    char name[SET_NAME_LEN];
    VivePair pairs[MAX_PAIRS];
    uint8_t n_pairs;
    uint8_t level; /* percent, used by Send level */
    uint8_t fade_idx; /* index into FADE_QS, used by every command for this set */
} LightSet;

typedef struct {
    uint8_t system; /* SystemType */
    uint8_t hub[4]; /* packet bytes 2..5 of a hub command, verbatim */
    uint8_t target[4]; /* Caseta/RA3: packet bytes 9..12 of a hub command, verbatim */
    uint8_t pico[4]; /* Pico/keypad device ID for button commands */
    uint8_t targets[MAX_TARGETS][4];
    uint8_t n_targets;
    uint8_t zone; /* Vive: packet byte 12 of a hub command */
    uint8_t zones[MAX_TARGETS];
    uint8_t n_zones;
    uint8_t channel_idx;
    uint8_t slot;
    uint8_t repeats;
    uint8_t level; /* percent */
    uint8_t fade_idx;
    bool log_rx;
    bool show_bad;
    LightSet sets[MAX_SETS]; /* named groups of Vive lights, driven from the Control menu */
    uint8_t n_sets;
} AppConfig;

typedef struct {
    uint8_t pkt[CCA_MAX_PKT];
    uint8_t len;
    uint8_t repeats;
    uint8_t group; /* interleaved sends: phases sharing a group are interleaved, groups run in order */
} TxPhase;

typedef struct {
    CcaPacket pkt;
    int8_t rssi;
    uint32_t tick;
} SniffEntry;

typedef struct {
    SniffEntry ring[SNIFF_RING];
    uint8_t count;
    uint8_t head;
    uint8_t selected; /* 0 = newest */
    bool detail;
    uint8_t detail_scroll;
    uint32_t total;
    uint32_t crc_bad;
    char status[28];
} SniffModel;

typedef struct {
    Gui* gui;
    ViewDispatcher* vd;
    NotificationApp* notif;
    Storage* storage;

    Submenu* menu;
    View* sniff_view;
    VariableItemList* control;
    VariableItemList* settings;
    ByteInput* byte_input;
    Widget* about;
    Submenu* pairs_menu;
    DialogEx* pair_dialog;
    ByteInput* pair_hub_input;
    ByteInput* pair_zone_input;
    Submenu* sets_menu;
    VariableItemList* set_control;
    TextInput* set_name_input;
    DialogEx* confirm_dialog;

    VariableItem* item_zone;
    VariableItem* item_target;
    VariableItem* item_level;
    VariableItem* item_fade;
    VariableItem* item_set_name;
    VariableItem* item_set_level;
    VariableItem* item_set_fade;
    VariableItem* item_system;
    VariableItem* item_hub;
    VariableItem* item_zone_setting;
    VariableItem* item_tgt;
    VariableItem* item_pico;
    VariableItem* item_show_bad;
    VariableItem* item_channel;
    VariableItem* item_slot;
    VariableItem* item_repeats;
    VariableItem* item_log;

    AppConfig cfg;
    uint8_t target_sel; /* index into cfg.targets, or cfg.n_targets for the manual target */
    uint8_t zone_sel; /* index into cfg.zones, or cfg.n_zones for the manual zone */

    uint8_t byte_buf[4];
    uint8_t* byte_dest;
    uint8_t byte_len;

    /* Light set + pairs editor state; strings live here because the GUI keeps the pointers */
    uint8_t set_sel; /* the set being controlled / edited */
    uint8_t set_edit_index; /* == cfg.n_sets when creating a new set */
    char set_name_buf[SET_NAME_LEN];
    char confirm_text[48];
    uint8_t pair_sel;
    uint8_t pair_edit_index; /* == current set's n_pairs when adding a new pair */
    uint8_t pair_hub_buf[4];
    uint8_t pair_zone_buf[1];
    char pairs_header[24];
    char pair_labels[MAX_PAIRS][24];
    char pair_dialog_header[24];
    char pair_dialog_text[40];

    FuriThread* worker;
    FuriMutex* mutex;
    volatile bool running;
    volatile bool rx_enabled;

    volatile bool tx_pending;
    TxPhase tx_phase[MAX_TX_PHASES];
    TxPhase tx_work[MAX_TX_PHASES]; /* worker-owned copy, kept off the worker's stack */
    uint8_t tx_nphases;
    bool tx_interleave; /* true: send copy r of every phase before copy r+1 */
    uint8_t seq_counter;
    uint8_t type_rot;
    volatile bool pico_batch_active;
    volatile bool pico_batch_cancel;
    uint8_t pico_batch_index;
    volatile bool target_batch_active;
    volatile bool target_batch_cancel;
    uint8_t target_batch_index;

    File* log_file;
    bool radio_ok;
} App;

/* ------------------------------------------------------------------ helpers */

static uint32_t channel_freq_hz(uint8_t channel) {
    /* Channel table: 431.0 MHz + ch * 100 kHz. The default channel 26 is observed at
     * 433.602844 MHz (CC1101 word 0x10AD52), 2844 Hz above the formula, so the same
     * offset is applied to every channel. */
    return 431000000u + (uint32_t)channel * 100000u + 2844u;
}

static void hex4_str(const uint8_t* b, char* out, size_t n) {
    snprintf(out, n, "%02X%02X%02X%02X", b[0], b[1], b[2], b[3]);
}

static const uint8_t* current_target(App* app) {
    if(app->target_sel < app->cfg.n_targets) return app->cfg.targets[app->target_sel];
    return app->cfg.target;
}

static uint8_t current_zone(App* app) {
    if(app->zone_sel < app->cfg.n_zones) return app->cfg.zones[app->zone_sel];
    return app->cfg.zone;
}

static void add_zone(App* app, uint8_t zone) {
    for(uint8_t i = 0; i < app->cfg.n_zones; i++) {
        if(app->cfg.zones[i] == zone) {
            app->zone_sel = i;
            return;
        }
    }
    if(app->cfg.n_zones < MAX_TARGETS) {
        app->cfg.zones[app->cfg.n_zones] = zone;
        app->zone_sel = app->cfg.n_zones;
        app->cfg.n_zones++;
    } else {
        memmove(app->cfg.zones, app->cfg.zones + 1, MAX_TARGETS - 1);
        app->cfg.zones[MAX_TARGETS - 1] = zone;
        app->zone_sel = MAX_TARGETS - 1;
    }
}

static void add_target(App* app, const uint8_t id[4]) {
    for(uint8_t i = 0; i < app->cfg.n_targets; i++) {
        if(memcmp(app->cfg.targets[i], id, 4) == 0) {
            app->target_sel = i;
            return;
        }
    }
    if(app->cfg.n_targets < MAX_TARGETS) {
        memcpy(app->cfg.targets[app->cfg.n_targets], id, 4);
        app->target_sel = app->cfg.n_targets;
        app->cfg.n_targets++;
    } else {
        memmove(app->cfg.targets[0], app->cfg.targets[1], (MAX_TARGETS - 1) * 4);
        memcpy(app->cfg.targets[MAX_TARGETS - 1], id, 4);
        app->target_sel = MAX_TARGETS - 1;
    }
}

/* ------------------------------------------------------------------ config */

static void config_defaults(AppConfig* c) {
    memset(c, 0, sizeof(*c));
    c->channel_idx = DEFAULT_CHANNEL_IDX;
    c->slot = 0;
    c->repeats = 11;
    c->level = 50;
    c->fade_idx = 1;
    c->log_rx = true;
    c->show_bad = false;
    c->system = SystemVive;
    c->zone = 0x38; /* the zone the repo's Vive pairing defaults to */
}

static void config_save(App* app) {
    storage_common_mkdir(app->storage, STORAGE_APP_DATA_PATH_PREFIX);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    if(flipper_format_file_open_always(ff, CONFIG_PATH)) {
        AppConfig* c = &app->cfg;
        uint32_t v;
        flipper_format_write_header_cstr(ff, CONFIG_MAGIC, CONFIG_VERSION);
        v = c->system;
        flipper_format_write_uint32(ff, "System", &v, 1);
        flipper_format_write_hex(ff, "Hub", c->hub, 4);
        flipper_format_write_hex(ff, "Zone", &c->zone, 1);
        v = c->n_zones;
        flipper_format_write_uint32(ff, "NZones", &v, 1);
        if(c->n_zones) flipper_format_write_hex(ff, "Zones", c->zones, c->n_zones);
        flipper_format_write_hex(ff, "Target", c->target, 4);
        flipper_format_write_hex(ff, "Pico", c->pico, 4);
        v = c->n_targets;
        flipper_format_write_uint32(ff, "NTargets", &v, 1);
        if(c->n_targets) flipper_format_write_hex(ff, "Targets", &c->targets[0][0], (size_t)c->n_targets * 4);
        v = c->channel_idx;
        flipper_format_write_uint32(ff, "ChannelIdx", &v, 1);
        v = c->slot;
        flipper_format_write_uint32(ff, "Slot", &v, 1);
        v = c->repeats;
        flipper_format_write_uint32(ff, "Repeats", &v, 1);
        v = c->level;
        flipper_format_write_uint32(ff, "Level", &v, 1);
        v = c->fade_idx;
        flipper_format_write_uint32(ff, "FadeIdx", &v, 1);
        v = c->log_rx ? 1 : 0;
        flipper_format_write_uint32(ff, "LogRx", &v, 1);
        v = c->show_bad ? 1 : 0;
        flipper_format_write_uint32(ff, "ShowBad", &v, 1);
        v = c->n_sets;
        flipper_format_write_uint32(ff, "NSets", &v, 1);
        char key[20];
        for(uint8_t i = 0; i < c->n_sets; i++) {
            const LightSet* st = &c->sets[i];
            snprintf(key, sizeof(key), "Set%uName", (unsigned)i);
            flipper_format_write_string_cstr(ff, key, st->name);
            v = st->n_pairs;
            snprintf(key, sizeof(key), "Set%uNPairs", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
            if(st->n_pairs) {
                uint8_t hubs[MAX_PAIRS * 4];
                uint8_t zones[MAX_PAIRS];
                for(uint8_t k = 0; k < st->n_pairs; k++) {
                    memcpy(hubs + k * 4, st->pairs[k].hub, 4);
                    zones[k] = st->pairs[k].zone;
                }
                snprintf(key, sizeof(key), "Set%uHubs", (unsigned)i);
                flipper_format_write_hex(ff, key, hubs, (size_t)st->n_pairs * 4);
                snprintf(key, sizeof(key), "Set%uZones", (unsigned)i);
                flipper_format_write_hex(ff, key, zones, st->n_pairs);
            }
            v = st->level;
            snprintf(key, sizeof(key), "Set%uLevel", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
            v = st->fade_idx;
            snprintf(key, sizeof(key), "Set%uFade", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
        }
    } else {
        FURI_LOG_W(TAG, "config save failed");
    }
    flipper_format_free(ff);
}

static void config_load(App* app) {
    config_defaults(&app->cfg);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    FuriString* name = furi_string_alloc();
    do {
        uint32_t version = 0;
        if(!flipper_format_file_open_existing(ff, CONFIG_PATH)) break;
        if(!flipper_format_read_header(ff, name, &version)) break;
        if(furi_string_cmp_str(name, CONFIG_MAGIC) != 0) break;
        AppConfig* c = &app->cfg;
        uint32_t v;
        if(flipper_format_read_uint32(ff, "System", &v, 1) && v <= SystemBridge) c->system = (uint8_t)v;
        flipper_format_read_hex(ff, "Hub", c->hub, 4);
        flipper_format_read_hex(ff, "Zone", &c->zone, 1);
        if(flipper_format_read_uint32(ff, "NZones", &v, 1) && v <= MAX_TARGETS) {
            c->n_zones = (uint8_t)v;
            if(v && !flipper_format_read_hex(ff, "Zones", c->zones, (size_t)v)) c->n_zones = 0;
        }
        flipper_format_read_hex(ff, "Target", c->target, 4);
        flipper_format_read_hex(ff, "Pico", c->pico, 4);
        if(flipper_format_read_uint32(ff, "NTargets", &v, 1) && v <= MAX_TARGETS) {
            c->n_targets = (uint8_t)v;
            if(v && !flipper_format_read_hex(ff, "Targets", &c->targets[0][0], (size_t)v * 4)) {
                c->n_targets = 0;
            }
        }
        if(flipper_format_read_uint32(ff, "ChannelIdx", &v, 1) && v < N_CHANNELS) c->channel_idx = (uint8_t)v;
        if(flipper_format_read_uint32(ff, "Slot", &v, 1) && v < 8) c->slot = (uint8_t)v;
        if(flipper_format_read_uint32(ff, "Repeats", &v, 1) && v >= 1 && v <= 16) c->repeats = (uint8_t)v;
        if(flipper_format_read_uint32(ff, "Level", &v, 1) && v <= 100) c->level = (uint8_t)v;
        if(flipper_format_read_uint32(ff, "FadeIdx", &v, 1) && v < N_FADES) c->fade_idx = (uint8_t)v;
        if(flipper_format_read_uint32(ff, "LogRx", &v, 1)) c->log_rx = (v != 0);
        if(flipper_format_read_uint32(ff, "ShowBad", &v, 1)) c->show_bad = (v != 0);
        /* Light sets. Rewind first: a key missing above leaves the stream at end of file. */
        flipper_format_rewind(ff);
        if(flipper_format_read_uint32(ff, "NSets", &v, 1) && v <= MAX_SETS) {
            uint32_t n_sets = v;
            char key[20];
            for(uint8_t i = 0; i < n_sets; i++) {
                LightSet* st = &c->sets[c->n_sets];
                memset(st, 0, sizeof(*st));
                st->level = 50;
                st->fade_idx = 1;
                snprintf(key, sizeof(key), "Set%uName", (unsigned)i);
                if(!flipper_format_read_string(ff, key, name)) break;
                snprintf(st->name, sizeof(st->name), "%s", furi_string_get_cstr(name));
                snprintf(key, sizeof(key), "Set%uNPairs", (unsigned)i);
                if(!flipper_format_read_uint32(ff, key, &v, 1) || v > MAX_PAIRS) break;
                if(v) {
                    uint8_t hubs[MAX_PAIRS * 4];
                    uint8_t zones[MAX_PAIRS];
                    snprintf(key, sizeof(key), "Set%uHubs", (unsigned)i);
                    if(!flipper_format_read_hex(ff, key, hubs, (size_t)v * 4)) break;
                    snprintf(key, sizeof(key), "Set%uZones", (unsigned)i);
                    if(!flipper_format_read_hex(ff, key, zones, (size_t)v)) break;
                    st->n_pairs = (uint8_t)v;
                    for(uint8_t k = 0; k < st->n_pairs; k++) {
                        memcpy(st->pairs[k].hub, hubs + k * 4, 4);
                        st->pairs[k].zone = zones[k];
                    }
                }
                snprintf(key, sizeof(key), "Set%uLevel", (unsigned)i);
                if(flipper_format_read_uint32(ff, key, &v, 1) && v <= 100) st->level = (uint8_t)v;
                snprintf(key, sizeof(key), "Set%uFade", (unsigned)i);
                if(flipper_format_read_uint32(ff, key, &v, 1) && v < N_FADES) st->fade_idx = (uint8_t)v;
                c->n_sets++;
            }
        } else {
            /* Configs from before light sets kept one global pairs list: turn it into a set. */
            flipper_format_rewind(ff);
            if(flipper_format_read_uint32(ff, "NPairs", &v, 1) && v > 0 && v <= MAX_PAIRS) {
                uint8_t hubs[MAX_PAIRS * 4];
                uint8_t zones[MAX_PAIRS];
                if(flipper_format_read_hex(ff, "PairHubs", hubs, (size_t)v * 4) &&
                   flipper_format_read_hex(ff, "PairZones", zones, (size_t)v)) {
                    LightSet* st = &c->sets[0];
                    memset(st, 0, sizeof(*st));
                    snprintf(st->name, sizeof(st->name), "Lights");
                    st->level = c->level;
                    st->fade_idx = c->fade_idx;
                    st->n_pairs = (uint8_t)v;
                    for(uint8_t k = 0; k < st->n_pairs; k++) {
                        memcpy(st->pairs[k].hub, hubs + k * 4, 4);
                        st->pairs[k].zone = zones[k];
                    }
                    c->n_sets = 1;
                }
            }
        }
    } while(false);
    furi_string_free(name);
    flipper_format_free(ff);
    app->target_sel = app->cfg.n_targets; /* manual target by default */
    app->zone_sel = app->cfg.n_zones;
}

/* ------------------------------------------------------------------ TX */

static uint8_t next_type_byte(App* app, uint8_t base) {
    /* Hubs rotate the type byte between commands: 0x81/82/83 (bridge), 0x89/8A/8B (Vive). */
    uint8_t t = (uint8_t)(base + (app->type_rot % 3));
    app->type_rot++;
    return t;
}

static void request_tx_level(App* app, uint8_t pct) {
    if(app->tx_pending) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    TxPhase* ph = &app->tx_phase[0];
    if(app->cfg.system == SystemVive) {
        ph->len = (uint8_t)cca_build_vive_level(
            ph->pkt,
            app->cfg.hub,
            current_zone(app),
            cca_pct_to_level16(pct),
            FADE_QS[app->cfg.fade_idx],
            next_type_byte(app, 0x89));
    } else {
        ph->len = (uint8_t)cca_build_set_level(
            ph->pkt,
            app->cfg.hub,
            current_target(app),
            cca_pct_to_level16(pct),
            FADE_QS[app->cfg.fade_idx],
            next_type_byte(app, 0x81));
    }
    ph->repeats = app->cfg.repeats;
    app->tx_nphases = 1;
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
}

static bool tx_busy(App* app) {
    return app->tx_pending || app->pico_batch_active || app->target_batch_active;
}

/*
 * Light set level: one Vive level command per light in the set, all with the same type byte.
 * The worker interleaves them (copy 1 of every light, then copy 2, ...) so every light switches
 * within the first pass instead of waiting for earlier lights' full bursts.
 */
static bool request_tx_set_level(App* app, const LightSet* set, uint8_t pct) {
    if(tx_busy(app) || set->n_pairs == 0) return false;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t type_byte = next_type_byte(app, 0x89);
    for(uint8_t i = 0; i < set->n_pairs; i++) {
        TxPhase* ph = &app->tx_phase[i];
        ph->len = (uint8_t)cca_build_vive_level(
            ph->pkt,
            set->pairs[i].hub,
            set->pairs[i].zone,
            cca_pct_to_level16(pct),
            FADE_QS[set->fade_idx],
            type_byte);
        ph->repeats = app->cfg.repeats;
        ph->group = 0;
    }
    app->tx_nphases = set->n_pairs;
    app->tx_interleave = true;
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
    return true;
}

/*
 * Light set raise/lower: the documented Vive two-phase dim for every light. All hold-starts go
 * out first (group 0, interleaved), then all dim steps (group 1), since a dimmer ignores steps
 * that are not preceded by a hold-start.
 */
static bool request_tx_set_dim(App* app, const LightSet* set, bool raise) {
    if(tx_busy(app) || set->n_pairs == 0) return false;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t type_byte = next_type_byte(app, 0x89);
    uint8_t n = set->n_pairs;
    for(uint8_t i = 0; i < n; i++) {
        TxPhase* hold = &app->tx_phase[i];
        hold->len = (uint8_t)cca_build_vive_dim(
            hold->pkt, set->pairs[i].hub, set->pairs[i].zone, raise, true, type_byte);
        hold->repeats = VIVE_HOLD_REPEATS;
        hold->group = 0;
        TxPhase* step = &app->tx_phase[n + i];
        step->len = (uint8_t)cca_build_vive_dim(
            step->pkt, set->pairs[i].hub, set->pairs[i].zone, raise, false, type_byte);
        step->repeats = VIVE_STEP_REPEATS;
        step->group = 1;
    }
    app->tx_nphases = (uint8_t)(n * 2);
    app->tx_interleave = true;
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
    return true;
}

static void request_tx_dim(App* app, bool raise) {
    if(app->tx_pending) return;
    if(app->cfg.system != SystemVive) {
        /* Bridge raise/lower is not documented in the repo; only Vive's two-phase dim is. */
        notification_message(app->notif, &sequence_error);
        return;
    }
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t type_byte = next_type_byte(app, 0x89);
    uint8_t zone = current_zone(app);
    /* Phase 1: hold-start (required, otherwise the dimmer ignores the steps). Phase 2: dim steps. */
    app->tx_phase[0].len =
        (uint8_t)cca_build_vive_dim(app->tx_phase[0].pkt, app->cfg.hub, zone, raise, true, type_byte);
    app->tx_phase[0].repeats = VIVE_HOLD_REPEATS;
    app->tx_phase[1].len =
        (uint8_t)cca_build_vive_dim(app->tx_phase[1].pkt, app->cfg.hub, zone, raise, false, type_byte);
    app->tx_phase[1].repeats = VIVE_STEP_REPEATS;
    app->tx_nphases = 2;
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
}

static void prepare_tx_pico_button(
    App* app,
    const uint8_t device_id[4],
    uint8_t button,
    uint8_t press_action) {
    uint8_t press_type = next_type_byte(app, 0x88);
    uint8_t release_type = next_type_byte(app, 0x88);
    app->tx_phase[0].len =
        (uint8_t)cca_build_button_short(
            app->tx_phase[0].pkt, device_id, button, press_action, press_type);
    app->tx_phase[0].repeats = app->cfg.repeats;
    app->tx_phase[1].len =
        (uint8_t)cca_build_button_long(app->tx_phase[1].pkt, device_id, button, release_type);
    app->tx_phase[1].repeats = app->cfg.repeats;
    app->tx_nphases = 2;
}

static void request_tx_pico_button(App* app, uint8_t button) {
    if(app->tx_pending) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    prepare_tx_pico_button(app, app->cfg.pico, button, 0x00);
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
}

static void start_pico_off_batch(App* app) {
    if(app->tx_pending || app->pico_batch_active || app->target_batch_active ||
       PICO_OFF_ID_COUNT == 0 ||
       PICO_OFF_ID_COUNT > MAX_PICO_OFF_IDS)
        return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->pico_batch_index = 0;
    app->pico_batch_cancel = false;
    app->pico_batch_active = true;
    prepare_tx_pico_button(app, PICO_OFF_IDS[0], 0x04, 0x06);
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
}

static void stop_pico_off_batch(App* app) {
    app->pico_batch_cancel = true;
}

static void prepare_tx_target_off(App* app, const uint8_t target[4]) {
    app->tx_phase[0].len =
        (uint8_t)cca_build_set_level(
            app->tx_phase[0].pkt,
            app->cfg.hub,
            target,
            cca_pct_to_level16(0),
            FADE_QS[app->cfg.fade_idx],
            next_type_byte(app, 0x81));
    app->tx_phase[0].repeats = app->cfg.repeats;
    app->tx_nphases = 1;
}

static void start_target_off_batch(App* app) {
    if(app->cfg.system != SystemBridge) {
        notification_message(app->notif, &sequence_error);
        return;
    }
    if(app->tx_pending || app->target_batch_active || app->pico_batch_active ||
       PICO_OFF_ID_COUNT == 0 ||
       PICO_OFF_ID_COUNT > MAX_PICO_OFF_IDS)
        return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->target_batch_index = 0;
    app->target_batch_cancel = false;
    app->target_batch_active = true;
    prepare_tx_target_off(app, PICO_OFF_IDS[0]);
    furi_mutex_release(app->mutex);
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
}

static void stop_target_off_batch(App* app) {
    app->target_batch_cancel = true;
}

/* Sends one copy of a phase's packet, then waits out the rest of the 75 ms frame. */
static bool tx_send_one(App* app, TxPhase* ph, uint8_t slot, uint8_t* enc, size_t enc_cap, uint32_t* next) {
    /* seq[2:0] = TDMA slot, seq[7:3] = retransmit counter */
    ph->pkt[1] = (uint8_t)(slot | ((app->seq_counter++ & 0x1F) << 3));
    cca_append_crc(ph->pkt, ph->len);
    size_t n = cca_n81_encode(ph->pkt, (size_t)ph->len + 2, enc, enc_cap);
    if(n == 0 || !cca_radio_transmit(enc, n)) return false;
    *next += FRAME_MS;
    int32_t wait = (int32_t)(*next - furi_get_tick());
    if(wait > 0) furi_delay_ms((uint32_t)wait);
    return true;
}

static void worker_do_tx(App* app) {
    TxPhase* phases = app->tx_work;
    uint8_t enc[CCA_ENC_MAX];

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    uint8_t nphases = app->tx_nphases < MAX_TX_PHASES ? app->tx_nphases : MAX_TX_PHASES;
    bool interleave = app->tx_interleave;
    app->tx_interleave = false; /* one-shot: batch continuations below are sequential */
    uint8_t slot = app->cfg.slot & 7;
    memcpy(phases, app->tx_phase, sizeof(TxPhase) * nphases);
    furi_mutex_release(app->mutex);

    bool ok = true;
    uint32_t next = furi_get_tick();
    uint16_t sent = 0;
    if(interleave) {
        /* Phases sharing a group are interleaved; groups run one after another. */
        uint8_t start = 0;
        while(start < nphases && ok) {
            uint8_t end = start;
            uint8_t max_rep = 0;
            while(end < nphases && phases[end].group == phases[start].group) {
                if(phases[end].repeats > max_rep) max_rep = phases[end].repeats;
                end++;
            }
            for(uint8_t r = 0; r < max_rep && ok; r++) {
                for(uint8_t p = start; p < end && ok; p++) {
                    if(r >= phases[p].repeats) continue;
                    ok = tx_send_one(app, &phases[p], slot, enc, sizeof(enc), &next);
                    if(ok) sent++;
                }
            }
            start = end;
        }
    } else {
        for(uint8_t p = 0; p < nphases && ok; p++) {
            for(uint8_t i = 0; i < phases[p].repeats && ok; i++) {
                ok = tx_send_one(app, &phases[p], slot, enc, sizeof(enc), &next);
                if(ok) sent++;
            }
        }
    }

    app->tx_pending = false;
    if(app->pico_batch_active && !app->pico_batch_cancel) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->pico_batch_index = (uint8_t)((app->pico_batch_index + 1) % PICO_OFF_ID_COUNT);
        prepare_tx_pico_button(app, PICO_OFF_IDS[app->pico_batch_index], 0x04, 0x06);
        furi_mutex_release(app->mutex);
        app->tx_pending = true;
    } else if(app->target_batch_active && !app->target_batch_cancel) {
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        app->target_batch_index = (uint8_t)((app->target_batch_index + 1) % PICO_OFF_ID_COUNT);
        prepare_tx_target_off(app, PICO_OFF_IDS[app->target_batch_index]);
        furi_mutex_release(app->mutex);
        app->tx_pending = true;
    } else {
        app->pico_batch_active = false;
        app->pico_batch_cancel = false;
        app->target_batch_active = false;
        app->target_batch_cancel = false;
    }
    notification_message(app->notif, &sequence_blink_stop);
    notification_message(app->notif, ok ? &sequence_success : &sequence_error);
    FURI_LOG_I(
        TAG, "TX %s (%u packets, %u phases)", ok ? "ok" : "FAILED", (unsigned)sent, (unsigned)nphases);
}

/* ------------------------------------------------------------------ RX */

static void log_packet(App* app, const CcaPacket* p, int8_t rssi, uint32_t tick) {
    if(!app->log_file) return;
    char line[16 + CCA_MAX_PKT * 3 + 32];
    int n = snprintf(
        line,
        sizeof(line),
        "%lu rssi=%d crc=%s err=%u ",
        (unsigned long)tick,
        (int)rssi,
        p->crc_ok ? "ok" : "bad",
        (unsigned)p->n81_errors);
    for(uint8_t i = 0; i < p->len && n < (int)sizeof(line) - 4; i++) {
        n += snprintf(line + n, sizeof(line) - (size_t)n, "%02x", p->raw[i]);
    }
    if(n < (int)sizeof(line) - 1) line[n++] = '\n';
    storage_file_write(app->log_file, line, (size_t)n);
}

static void worker_handle_rx(App* app, const uint8_t* fifo, size_t len, int8_t rssi) {
    CcaPacket p;
    if(!cca_decode(fifo, len, &p)) return;
    uint32_t tick = furi_get_tick();
    bool show = p.crc_ok || app->cfg.show_bad;

    with_view_model(
        app->sniff_view,
        SniffModel * model,
        {
            model->total++;
            if(!p.crc_ok) model->crc_bad++;
            if(show) {
                SniffEntry* e = &model->ring[model->head];
                e->pkt = p;
                e->rssi = rssi;
                e->tick = tick;
                model->head = (uint8_t)((model->head + 1) % SNIFF_RING);
                if(model->count < SNIFF_RING) model->count++;
                if(model->selected > 0 && model->selected < model->count - 1) model->selected++;
            }
        },
        show);

    if(p.crc_ok) notification_message(app->notif, &sequence_blink_green_10);
    log_packet(app, &p, rssi, tick);
}

static int32_t worker_thread(void* ctx) {
    App* app = ctx;
    uint8_t fifo[CCA_RX_LEN + 4];
    size_t fifo_len = 0;
    int8_t rssi = 0;

    while(app->running) {
        if(app->tx_pending) {
            worker_do_tx(app);
            continue;
        }
        if(app->rx_enabled) {
            if(!cca_radio_rx_active()) cca_radio_start_rx();
            if(cca_radio_poll_rx(fifo, sizeof(fifo), &fifo_len, &rssi)) {
                worker_handle_rx(app, fifo, fifo_len, rssi);
            }
            furi_delay_ms(1);
        } else {
            if(cca_radio_rx_active()) cca_radio_stop_rx();
            furi_delay_ms(5);
        }
    }
    if(cca_radio_rx_active()) cca_radio_stop_rx();
    return 0;
}

/* ------------------------------------------------------------------ learn */

static const char* learn_from_packet(App* app, const CcaPacket* p) {
    const uint8_t* r = p->raw;
    uint8_t t = p->type;
    uint8_t f = p->has_format ? p->format : 0;
    if(!p->crc_ok) return "CRC bad: not saved";

    if(cca_is_vive_cmd(p)) {
        /* Vive hub command: hub ID at bytes 2..5, zone at byte 12. */
        memcpy(app->cfg.hub, r + 2, 4);
        app->cfg.zone = r[12];
        add_zone(app, r[12]);
        app->cfg.system = SystemVive;
        config_save(app);
        return "Saved Vive hub + zone";
    }
    if(cca_is_bridge_cmd(p)) {
        /* Caseta/RA3 SET_LEVEL: source bytes 2..5 and target bytes 9..12, verbatim. */
        memcpy(app->cfg.hub, r + 2, 4);
        memcpy(app->cfg.target, r + 9, 4);
        add_target(app, r + 9);
        app->cfg.system = SystemBridge;
        config_save(app);
        return "Saved hub + target";
    }
    if(t >= 0x81 && t <= 0x83 && f == 0x08) {
        /* Dimmer state report: load ID = RF transmit ID XOR 0x20000008 (docs/devices/index.md). */
        uint8_t id[4] = {(uint8_t)(r[2] ^ 0x20), r[3], r[4], (uint8_t)(r[5] ^ 0x08)};
        memcpy(app->cfg.target, id, 4);
        add_target(app, id);
        config_save(app);
        return "Saved target (xor)";
    }
    if(t >= 0x91 && t <= 0x93) {
        memcpy(app->cfg.hub, r + 2, 4);
        config_save(app);
        return "Saved hub ID";
    }
    if((t == 0xB9 || t == 0xBA) && p->len >= 24 && f == 0x11) {
        /* Vive hub pairing beacon (format 0x11): hub ID at bytes 2..5. */
        memcpy(app->cfg.hub, r + 2, 4);
        config_save(app);
        return "Saved Vive hub ID";
    }
    return "No IDs in this packet";
}

/* ------------------------------------------------------------------ sniff view */

static const SniffEntry* model_entry(const SniffModel* m, uint8_t idx_from_newest) {
    int i = (int)m->head - 1 - (int)idx_from_newest;
    while(i < 0) i += SNIFF_RING;
    return &m->ring[i % SNIFF_RING];
}

static void sniff_draw(Canvas* canvas, void* ctx) {
    SniffModel* m = ctx;
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);

    char line[48];
    snprintf(
        line,
        sizeof(line),
        "%s  n=%lu bad=%lu",
        m->status,
        (unsigned long)m->total,
        (unsigned long)m->crc_bad);
    canvas_draw_str(canvas, 0, 8, line);
    canvas_draw_line(canvas, 0, 10, 127, 10);

    if(m->count == 0) {
        canvas_draw_str(canvas, 0, 24, "Listening...");
        canvas_draw_str(canvas, 0, 36, "Tap a Pico or dimmer,");
        canvas_draw_str(canvas, 0, 46, "or press the hub button.");
        return;
    }

    if(m->detail) {
        const SniffEntry* e = model_entry(m, m->selected);
        const CcaPacket* p = &e->pkt;
        char rows[12][28];
        uint8_t nrows = 0;
        snprintf(
            rows[nrows++],
            28,
            "t%02X f%02X s%02X %s %ddB",
            (unsigned)p->type,
            (unsigned)(p->has_format ? p->format : 0),
            (unsigned)p->seq,
            p->crc_ok ? "ok" : "BAD",
            (int)e->rssi);
        if(cca_is_vive_cmd(p)) {
            snprintf(
                rows[nrows++],
                28,
                "hub %02X%02X%02X%02X zone %02X",
                p->raw[2],
                p->raw[3],
                p->raw[4],
                p->raw[5],
                p->raw[12]);
        } else if(p->len >= 13) {
            snprintf(
                rows[nrows++],
                28,
                "src %02X%02X%02X%02X tgt %02X%02X%02X%02X",
                p->raw[2],
                p->raw[3],
                p->raw[4],
                p->raw[5],
                p->raw[9],
                p->raw[10],
                p->raw[11],
                p->raw[12]);
        }
        for(uint8_t off = 0; off < p->len && nrows < 12; off += 8) {
            int n = 0;
            for(uint8_t j = 0; j < 8 && off + j < p->len; j++) {
                n += snprintf(rows[nrows] + n, 28 - (size_t)n, "%02X ", p->raw[off + j]);
            }
            nrows++;
        }
        uint8_t start = m->detail_scroll;
        if(start + 5 > nrows) start = nrows > 5 ? nrows - 5 : 0;
        for(uint8_t i = 0; i < 5 && start + i < nrows; i++) {
            canvas_draw_str(canvas, 0, 20 + i * 10, rows[start + i]);
        }
        return;
    }

    uint8_t start = m->selected > 4 ? m->selected - 4 : 0;
    for(uint8_t row = 0; row < 5 && start + row < m->count; row++) {
        const SniffEntry* e = model_entry(m, start + row);
        char desc[32];
        cca_describe(&e->pkt, desc, sizeof(desc));
        if(start + row == m->selected) canvas_draw_str(canvas, 0, 20 + row * 10, ">");
        canvas_draw_str(canvas, 6, 20 + row * 10, desc);
        if(!e->pkt.crc_ok) canvas_draw_str(canvas, 120, 20 + row * 10, "?");
    }
}

static bool sniff_input(InputEvent* event, void* ctx) {
    App* app = ctx;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;
    if(event->key == InputKeyBack) return false;

    bool learned = false;
    const char* msg = NULL;
    CcaPacket sel;
    bool have_sel = false;

    with_view_model(
        app->sniff_view,
        SniffModel * m,
        {
            if(event->key == InputKeyUp) {
                if(m->detail) {
                    if(m->detail_scroll > 0) m->detail_scroll--;
                } else if(m->selected > 0) {
                    m->selected--;
                }
            } else if(event->key == InputKeyDown) {
                if(m->detail) {
                    m->detail_scroll++;
                } else if(m->count && m->selected < m->count - 1) {
                    m->selected++;
                }
            } else if(event->key == InputKeyLeft || event->key == InputKeyRight) {
                m->detail = !m->detail;
                m->detail_scroll = 0;
            } else if(event->key == InputKeyOk && m->count) {
                sel = model_entry(m, m->selected)->pkt;
                have_sel = true;
            }
        },
        true);

    if(have_sel) {
        msg = learn_from_packet(app, &sel);
        learned = true;
    }
    if(learned) {
        with_view_model(
            app->sniff_view, SniffModel * m, { snprintf(m->status, sizeof(m->status), "%s", msg); }, true);
        notification_message(app->notif, &sequence_single_vibro);
    }
    return true;
}

static void sniff_enter(void* ctx) {
    App* app = ctx;
    if(app->cfg.log_rx && !app->log_file) {
        storage_common_mkdir(app->storage, STORAGE_APP_DATA_PATH_PREFIX);
        app->log_file = storage_file_alloc(app->storage);
        if(!storage_file_open(app->log_file, LOG_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            storage_file_free(app->log_file);
            app->log_file = NULL;
        }
    }
    with_view_model(
        app->sniff_view,
        SniffModel * m,
        {
            snprintf(
                m->status,
                sizeof(m->status),
                "RX ch%u %s%s",
                (unsigned)CHANNELS[app->cfg.channel_idx],
                app->cfg.system == SystemVive ? "Vive" : "Bridge",
                app->radio_ok ? "" : " NO RADIO");
        },
        true);
    app->rx_enabled = app->radio_ok;
}

static void sniff_exit(void* ctx) {
    App* app = ctx;
    app->rx_enabled = false;
    if(app->log_file) {
        storage_file_close(app->log_file);
        storage_file_free(app->log_file);
        app->log_file = NULL;
    }
}

/* ------------------------------------------------------------------ control view */

static void control_refresh(App* app) {
    char buf[24];
    if(app->zone_sel < app->cfg.n_zones) {
        snprintf(buf, sizeof(buf), "%02X", (unsigned)app->cfg.zones[app->zone_sel]);
    } else {
        snprintf(buf, sizeof(buf), "%02X*", (unsigned)app->cfg.zone);
    }
    variable_item_set_values_count(app->item_zone, (uint8_t)(app->cfg.n_zones + 1));
    variable_item_set_current_value_index(app->item_zone, app->zone_sel);
    variable_item_set_current_value_text(app->item_zone, buf);

    if(app->target_sel < app->cfg.n_targets) {
        hex4_str(app->cfg.targets[app->target_sel], buf, sizeof(buf));
    } else {
        char h[12];
        hex4_str(app->cfg.target, h, sizeof(h));
        snprintf(buf, sizeof(buf), "%s*", h);
    }
    variable_item_set_values_count(app->item_target, (uint8_t)(app->cfg.n_targets + 1));
    variable_item_set_current_value_index(app->item_target, app->target_sel);
    variable_item_set_current_value_text(app->item_target, buf);

    snprintf(buf, sizeof(buf), "%u%%", (unsigned)app->cfg.level);
    variable_item_set_current_value_index(app->item_level, app->cfg.level / 5);
    variable_item_set_current_value_text(app->item_level, buf);

    variable_item_set_current_value_index(app->item_fade, app->cfg.fade_idx);
    variable_item_set_current_value_text(app->item_fade, FADE_NAMES[app->cfg.fade_idx]);
}

static void control_zone_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->zone_sel = variable_item_get_current_value_index(item);
    control_refresh(app);
}

static void control_target_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->target_sel = variable_item_get_current_value_index(item);
    control_refresh(app);
}

static void control_level_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.level = (uint8_t)(variable_item_get_current_value_index(item) * 5);
    control_refresh(app);
}

static void control_fade_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.fade_idx = variable_item_get_current_value_index(item);
    control_refresh(app);
}

static void control_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    switch(index) {
    case CtrlSendLevel:
        request_tx_level(app, app->cfg.level);
        break;
    case CtrlSendOn:
        request_tx_level(app, 100);
        break;
    case CtrlSendOff:
        request_tx_level(app, 0);
        break;
    case CtrlPicoOn:
        request_tx_pico_button(app, 0x02);
        break;
    case CtrlPicoOff:
        request_tx_pico_button(app, 0x04);
        break;
    case CtrlPicoOffBatch:
        start_pico_off_batch(app);
        break;
    case CtrlPicoOffStop:
        stop_pico_off_batch(app);
        break;
    case CtrlTargetOffBatch:
        start_target_off_batch(app);
        break;
    case CtrlTargetOffStop:
        stop_target_off_batch(app);
        break;
    case CtrlRaise:
        request_tx_dim(app, true);
        break;
    case CtrlLower:
        request_tx_dim(app, false);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ settings view */

static void settings_refresh(App* app) {
    char buf[24];
    variable_item_set_current_value_index(app->item_system, app->cfg.system);
    variable_item_set_current_value_text(app->item_system, SYSTEM_NAMES[app->cfg.system]);
    hex4_str(app->cfg.hub, buf, sizeof(buf));
    variable_item_set_current_value_text(app->item_hub, buf);
    snprintf(buf, sizeof(buf), "%02X", (unsigned)app->cfg.zone);
    variable_item_set_current_value_text(app->item_zone_setting, buf);
    variable_item_set_current_value_index(app->item_show_bad, app->cfg.show_bad ? 1 : 0);
    variable_item_set_current_value_text(app->item_show_bad, app->cfg.show_bad ? "On" : "Off");
    hex4_str(app->cfg.target, buf, sizeof(buf));
    variable_item_set_current_value_text(app->item_tgt, buf);
    hex4_str(app->cfg.pico, buf, sizeof(buf));
    variable_item_set_current_value_text(app->item_pico, buf);

    uint32_t f = channel_freq_hz(CHANNELS[app->cfg.channel_idx]);
    snprintf(
        buf,
        sizeof(buf),
        "%u %lu.%03lu",
        (unsigned)CHANNELS[app->cfg.channel_idx],
        (unsigned long)(f / 1000000u),
        (unsigned long)((f / 1000u) % 1000u));
    variable_item_set_current_value_index(app->item_channel, app->cfg.channel_idx);
    variable_item_set_current_value_text(app->item_channel, buf);

    snprintf(buf, sizeof(buf), "%u", (unsigned)app->cfg.slot);
    variable_item_set_current_value_index(app->item_slot, app->cfg.slot);
    variable_item_set_current_value_text(app->item_slot, buf);

    snprintf(buf, sizeof(buf), "%u", (unsigned)app->cfg.repeats);
    variable_item_set_current_value_index(app->item_repeats, (uint8_t)(app->cfg.repeats - 1));
    variable_item_set_current_value_text(app->item_repeats, buf);

    variable_item_set_current_value_index(app->item_log, app->cfg.log_rx ? 1 : 0);
    variable_item_set_current_value_text(app->item_log, app->cfg.log_rx ? "On" : "Off");
}

static void settings_system_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.system = variable_item_get_current_value_index(item);
    settings_refresh(app);
    control_refresh(app);
    config_save(app);
}

static void settings_show_bad_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.show_bad = variable_item_get_current_value_index(item) != 0;
    settings_refresh(app);
    config_save(app);
}

static void settings_channel_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.channel_idx = variable_item_get_current_value_index(item);
    if(app->radio_ok) cca_radio_set_frequency(channel_freq_hz(CHANNELS[app->cfg.channel_idx]));
    settings_refresh(app);
    config_save(app);
}

static void settings_slot_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.slot = variable_item_get_current_value_index(item);
    settings_refresh(app);
    config_save(app);
}

static void settings_repeats_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.repeats = (uint8_t)(variable_item_get_current_value_index(item) + 1);
    settings_refresh(app);
    config_save(app);
}

static void settings_log_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    app->cfg.log_rx = variable_item_get_current_value_index(item) != 0;
    settings_refresh(app);
    config_save(app);
}

static void export_raw_log(App* app) {
    File* input = storage_file_alloc(app->storage);
    File* output = storage_file_alloc(app->storage);
    bool ok = storage_file_open(input, LOG_PATH, FSAM_READ, FSOM_OPEN_EXISTING) &&
              storage_file_open(output, RAW_EXPORT_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    char line[16 + CCA_MAX_PKT * 3 + 32];
    size_t line_len = 0;

    if(ok) {
        uint8_t byte;
        while(storage_file_read(input, &byte, 1) == 1) {
            if(byte == '\n' || line_len == sizeof(line) - 1) {
                line[line_len] = '\0';
                char* raw = strrchr(line, ' ');
                if(raw && raw[1] != '\0') {
                    raw++;
                    storage_file_write(output, raw, strlen(raw));
                    storage_file_write(output, "\n", 1);
                }
                line_len = 0;
            } else if(byte != '\r') {
                line[line_len++] = (char)byte;
            }
        }
        if(line_len > 0) {
            line[line_len] = '\0';
            char* raw = strrchr(line, ' ');
            if(raw && raw[1] != '\0') {
                raw++;
                storage_file_write(output, raw, strlen(raw));
                storage_file_write(output, "\n", 1);
            }
        }
    } else {
        FURI_LOG_W(TAG, "raw export open failed");
    }

    if(ok) {
        storage_file_close(input);
        storage_file_close(output);
        notification_message(app->notif, &sequence_success);
    } else {
        if(storage_file_is_open(input)) storage_file_close(input);
        if(storage_file_is_open(output)) storage_file_close(output);
        notification_message(app->notif, &sequence_error);
    }
    storage_file_free(input);
    storage_file_free(output);
}

static void byte_input_done(void* ctx) {
    App* app = ctx;
    if(app->byte_dest) memcpy(app->byte_dest, app->byte_buf, app->byte_len);
    app->byte_dest = NULL;
    config_save(app);
    settings_refresh(app);
    control_refresh(app);
    view_dispatcher_switch_to_view(app->vd, ViewIdSettings);
}

static void settings_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    switch(index) {
    case SetHub:
        app->byte_dest = app->cfg.hub;
        app->byte_len = 4;
        memcpy(app->byte_buf, app->cfg.hub, 4);
        byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->byte_buf, 4);
        byte_input_set_header_text(app->byte_input, "Hub ID (pkt bytes 2-5)");
        view_dispatcher_switch_to_view(app->vd, ViewIdByteInput);
        break;
    case SetZone:
        app->byte_dest = &app->cfg.zone;
        app->byte_len = 1;
        app->byte_buf[0] = app->cfg.zone;
        byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->byte_buf, 1);
        byte_input_set_header_text(app->byte_input, "Vive zone (pkt byte 12)");
        view_dispatcher_switch_to_view(app->vd, ViewIdByteInput);
        break;
    case SetTarget:
        app->byte_dest = app->cfg.target;
        app->byte_len = 4;
        memcpy(app->byte_buf, app->cfg.target, 4);
        byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->byte_buf, 4);
        byte_input_set_header_text(app->byte_input, "Target ID (pkt bytes 9-12)");
        view_dispatcher_switch_to_view(app->vd, ViewIdByteInput);
        break;
    case SetPico:
        app->byte_dest = app->cfg.pico;
        app->byte_len = 4;
        memcpy(app->byte_buf, app->cfg.pico, 4);
        byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->byte_buf, 4);
        byte_input_set_header_text(app->byte_input, "Pico ID (button source)");
        view_dispatcher_switch_to_view(app->vd, ViewIdByteInput);
        break;
    case SetClearDevices:
        app->cfg.n_targets = 0;
        app->target_sel = 0;
        app->cfg.n_zones = 0;
        app->zone_sel = 0;
        config_save(app);
        control_refresh(app);
        notification_message(app->notif, &sequence_single_vibro);
        break;
    case SetExportRaw:
        export_raw_log(app);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ light sets */

static void sets_menu_callback(void* ctx, uint32_t index);
static void pairs_menu_callback(void* ctx, uint32_t index);
static void set_control_enter(void* ctx, uint32_t index);

static LightSet* cur_set(App* app) {
    if(app->set_sel >= app->cfg.n_sets) app->set_sel = 0;
    return &app->cfg.sets[app->set_sel];
}

static void sets_rebuild(App* app) {
    submenu_reset(app->sets_menu);
    submenu_set_header(app->sets_menu, "Light sets");
    for(uint8_t i = 0; i < app->cfg.n_sets; i++) {
        submenu_add_item(app->sets_menu, app->cfg.sets[i].name, i, sets_menu_callback, app);
    }
    if(app->cfg.n_sets < MAX_SETS) {
        submenu_add_item(app->sets_menu, "+ New set", SETS_NEW_INDEX, sets_menu_callback, app);
    }
}

static void set_level_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    LightSet* st = cur_set(app);
    char buf[8];
    st->level = (uint8_t)(variable_item_get_current_value_index(item) * 5);
    snprintf(buf, sizeof(buf), "%u%%", (unsigned)st->level);
    variable_item_set_current_value_text(item, buf);
    config_save(app);
}

static void set_fade_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    LightSet* st = cur_set(app);
    st->fade_idx = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, FADE_NAMES[st->fade_idx]);
    config_save(app);
}

/* Rebuilds the set control screen for the current set and selects row `select`. */
static void set_control_rebuild(App* app, uint8_t select) {
    VariableItemList* l = app->set_control;
    variable_item_list_reset(l);
    variable_item_list_set_enter_callback(l, set_control_enter, app);
    if(app->cfg.n_sets == 0) return;

    LightSet* st = cur_set(app);
    char buf[16];
    app->item_set_name = variable_item_list_add(l, st->name, 1, NULL, app);
    snprintf(buf, sizeof(buf), "%u light%s", (unsigned)st->n_pairs, st->n_pairs == 1 ? "" : "s");
    variable_item_set_current_value_text(app->item_set_name, buf);

    variable_item_list_add(l, "On", 0, NULL, app);
    variable_item_list_add(l, "Off", 0, NULL, app);

    app->item_set_level = variable_item_list_add(l, "Level", 21, set_level_changed, app);
    snprintf(buf, sizeof(buf), "%u%%", (unsigned)st->level);
    variable_item_set_current_value_index(app->item_set_level, st->level / 5);
    variable_item_set_current_value_text(app->item_set_level, buf);

    app->item_set_fade = variable_item_list_add(l, "Fade", N_FADES, set_fade_changed, app);
    variable_item_set_current_value_index(app->item_set_fade, st->fade_idx);
    variable_item_set_current_value_text(app->item_set_fade, FADE_NAMES[st->fade_idx]);

    variable_item_list_add(l, "Send level", 0, NULL, app);
    variable_item_list_add(l, "Raise", 0, NULL, app);
    variable_item_list_add(l, "Lower", 0, NULL, app);
    variable_item_list_add(l, "Edit lights", 0, NULL, app);
    variable_item_list_add(l, "Rename", 0, NULL, app);
    variable_item_list_add(l, "Delete set", 0, NULL, app);
    variable_item_list_set_selected_item(l, select);
}

static void set_name_done(void* ctx);

/* index < n_sets renames that set; index == n_sets names a new one. */
static void set_start_name(App* app, uint8_t index) {
    bool rename = index < app->cfg.n_sets;
    app->set_edit_index = index;
    if(rename) {
        snprintf(app->set_name_buf, sizeof(app->set_name_buf), "%s", app->cfg.sets[index].name);
    } else {
        snprintf(app->set_name_buf, sizeof(app->set_name_buf), "Set %u", (unsigned)(app->cfg.n_sets + 1));
    }
    text_input_set_header_text(app->set_name_input, rename ? "Rename set" : "Name the new set");
    text_input_set_result_callback(
        app->set_name_input, set_name_done, app, app->set_name_buf, sizeof(app->set_name_buf), !rename);
    view_dispatcher_switch_to_view(app->vd, ViewIdSetName);
}

static void pairs_rebuild(App* app);

static void set_name_done(void* ctx) {
    App* app = ctx;
    uint8_t i = app->set_edit_index;
    if(i < app->cfg.n_sets) {
        snprintf(app->cfg.sets[i].name, SET_NAME_LEN, "%s", app->set_name_buf);
        config_save(app);
        sets_rebuild(app);
        set_control_rebuild(app, SetCtlRename);
        view_dispatcher_switch_to_view(app->vd, ViewIdSetControl);
        return;
    }
    if(app->cfg.n_sets >= MAX_SETS) {
        notification_message(app->notif, &sequence_error);
        view_dispatcher_switch_to_view(app->vd, ViewIdSets);
        return;
    }
    LightSet* st = &app->cfg.sets[app->cfg.n_sets];
    memset(st, 0, sizeof(*st));
    snprintf(st->name, sizeof(st->name), "%s", app->set_name_buf);
    st->level = 50;
    st->fade_idx = 1;
    app->set_sel = app->cfg.n_sets++;
    config_save(app);
    sets_rebuild(app);
    set_control_rebuild(app, SetCtlLights);
    /* A new set has no lights yet: go straight to adding them. Back leads to its controls. */
    pairs_rebuild(app);
    view_dispatcher_switch_to_view(app->vd, ViewIdPairs);
}

static void set_confirm_delete(App* app) {
    LightSet* st = cur_set(app);
    snprintf(app->confirm_text, sizeof(app->confirm_text), "Delete \"%s\"?", st->name);
    dialog_ex_set_header(app->confirm_dialog, "Delete set", 64, 2, AlignCenter, AlignTop);
    dialog_ex_set_text(app->confirm_dialog, app->confirm_text, 64, 28, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->confirm_dialog, "Cancel");
    dialog_ex_set_right_button_text(app->confirm_dialog, "Delete");
    view_dispatcher_switch_to_view(app->vd, ViewIdConfirm);
}

static void confirm_dialog_callback(DialogExResult result, void* ctx) {
    App* app = ctx;
    if(result == DialogExResultRight && app->set_sel < app->cfg.n_sets) {
        uint8_t i = app->set_sel;
        memmove(
            &app->cfg.sets[i],
            &app->cfg.sets[i + 1],
            (size_t)(app->cfg.n_sets - i - 1) * sizeof(LightSet));
        app->cfg.n_sets--;
        app->set_sel = 0;
        config_save(app);
        sets_rebuild(app);
        notification_message(app->notif, &sequence_single_vibro);
        view_dispatcher_switch_to_view(app->vd, ViewIdSets);
    } else if(result == DialogExResultLeft) {
        view_dispatcher_switch_to_view(app->vd, ViewIdSetControl);
    }
}

static void set_control_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    if(app->cfg.n_sets == 0) return;
    LightSet* st = cur_set(app);
    bool ok = true;
    switch(index) {
    case SetCtlOn:
        ok = request_tx_set_level(app, st, 100);
        break;
    case SetCtlOff:
        ok = request_tx_set_level(app, st, 0);
        break;
    case SetCtlSendLevel:
        ok = request_tx_set_level(app, st, st->level);
        break;
    case SetCtlRaise:
        ok = request_tx_set_dim(app, st, true);
        break;
    case SetCtlLower:
        ok = request_tx_set_dim(app, st, false);
        break;
    case SetCtlLights:
        pairs_rebuild(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdPairs);
        break;
    case SetCtlRename:
        set_start_name(app, app->set_sel);
        break;
    case SetCtlDelete:
        set_confirm_delete(app);
        break;
    default:
        break;
    }
    /* Refused: a send is already running, or the set has no lights yet. */
    if(!ok) notification_message(app->notif, &sequence_error);
}

static void sets_menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == SETS_NEW_INDEX) {
        if(app->cfg.n_sets < MAX_SETS)
            set_start_name(app, app->cfg.n_sets);
        else
            notification_message(app->notif, &sequence_error);
        return;
    }
    if(index >= app->cfg.n_sets) return;
    app->set_sel = (uint8_t)index;
    set_control_rebuild(app, SetCtlOn);
    view_dispatcher_switch_to_view(app->vd, ViewIdSetControl);
}

/* ------------------------------------------------------------------ set lights (pairs) editor */

static void pairs_rebuild(App* app) {
    LightSet* st = cur_set(app);
    submenu_reset(app->pairs_menu);
    snprintf(
        app->pairs_header,
        sizeof(app->pairs_header),
        "Lights %u/%u",
        (unsigned)st->n_pairs,
        (unsigned)MAX_PAIRS);
    submenu_set_header(app->pairs_menu, app->pairs_header);
    if(st->n_pairs < MAX_PAIRS) {
        submenu_add_item(app->pairs_menu, "+ Add light", PAIRS_ADD_INDEX, pairs_menu_callback, app);
    }
    for(uint8_t i = 0; i < st->n_pairs; i++) {
        const VivePair* pr = &st->pairs[i];
        snprintf(
            app->pair_labels[i],
            sizeof(app->pair_labels[i]),
            "%u: %02X%02X%02X%02X z%02X",
            (unsigned)(i + 1),
            pr->hub[0],
            pr->hub[1],
            pr->hub[2],
            pr->hub[3],
            (unsigned)pr->zone);
        submenu_add_item(app->pairs_menu, app->pair_labels[i], i, pairs_menu_callback, app);
    }
}

static void pair_zone_done(void* ctx) {
    App* app = ctx;
    LightSet* st = cur_set(app);
    VivePair entered;
    memcpy(entered.hub, app->pair_hub_buf, 4);
    entered.zone = app->pair_zone_buf[0];

    uint8_t i = app->pair_edit_index;
    bool adding = i >= st->n_pairs;
    bool duplicate = false;
    for(uint8_t k = 0; k < st->n_pairs; k++) {
        if(k != i && memcmp(st->pairs[k].hub, entered.hub, 4) == 0 && st->pairs[k].zone == entered.zone) {
            duplicate = true;
        }
    }

    if(duplicate || (adding && st->n_pairs >= MAX_PAIRS)) {
        notification_message(app->notif, &sequence_error);
    } else {
        if(adding) i = st->n_pairs++;
        st->pairs[i] = entered;
        config_save(app);
        notification_message(app->notif, &sequence_single_vibro);
    }
    pairs_rebuild(app);
    set_control_rebuild(app, SetCtlLights);
    view_dispatcher_switch_to_view(app->vd, ViewIdPairs);
}

static void pair_hub_done(void* ctx) {
    App* app = ctx;
    byte_input_set_result_callback(
        app->pair_zone_input, pair_zone_done, NULL, app, app->pair_zone_buf, 1);
    byte_input_set_header_text(app->pair_zone_input, "Light zone (pkt byte 12)");
    view_dispatcher_switch_to_view(app->vd, ViewIdPairZone);
}

static void pair_start_edit(App* app, uint8_t index) {
    LightSet* st = cur_set(app);
    app->pair_edit_index = index;
    if(index < st->n_pairs) {
        memcpy(app->pair_hub_buf, st->pairs[index].hub, 4);
        app->pair_zone_buf[0] = st->pairs[index].zone;
    } else {
        /* New light: start from this set's last hub (lights in a set usually share one hub),
         * or the Settings hub for the first light. */
        memcpy(app->pair_hub_buf, st->n_pairs ? st->pairs[st->n_pairs - 1].hub : app->cfg.hub, 4);
        app->pair_zone_buf[0] = app->cfg.zone;
    }
    byte_input_set_result_callback(app->pair_hub_input, pair_hub_done, NULL, app, app->pair_hub_buf, 4);
    byte_input_set_header_text(app->pair_hub_input, "Light hub ID (bytes 2-5)");
    view_dispatcher_switch_to_view(app->vd, ViewIdPairHub);
}

static void pairs_menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    LightSet* st = cur_set(app);
    if(index == PAIRS_ADD_INDEX) {
        if(st->n_pairs < MAX_PAIRS)
            pair_start_edit(app, st->n_pairs);
        else
            notification_message(app->notif, &sequence_error);
        return;
    }
    if(index >= st->n_pairs) return;

    app->pair_sel = (uint8_t)index;
    const VivePair* pr = &st->pairs[index];
    snprintf(
        app->pair_dialog_header,
        sizeof(app->pair_dialog_header),
        "Light %u of %u",
        (unsigned)(index + 1),
        (unsigned)st->n_pairs);
    snprintf(
        app->pair_dialog_text,
        sizeof(app->pair_dialog_text),
        "Hub  %02X%02X%02X%02X\nZone %02X",
        pr->hub[0],
        pr->hub[1],
        pr->hub[2],
        pr->hub[3],
        (unsigned)pr->zone);
    dialog_ex_set_header(app->pair_dialog, app->pair_dialog_header, 64, 2, AlignCenter, AlignTop);
    dialog_ex_set_text(app->pair_dialog, app->pair_dialog_text, 64, 28, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->pair_dialog, "Delete");
    dialog_ex_set_right_button_text(app->pair_dialog, "Edit");
    view_dispatcher_switch_to_view(app->vd, ViewIdPairEdit);
}

static void pair_dialog_callback(DialogExResult result, void* ctx) {
    App* app = ctx;
    LightSet* st = cur_set(app);
    uint8_t i = app->pair_sel;
    if(i >= st->n_pairs) {
        view_dispatcher_switch_to_view(app->vd, ViewIdPairs);
        return;
    }
    if(result == DialogExResultLeft) {
        memmove(&st->pairs[i], &st->pairs[i + 1], (size_t)(st->n_pairs - i - 1) * sizeof(VivePair));
        st->n_pairs--;
        config_save(app);
        pairs_rebuild(app);
        set_control_rebuild(app, SetCtlLights);
        notification_message(app->notif, &sequence_single_vibro);
        view_dispatcher_switch_to_view(app->vd, ViewIdPairs);
    } else if(result == DialogExResultRight) {
        pair_start_edit(app, i);
    }
}

/* ------------------------------------------------------------------ navigation */

static uint32_t nav_exit(void* ctx) {
    UNUSED(ctx);
    return VIEW_NONE;
}

static uint32_t nav_menu(void* ctx) {
    UNUSED(ctx);
    return ViewIdMenu;
}

static uint32_t nav_settings(void* ctx) {
    UNUSED(ctx);
    return ViewIdSettings;
}

static uint32_t nav_pairs(void* ctx) {
    UNUSED(ctx);
    return ViewIdPairs;
}

static uint32_t nav_sets(void* ctx) {
    UNUSED(ctx);
    return ViewIdSets;
}

static uint32_t nav_set_control(void* ctx) {
    UNUSED(ctx);
    return ViewIdSetControl;
}

static void menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    switch(index) {
    case MenuSniff:
        view_dispatcher_switch_to_view(app->vd, ViewIdSniff);
        break;
    case MenuControl:
        control_refresh(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdControl);
        break;
    case MenuSets:
        sets_rebuild(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdSets);
        break;
    case MenuSettings:
        settings_refresh(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdSettings);
        break;
    case MenuAbout:
        view_dispatcher_switch_to_view(app->vd, ViewIdAbout);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ app */

static App* app_alloc(void) {
    App* app = malloc(sizeof(App));
    memset(app, 0, sizeof(App));

    app->gui = furi_record_open(RECORD_GUI);
    app->notif = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);

    config_load(app);

    app->vd = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->vd, app->gui, ViewDispatcherTypeFullscreen);

    /* Menu */
    app->menu = submenu_alloc();
    submenu_set_header(app->menu, "Lutron CCA");
    submenu_add_item(app->menu, "Sniff / Learn", MenuSniff, menu_callback, app);
    submenu_add_item(app->menu, "Control", MenuSets, menu_callback, app);
    submenu_add_item(app->menu, "Control advanced", MenuControl, menu_callback, app);
    submenu_add_item(app->menu, "Settings", MenuSettings, menu_callback, app);
    submenu_add_item(app->menu, "About", MenuAbout, menu_callback, app);
    view_set_previous_callback(submenu_get_view(app->menu), nav_exit);
    view_dispatcher_add_view(app->vd, ViewIdMenu, submenu_get_view(app->menu));

    /* Sniff */
    app->sniff_view = view_alloc();
    view_allocate_model(app->sniff_view, ViewModelTypeLocking, sizeof(SniffModel));
    view_set_context(app->sniff_view, app);
    view_set_draw_callback(app->sniff_view, sniff_draw);
    view_set_input_callback(app->sniff_view, sniff_input);
    view_set_enter_callback(app->sniff_view, sniff_enter);
    view_set_exit_callback(app->sniff_view, sniff_exit);
    view_set_previous_callback(app->sniff_view, nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdSniff, app->sniff_view);

    /* Control */
    app->control = variable_item_list_alloc();
    app->item_zone = variable_item_list_add(app->control, "Zone (Vive)", 1, control_zone_changed, app);
    app->item_target =
        variable_item_list_add(app->control, "Target (Caseta)", 1, control_target_changed, app);
    app->item_level = variable_item_list_add(app->control, "Level", 21, control_level_changed, app);
    app->item_fade = variable_item_list_add(app->control, "Fade", N_FADES, control_fade_changed, app);
    variable_item_list_add(app->control, "Send level", 0, NULL, app);
    variable_item_list_add(app->control, "Send ON", 0, NULL, app);
    variable_item_list_add(app->control, "Send OFF", 0, NULL, app);
    variable_item_list_add(app->control, "Send Pico ON", 0, NULL, app);
    variable_item_list_add(app->control, "Send Pico OFF", 0, NULL, app);
    variable_item_list_add(app->control, "Start Pico OFF list", 0, NULL, app);
    variable_item_list_add(app->control, "Stop Pico OFF list", 0, NULL, app);
    variable_item_list_add(app->control, "Start Target OFF list", 0, NULL, app);
    variable_item_list_add(app->control, "Stop Target OFF list", 0, NULL, app);
    variable_item_list_add(app->control, "Raise (Vive)", 0, NULL, app);
    variable_item_list_add(app->control, "Lower (Vive)", 0, NULL, app);
    variable_item_list_set_enter_callback(app->control, control_enter, app);
    view_set_previous_callback(variable_item_list_get_view(app->control), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdControl, variable_item_list_get_view(app->control));

    /* Settings */
    app->settings = variable_item_list_alloc();
    app->item_system = variable_item_list_add(app->settings, "System", 2, settings_system_changed, app);
    app->item_hub = variable_item_list_add(app->settings, "Hub ID", 1, NULL, app);
    app->item_zone_setting = variable_item_list_add(app->settings, "Zone (Vive)", 1, NULL, app);
    app->item_tgt = variable_item_list_add(app->settings, "Target ID (Caseta)", 1, NULL, app);
    app->item_pico = variable_item_list_add(app->settings, "Pico ID", 1, NULL, app);
    app->item_channel =
        variable_item_list_add(app->settings, "Channel", N_CHANNELS, settings_channel_changed, app);
    app->item_slot = variable_item_list_add(app->settings, "TX slot", 8, settings_slot_changed, app);
    app->item_repeats = variable_item_list_add(app->settings, "Repeats", 16, settings_repeats_changed, app);
    app->item_log = variable_item_list_add(app->settings, "Log RX", 2, settings_log_changed, app);
    app->item_show_bad =
        variable_item_list_add(app->settings, "Show bad CRC", 2, settings_show_bad_changed, app);
    variable_item_list_add(app->settings, "Clear devices", 0, NULL, app);
    variable_item_list_add(app->settings, "Export raw", 0, NULL, app);
    variable_item_list_set_enter_callback(app->settings, settings_enter, app);
    view_set_previous_callback(variable_item_list_get_view(app->settings), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdSettings, variable_item_list_get_view(app->settings));

    /* Light sets: list of named sets, per-set control screen, name entry, delete confirmation */
    app->sets_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->sets_menu), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdSets, submenu_get_view(app->sets_menu));

    app->set_control = variable_item_list_alloc();
    view_set_previous_callback(variable_item_list_get_view(app->set_control), nav_sets);
    view_dispatcher_add_view(app->vd, ViewIdSetControl, variable_item_list_get_view(app->set_control));

    app->set_name_input = text_input_alloc();
    text_input_set_minimum_length(app->set_name_input, 1);
    view_set_previous_callback(text_input_get_view(app->set_name_input), nav_sets);
    view_dispatcher_add_view(app->vd, ViewIdSetName, text_input_get_view(app->set_name_input));

    app->confirm_dialog = dialog_ex_alloc();
    dialog_ex_set_context(app->confirm_dialog, app);
    dialog_ex_set_result_callback(app->confirm_dialog, confirm_dialog_callback);
    view_set_previous_callback(dialog_ex_get_view(app->confirm_dialog), nav_set_control);
    view_dispatcher_add_view(app->vd, ViewIdConfirm, dialog_ex_get_view(app->confirm_dialog));

    /* Set lights editor: list, per-light Delete/Edit dialog, hub then zone byte entry */
    app->pairs_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->pairs_menu), nav_set_control);
    view_dispatcher_add_view(app->vd, ViewIdPairs, submenu_get_view(app->pairs_menu));

    app->pair_dialog = dialog_ex_alloc();
    dialog_ex_set_context(app->pair_dialog, app);
    dialog_ex_set_result_callback(app->pair_dialog, pair_dialog_callback);
    view_set_previous_callback(dialog_ex_get_view(app->pair_dialog), nav_pairs);
    view_dispatcher_add_view(app->vd, ViewIdPairEdit, dialog_ex_get_view(app->pair_dialog));

    app->pair_hub_input = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->pair_hub_input), nav_pairs);
    view_dispatcher_add_view(app->vd, ViewIdPairHub, byte_input_get_view(app->pair_hub_input));

    app->pair_zone_input = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->pair_zone_input), nav_pairs);
    view_dispatcher_add_view(app->vd, ViewIdPairZone, byte_input_get_view(app->pair_zone_input));
    sets_rebuild(app);

    /* Byte input */
    app->byte_input = byte_input_alloc();
    app->byte_len = 4;
    byte_input_set_result_callback(app->byte_input, byte_input_done, NULL, app, app->byte_buf, 4);
    view_set_previous_callback(byte_input_get_view(app->byte_input), nav_settings);
    view_dispatcher_add_view(app->vd, ViewIdByteInput, byte_input_get_view(app->byte_input));

    /* About */
    app->about = widget_alloc();
    widget_add_text_scroll_element(
        app->about,
        0,
        0,
        128,
        64,
        "\e#Lutron CCA\n"
        "CC1101 packet mode, 2-FSK\n"
        "62.5 kBaud, 433 MHz.\n\n"
        "Sniff: Up/Down select,\n"
        "Left/Right hex detail,\n"
        "OK learns IDs from the\n"
        "selected packet.\n\n"
        "Vive cmd -> hub + zone.\n"
        "Caseta cmd -> hub+target.\n"
        "State rpt -> target (xor).\n"
        "Beacon -> hub.\n\n"
        "Control sends level cmds\n"
        "as the hub, N repeats at\n"
        "75 ms. Raise/Lower (Vive)\n"
        "= 6 hold + 12 step pkts.\n\n"
        "Control: pick a named\n"
        "light set, then On / Off /\n"
        "Level / Raise / Lower hit\n"
        "every light in it.\n"
        "Control advanced: one\n"
        "zone/target, Pico, lists.\n\n"
        "Bad-CRC packets hidden\n"
        "unless Show bad CRC = On.\n\n"
        "Log: apps_data/lutron_cca/\n"
        "rx_log.txt\n");
    view_set_previous_callback(widget_get_view(app->about), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdAbout, widget_get_view(app->about));

    settings_refresh(app);
    control_refresh(app);
    return app;
}

static void app_free(App* app) {
    view_dispatcher_remove_view(app->vd, ViewIdMenu);
    view_dispatcher_remove_view(app->vd, ViewIdSniff);
    view_dispatcher_remove_view(app->vd, ViewIdControl);
    view_dispatcher_remove_view(app->vd, ViewIdSettings);
    view_dispatcher_remove_view(app->vd, ViewIdByteInput);
    view_dispatcher_remove_view(app->vd, ViewIdAbout);
    view_dispatcher_remove_view(app->vd, ViewIdPairs);
    view_dispatcher_remove_view(app->vd, ViewIdPairEdit);
    view_dispatcher_remove_view(app->vd, ViewIdPairHub);
    view_dispatcher_remove_view(app->vd, ViewIdPairZone);
    view_dispatcher_remove_view(app->vd, ViewIdSets);
    view_dispatcher_remove_view(app->vd, ViewIdSetControl);
    view_dispatcher_remove_view(app->vd, ViewIdSetName);
    view_dispatcher_remove_view(app->vd, ViewIdConfirm);

    submenu_free(app->sets_menu);
    variable_item_list_free(app->set_control);
    text_input_free(app->set_name_input);
    dialog_ex_free(app->confirm_dialog);
    submenu_free(app->pairs_menu);
    dialog_ex_free(app->pair_dialog);
    byte_input_free(app->pair_hub_input);
    byte_input_free(app->pair_zone_input);
    submenu_free(app->menu);
    view_free(app->sniff_view);
    variable_item_list_free(app->control);
    variable_item_list_free(app->settings);
    byte_input_free(app->byte_input);
    widget_free(app->about);
    view_dispatcher_free(app->vd);

    furi_mutex_free(app->mutex);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t lutron_cca_app(void* p) {
    UNUSED(p);
    App* app = app_alloc();

    app->radio_ok = cca_radio_init(channel_freq_hz(CHANNELS[app->cfg.channel_idx]));
    if(!app->radio_ok) {
        FURI_LOG_E(TAG, "CC1101 not responding");
        notification_message(app->notif, &sequence_error);
    }

    app->running = true;
    app->worker = furi_thread_alloc_ex("CcaWorker", 3072, worker_thread, app);
    furi_thread_set_priority(app->worker, FuriThreadPriorityHigh);
    furi_thread_start(app->worker);

    view_dispatcher_switch_to_view(app->vd, ViewIdMenu);
    view_dispatcher_run(app->vd);

    app->running = false;
    app->rx_enabled = false;
    furi_thread_join(app->worker);
    furi_thread_free(app->worker);
    cca_radio_deinit();

    app_free(app);
    return 0;
}
