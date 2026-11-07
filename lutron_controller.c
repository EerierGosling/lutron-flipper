/*
 * Lutron Controller for Flipper Zero
 *
 * Runs the internal CC1101 in packet mode (not the stock async pulse-timing path,
 * which cannot resolve CCA's 16 us bits) to sniff, decode, learn IDs from, and
 * transmit Lutron Clear Connect Type A packets at 433 MHz.
 *
 * Screens:
 *   Sniff / Learn  - live decoded packets; OK on a Vive hub command or a Pico button
 *                    adds that light to an existing group or a new one
 *   Control        - named light groups. Each light is either a Vive zone (hub ID + zone)
 *                    or a Pico (device ID). Pick a group, then On / Off / Level / Raise /
 *                    Lower every light in it at once.
 *   Settings       - channel, TX slot, repeats, logging
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
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <flipper_format/flipper_format.h>
#include <stdio.h>
#include <string.h>

#include "cca_codec.h"
#include "cca_radio.h"

#define TAG "LutronController"
#define CONFIG_PATH APP_DATA_PATH("config.txt")
#define LOG_PATH APP_DATA_PATH("rx_log.txt")
#define RAW_EXPORT_PATH APP_DATA_PATH("raw_export.txt")
#define CONFIG_MAGIC "Lutron Controller Config"
/* Builds before the rename to "Lutron Controller" wrote this header and kept their data in
 * apps_data/lutron_cca; both are still accepted / migrated on start-up. */
#define LEGACY_CONFIG_MAGIC "Lutron CCA Config"
#define LEGACY_DATA_DIR EXT_PATH("apps_data/lutron_cca")
#define DATA_DIR EXT_PATH("apps_data/lutron_controller")
#define CONFIG_VERSION 1

#define MAX_GROUPS 10
#define MAX_LIGHTS 16 /* per group */
#define GROUP_NAME_LEN 20
#define MAX_TX_PHASES (MAX_LIGHTS * 2) /* every light kind needs at most two phases */
#define GROUPS_NEW_INDEX 0xFE
#define LIGHTS_ADD_VIVE 0xFE
#define LIGHTS_ADD_PICO 0xFF
#define SNIFF_RING 24
#define FRAME_MS 75

/* Vive two-phase dim: hold-start packets, then dim steps (docs/protocols/cca/index.md) */
#define VIVE_HOLD_REPEATS 6
#define VIVE_STEP_REPEATS 12

/* 5-button Pico (PJ2-3BRL) button codes */
#define PICO_BTN_ON 0x02
#define PICO_BTN_OFF 0x04
#define PICO_BTN_RAISE 0x05
#define PICO_BTN_LOWER 0x06
#define PICO_ACTION_PRESS 0x00
/* OFF presses carry action 0x06, as the earlier "Pico OFF list" sent them. */
#define PICO_ACTION_OFF_PRESS 0x06

typedef enum {
    ViewIdMenu,
    ViewIdSniff,
    ViewIdSettings,
    ViewIdGroups,
    ViewIdGroupControl,
    ViewIdGroupName,
    ViewIdConfirm,
    ViewIdLights,
    ViewIdLightEdit,
    ViewIdLightId,
    ViewIdLightZone,
    ViewIdSniffAdd,
    ViewIdSniffNewGroup,
} ViewId;

typedef enum {
    MenuSniff,
    MenuControl,
    MenuSettings,
} MenuIndex;

/* Settings rows, in display order */
typedef enum {
    SetChannel,
    SetSlot,
    SetRepeats,
    SetLog,
    SetShowBad,
    SetExportRaw,
} SettingsIndex;

/* Group control rows, in display order */
typedef enum {
    GroupCtlName,
    GroupCtlOn,
    GroupCtlOff,
    GroupCtlLevel,
    GroupCtlFade,
    GroupCtlSendLevel,
    GroupCtlRaise,
    GroupCtlLower,
    GroupCtlLights,
    GroupCtlRename,
    GroupCtlDelete,
} GroupCtlIndex;

typedef enum {
    GroupCmdOn,
    GroupCmdOff,
    GroupCmdLevel,
    GroupCmdRaise,
    GroupCmdLower,
} GroupCmd;

typedef enum {
    LightKindVive = 0,
    LightKindPico = 1,
} LightKind;

static const uint8_t CHANNELS[] = {5, 14, 17, 20, 23, 26, 29, 32, 38, 41, 44, 47, 50, 53, 56};
#define N_CHANNELS (sizeof(CHANNELS) / sizeof(CHANNELS[0]))
/* Every launch starts on channel 26 (433.602844 MHz, the Lutron default). The channel can be
 * changed in Settings for the current session but is never saved, so a stray change cannot
 * leave the app listening on the wrong frequency next time. */
#define DEFAULT_CHANNEL_IDX 5 /* channel 26 */

static const uint8_t FADE_QS[] = {1, 4, 8, 20, 40};
static const char* const FADE_NAMES[] = {"0.25s", "1s", "2s", "5s", "10s"};
#define N_FADES (sizeof(FADE_QS) / sizeof(FADE_QS[0]))

typedef struct {
    uint8_t kind; /* LightKind */
    uint8_t id[4]; /* Vive: hub ID (packet bytes 2..5). Pico: device ID (packet bytes 2..5) */
    uint8_t zone; /* Vive: zone (packet byte 12). Unused for Picos */
} GroupLight;

typedef struct {
    char name[GROUP_NAME_LEN];
    GroupLight lights[MAX_LIGHTS];
    uint8_t n_lights;
    uint8_t level; /* percent, used by Send level */
    uint8_t fade_idx; /* index into FADE_QS, used by Vive level commands */
} LightGroup;

typedef struct {
    uint8_t channel_idx;
    uint8_t slot;
    uint8_t repeats;
    uint8_t level; /* default level for new groups */
    uint8_t fade_idx; /* default fade for new groups */
    bool log_rx;
    bool show_bad;
    LightGroup groups[MAX_GROUPS];
    uint8_t n_groups;
} AppConfig;

typedef struct {
    uint8_t pkt[CCA_MAX_PKT];
    uint8_t len;
    uint8_t repeats;
    uint8_t stage; /* stages run in order; phases within a stage are interleaved */
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
    char status[32]; /* fits "Added to " + a full group name */
} SniffModel;

typedef struct {
    Gui* gui;
    ViewDispatcher* vd;
    NotificationApp* notif;
    Storage* storage;

    Submenu* menu;
    View* sniff_view;
    VariableItemList* settings;
    Submenu* groups_menu;
    VariableItemList* group_control;
    TextInput* group_name_input;
    DialogEx* confirm_dialog;
    Submenu* lights_menu;
    DialogEx* light_dialog;
    ByteInput* light_id_input;
    ByteInput* light_zone_input;
    Submenu* sniff_add_menu;
    TextInput* sniff_group_input;

    VariableItem* item_channel;
    VariableItem* item_slot;
    VariableItem* item_repeats;
    VariableItem* item_log;
    VariableItem* item_show_bad;

    AppConfig cfg;

    /* Sniff "add to group" state */
    GroupLight pending_light; /* the light picked in Sniff, waiting for a group */
    char sniff_add_header[28];
    char sniff_group_name_buf[GROUP_NAME_LEN];
    char sniff_msg[32]; /* shown in Sniff's status line on return, then cleared */

    /* Group + light editor state. Strings live here because the GUI keeps the pointers. */
    uint8_t group_sel; /* the group being controlled / edited */
    uint8_t group_edit_index; /* == cfg.n_groups when creating a new group */
    char group_name_buf[GROUP_NAME_LEN];
    char confirm_text[48];
    uint8_t light_sel;
    uint8_t light_edit_index; /* == group's n_lights when adding a new light */
    uint8_t light_edit_kind;
    uint8_t light_id_buf[4];
    uint8_t light_zone_buf[1];
    char lights_header[24];
    char light_labels[MAX_LIGHTS][24];
    char light_dialog_header[24];
    char light_dialog_text[40];

    FuriThread* worker;
    FuriMutex* mutex;
    volatile bool running;
    volatile bool rx_enabled;

    volatile bool tx_pending;
    TxPhase tx_phase[MAX_TX_PHASES];
    TxPhase tx_work[MAX_TX_PHASES]; /* worker-owned copy, kept off the worker's stack */
    uint8_t tx_nphases;
    uint8_t seq_counter;
    uint8_t type_rot;
    uint8_t pico_ab; /* Picos alternate button group A/B on successive events */

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

static LightGroup* cur_group(App* app) {
    if(app->group_sel >= app->cfg.n_groups) app->group_sel = 0;
    return &app->cfg.groups[app->group_sel];
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
}

/*
 * Config keys keep the names earlier builds used ("NSets", "Set0Name", ...) so existing
 * config files keep working. Group i's lights are stored as parallel arrays:
 * Set<i>Hubs (4 bytes each: Vive hub or Pico ID), Set<i>Zones, Set<i>Kinds (0 Vive, 1 Pico).
 */
static void config_save(App* app) {
    storage_common_mkdir(app->storage, STORAGE_APP_DATA_PATH_PREFIX);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    if(flipper_format_file_open_always(ff, CONFIG_PATH)) {
        AppConfig* c = &app->cfg;
        uint32_t v;
        char key[20];
        flipper_format_write_header_cstr(ff, CONFIG_MAGIC, CONFIG_VERSION);
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

        v = c->n_groups;
        flipper_format_write_uint32(ff, "NSets", &v, 1);
        for(uint8_t i = 0; i < c->n_groups; i++) {
            const LightGroup* g = &c->groups[i];
            snprintf(key, sizeof(key), "Set%uName", (unsigned)i);
            flipper_format_write_string_cstr(ff, key, g->name);
            v = g->n_lights;
            snprintf(key, sizeof(key), "Set%uNPairs", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
            if(g->n_lights) {
                uint8_t ids[MAX_LIGHTS * 4];
                uint8_t zones[MAX_LIGHTS];
                uint8_t kinds[MAX_LIGHTS];
                for(uint8_t k = 0; k < g->n_lights; k++) {
                    memcpy(ids + k * 4, g->lights[k].id, 4);
                    zones[k] = g->lights[k].zone;
                    kinds[k] = g->lights[k].kind;
                }
                snprintf(key, sizeof(key), "Set%uHubs", (unsigned)i);
                flipper_format_write_hex(ff, key, ids, (size_t)g->n_lights * 4);
                snprintf(key, sizeof(key), "Set%uZones", (unsigned)i);
                flipper_format_write_hex(ff, key, zones, g->n_lights);
                snprintf(key, sizeof(key), "Set%uKinds", (unsigned)i);
                flipper_format_write_hex(ff, key, kinds, g->n_lights);
            }
            v = g->level;
            snprintf(key, sizeof(key), "Set%uLevel", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
            v = g->fade_idx;
            snprintf(key, sizeof(key), "Set%uFade", (unsigned)i);
            flipper_format_write_uint32(ff, key, &v, 1);
        }
    } else {
        FURI_LOG_W(TAG, "config save failed");
    }
    flipper_format_free(ff);
}

/* Each read rewinds first, so keys can be read in any order and a missing key
 * (e.g. Kinds in configs from before Pico lights) cannot strand the stream at EOF. */
static bool cfg_u32(FlipperFormat* ff, const char* key, uint32_t* v) {
    flipper_format_rewind(ff);
    return flipper_format_read_uint32(ff, key, v, 1);
}

static bool cfg_hex(FlipperFormat* ff, const char* key, uint8_t* data, size_t n) {
    flipper_format_rewind(ff);
    return flipper_format_read_hex(ff, key, data, n);
}

static bool cfg_str(FlipperFormat* ff, const char* key, FuriString* out) {
    flipper_format_rewind(ff);
    return flipper_format_read_string(ff, key, out);
}

static void config_load(App* app) {
    config_defaults(&app->cfg);
    FlipperFormat* ff = flipper_format_file_alloc(app->storage);
    FuriString* str = furi_string_alloc();
    do {
        uint32_t version = 0;
        if(!flipper_format_file_open_existing(ff, CONFIG_PATH)) break;
        if(!flipper_format_read_header(ff, str, &version)) break;
        if(furi_string_cmp_str(str, CONFIG_MAGIC) != 0 &&
           furi_string_cmp_str(str, LEGACY_CONFIG_MAGIC) != 0)
            break;
        AppConfig* c = &app->cfg;
        uint32_t v;
        char key[20];
        /* "ChannelIdx" in older configs is ignored: the channel always starts on 26. */
        if(cfg_u32(ff, "Slot", &v) && v < 8) c->slot = (uint8_t)v;
        if(cfg_u32(ff, "Repeats", &v) && v >= 1 && v <= 16) c->repeats = (uint8_t)v;
        if(cfg_u32(ff, "Level", &v) && v <= 100) c->level = (uint8_t)v;
        if(cfg_u32(ff, "FadeIdx", &v) && v < N_FADES) c->fade_idx = (uint8_t)v;
        if(cfg_u32(ff, "LogRx", &v)) c->log_rx = (v != 0);
        if(cfg_u32(ff, "ShowBad", &v)) c->show_bad = (v != 0);

        uint8_t ids[MAX_LIGHTS * 4];
        uint8_t zones[MAX_LIGHTS];
        uint8_t kinds[MAX_LIGHTS];

        if(cfg_u32(ff, "NSets", &v) && v <= MAX_GROUPS) {
            uint32_t n_groups = v;
            for(uint8_t i = 0; i < n_groups; i++) {
                LightGroup* g = &c->groups[c->n_groups];
                memset(g, 0, sizeof(*g));
                g->level = c->level;
                g->fade_idx = c->fade_idx;
                snprintf(key, sizeof(key), "Set%uName", (unsigned)i);
                if(!cfg_str(ff, key, str)) continue;
                snprintf(g->name, sizeof(g->name), "%s", furi_string_get_cstr(str));
                snprintf(key, sizeof(key), "Set%uNPairs", (unsigned)i);
                if(cfg_u32(ff, key, &v) && v > 0 && v <= MAX_LIGHTS) {
                    uint8_t n = (uint8_t)v;
                    snprintf(key, sizeof(key), "Set%uHubs", (unsigned)i);
                    bool ok = cfg_hex(ff, key, ids, (size_t)n * 4);
                    snprintf(key, sizeof(key), "Set%uZones", (unsigned)i);
                    ok = ok && cfg_hex(ff, key, zones, n);
                    snprintf(key, sizeof(key), "Set%uKinds", (unsigned)i);
                    if(!cfg_hex(ff, key, kinds, n)) memset(kinds, LightKindVive, n);
                    if(ok) {
                        g->n_lights = n;
                        for(uint8_t k = 0; k < n; k++) {
                            g->lights[k].kind = kinds[k] == LightKindPico ? LightKindPico : LightKindVive;
                            memcpy(g->lights[k].id, ids + k * 4, 4);
                            g->lights[k].zone = zones[k];
                        }
                    }
                }
                snprintf(key, sizeof(key), "Set%uLevel", (unsigned)i);
                if(cfg_u32(ff, key, &v) && v <= 100) g->level = (uint8_t)v;
                snprintf(key, sizeof(key), "Set%uFade", (unsigned)i);
                if(cfg_u32(ff, key, &v) && v < N_FADES) g->fade_idx = (uint8_t)v;
                c->n_groups++;
            }
        } else if(cfg_u32(ff, "NPairs", &v) && v > 0 && v <= MAX_LIGHTS) {
            /* Configs from before groups kept one global "Vive pairs" list: make it a group. */
            uint8_t n = (uint8_t)v;
            if(cfg_hex(ff, "PairHubs", ids, (size_t)n * 4) && cfg_hex(ff, "PairZones", zones, n)) {
                LightGroup* g = &c->groups[0];
                memset(g, 0, sizeof(*g));
                snprintf(g->name, sizeof(g->name), "Lights");
                g->level = c->level;
                g->fade_idx = c->fade_idx;
                g->n_lights = n;
                for(uint8_t k = 0; k < n; k++) {
                    g->lights[k].kind = LightKindVive;
                    memcpy(g->lights[k].id, ids + k * 4, 4);
                    g->lights[k].zone = zones[k];
                }
                c->n_groups = 1;
            }
        }
    } while(false);
    furi_string_free(str);
    flipper_format_free(ff);
}

/* ------------------------------------------------------------------ TX */

static uint8_t next_type_byte(App* app, uint8_t base) {
    /* Vive hubs rotate the type byte between commands: 0x89 / 0x8A / 0x8B. */
    uint8_t t = (uint8_t)(base + (app->type_rot % 3));
    app->type_rot++;
    return t;
}

static TxPhase* tx_add(App* app, uint8_t stage, uint8_t repeats) {
    if(app->tx_nphases >= MAX_TX_PHASES) return NULL;
    TxPhase* ph = &app->tx_phase[app->tx_nphases++];
    ph->stage = stage;
    ph->repeats = repeats;
    return ph;
}

/*
 * One command for every light in a group.
 *
 *   Vive light, On / Off / Level: one level command (format 0x0E), stage 0.
 *   Vive light, Raise / Lower:    hold-start (format 0x09) in stage 0, then dim steps (format
 *                                 0x0B) in stage 1. A dimmer ignores steps without a hold-start.
 *   Pico light, On / Off / Raise / Lower: the button's press (short format) in stage 0, then its
 *                                 release (long format) in stage 1, as the Pico itself sends them.
 *   Pico light, Level: skipped; a Pico has no level button.
 *
 * Within a stage the worker interleaves every light's copies (copy 1 of each, then copy 2, ...)
 * so all lights react within the first pass. Returns false if a send is already running or the
 * group has nothing that can carry this command.
 */
static bool request_tx_group(App* app, const LightGroup* g, GroupCmd cmd) {
    if(app->tx_pending) return false;

    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->tx_nphases = 0;
    uint8_t vive_type = next_type_byte(app, 0x89);
    /* Pico type byte: base 0x88, bit 0 = release (long format), bit 1 = group B. */
    uint8_t pico_ab = app->pico_ab;
    app->pico_ab ^= 1;
    uint8_t pico_press_type = (uint8_t)(0x88 | (pico_ab << 1));
    uint8_t pico_release_type = (uint8_t)(0x89 | (pico_ab << 1));

    bool raise = cmd == GroupCmdRaise;
    uint8_t pct = cmd == GroupCmdOn ? 100 : (cmd == GroupCmdOff ? 0 : g->level);

    for(uint8_t i = 0; i < g->n_lights; i++) {
        const GroupLight* l = &g->lights[i];
        if(l->kind == LightKindVive) {
            if(cmd == GroupCmdRaise || cmd == GroupCmdLower) {
                TxPhase* hold = tx_add(app, 0, VIVE_HOLD_REPEATS);
                TxPhase* step = tx_add(app, 1, VIVE_STEP_REPEATS);
                if(!hold || !step) break;
                hold->len =
                    (uint8_t)cca_build_vive_dim(hold->pkt, l->id, l->zone, raise, true, vive_type);
                step->len =
                    (uint8_t)cca_build_vive_dim(step->pkt, l->id, l->zone, raise, false, vive_type);
            } else {
                TxPhase* ph = tx_add(app, 0, app->cfg.repeats);
                if(!ph) break;
                ph->len = (uint8_t)cca_build_vive_level(
                    ph->pkt, l->id, l->zone, cca_pct_to_level16(pct), FADE_QS[g->fade_idx], vive_type);
            }
        } else {
            uint8_t button, action = PICO_ACTION_PRESS;
            switch(cmd) {
            case GroupCmdOn:
                button = PICO_BTN_ON;
                break;
            case GroupCmdOff:
                button = PICO_BTN_OFF;
                action = PICO_ACTION_OFF_PRESS;
                break;
            case GroupCmdRaise:
                button = PICO_BTN_RAISE;
                break;
            case GroupCmdLower:
                button = PICO_BTN_LOWER;
                break;
            default:
                continue; /* Level: Picos have no level button */
            }
            TxPhase* press = tx_add(app, 0, app->cfg.repeats);
            TxPhase* release = tx_add(app, 1, app->cfg.repeats);
            if(!press || !release) break;
            press->len =
                (uint8_t)cca_build_button_short(press->pkt, l->id, button, action, pico_press_type);
            release->len = (uint8_t)cca_build_button_long(release->pkt, l->id, button, pico_release_type);
        }
    }

    bool any = app->tx_nphases > 0;
    furi_mutex_release(app->mutex);
    if(!any) return false;
    app->tx_pending = true;
    notification_message(app->notif, &sequence_blink_start_blue);
    return true;
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
    uint8_t slot = app->cfg.slot & 7;
    memcpy(phases, app->tx_phase, sizeof(TxPhase) * nphases);
    furi_mutex_release(app->mutex);

    uint8_t max_stage = 0;
    for(uint8_t p = 0; p < nphases; p++) {
        if(phases[p].stage > max_stage) max_stage = phases[p].stage;
    }

    bool ok = true;
    uint32_t next = furi_get_tick();
    uint16_t sent = 0;
    for(uint8_t s = 0; s <= max_stage && ok; s++) {
        uint8_t max_rep = 0;
        for(uint8_t p = 0; p < nphases; p++) {
            if(phases[p].stage == s && phases[p].repeats > max_rep) max_rep = phases[p].repeats;
        }
        for(uint8_t r = 0; r < max_rep && ok; r++) {
            for(uint8_t p = 0; p < nphases && ok; p++) {
                if(phases[p].stage != s || r >= phases[p].repeats) continue;
                ok = tx_send_one(app, &phases[p], slot, enc, sizeof(enc), &next);
                if(ok) sent++;
            }
        }
    }

    app->tx_pending = false;
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

/* The light a sniffed packet identifies: a Vive hub command gives hub + zone, a Pico button
 * packet gives the Pico's ID. Returns false for anything else. */
static bool light_from_packet(const CcaPacket* p, GroupLight* out) {
    const uint8_t* r = p->raw;
    memset(out, 0, sizeof(*out));
    if(cca_is_vive_cmd(p)) {
        out->kind = LightKindVive;
        memcpy(out->id, r + 2, 4);
        out->zone = r[12];
        return true;
    }
    if(p->type >= 0x88 && p->type <= 0x8B && p->len > 5) {
        out->kind = LightKindPico;
        memcpy(out->id, r + 2, 4);
        return true;
    }
    return false;
}

static void sniff_add_open(App* app, const GroupLight* light);

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
        canvas_draw_str(canvas, 0, 36, "Tap a Pico or wait for");
        canvas_draw_str(canvas, 0, 46, "the hub to send.");
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
        GroupLight light;
        const char* msg = NULL;
        if(!sel.crc_ok) {
            msg = "CRC bad: not added";
        } else if(!light_from_packet(&sel, &light)) {
            msg = "No light in this packet";
        } else {
            sniff_add_open(app, &light);
        }
        if(msg) {
            with_view_model(
                app->sniff_view, SniffModel * m, { snprintf(m->status, sizeof(m->status), "%s", msg); }, true);
            notification_message(app->notif, &sequence_error);
        }
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
            if(app->sniff_msg[0]) {
                snprintf(m->status, sizeof(m->status), "%s", app->sniff_msg);
            } else {
                snprintf(
                    m->status,
                    sizeof(m->status),
                    "RX ch%u%s",
                    (unsigned)CHANNELS[app->cfg.channel_idx],
                    app->radio_ok ? "" : " NO RADIO");
            }
        },
        true);
    app->sniff_msg[0] = '\0';
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

/* ------------------------------------------------------------------ settings view */

static void settings_refresh(App* app) {
    char buf[24];
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

    variable_item_set_current_value_index(app->item_show_bad, app->cfg.show_bad ? 1 : 0);
    variable_item_set_current_value_text(app->item_show_bad, app->cfg.show_bad ? "On" : "Off");
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
    settings_refresh(app); /* not saved: next launch is back on channel 26 */
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

static void settings_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    switch(index) {
    case SetExportRaw:
        export_raw_log(app);
        break;
    default:
        break;
    }
}

/* ------------------------------------------------------------------ groups */

static void groups_menu_callback(void* ctx, uint32_t index);
static void lights_menu_callback(void* ctx, uint32_t index);
static void group_control_enter(void* ctx, uint32_t index);
static void lights_rebuild(App* app);

static void groups_rebuild(App* app) {
    submenu_reset(app->groups_menu);
    submenu_set_header(app->groups_menu, "Light groups");
    for(uint8_t i = 0; i < app->cfg.n_groups; i++) {
        submenu_add_item(app->groups_menu, app->cfg.groups[i].name, i, groups_menu_callback, app);
    }
    if(app->cfg.n_groups < MAX_GROUPS) {
        submenu_add_item(app->groups_menu, "+ New group", GROUPS_NEW_INDEX, groups_menu_callback, app);
    }
}

static void group_level_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    LightGroup* g = cur_group(app);
    char buf[8];
    g->level = (uint8_t)(variable_item_get_current_value_index(item) * 5);
    snprintf(buf, sizeof(buf), "%u%%", (unsigned)g->level);
    variable_item_set_current_value_text(item, buf);
    config_save(app);
}

static void group_fade_changed(VariableItem* item) {
    App* app = variable_item_get_context(item);
    LightGroup* g = cur_group(app);
    g->fade_idx = variable_item_get_current_value_index(item);
    variable_item_set_current_value_text(item, FADE_NAMES[g->fade_idx]);
    config_save(app);
}

/* Rebuilds the control screen for the current group and selects row `select`. */
static void group_control_rebuild(App* app, uint8_t select) {
    VariableItemList* l = app->group_control;
    variable_item_list_reset(l);
    variable_item_list_set_enter_callback(l, group_control_enter, app);
    if(app->cfg.n_groups == 0) return;

    LightGroup* g = cur_group(app);
    char buf[16];
    VariableItem* item = variable_item_list_add(l, g->name, 1, NULL, app);
    snprintf(buf, sizeof(buf), "%u light%s", (unsigned)g->n_lights, g->n_lights == 1 ? "" : "s");
    variable_item_set_current_value_text(item, buf);

    variable_item_list_add(l, "On", 0, NULL, app);
    variable_item_list_add(l, "Off", 0, NULL, app);

    item = variable_item_list_add(l, "Level", 21, group_level_changed, app);
    snprintf(buf, sizeof(buf), "%u%%", (unsigned)g->level);
    variable_item_set_current_value_index(item, g->level / 5);
    variable_item_set_current_value_text(item, buf);

    item = variable_item_list_add(l, "Fade", N_FADES, group_fade_changed, app);
    variable_item_set_current_value_index(item, g->fade_idx);
    variable_item_set_current_value_text(item, FADE_NAMES[g->fade_idx]);

    variable_item_list_add(l, "Send level", 0, NULL, app);
    variable_item_list_add(l, "Raise", 0, NULL, app);
    variable_item_list_add(l, "Lower", 0, NULL, app);
    variable_item_list_add(l, "Edit lights", 0, NULL, app);
    variable_item_list_add(l, "Rename", 0, NULL, app);
    variable_item_list_add(l, "Delete group", 0, NULL, app);
    variable_item_list_set_selected_item(l, select);
}

static void group_name_done(void* ctx);

/* index < n_groups renames that group; index == n_groups names a new one. */
static void group_start_name(App* app, uint8_t index) {
    bool rename = index < app->cfg.n_groups;
    app->group_edit_index = index;
    if(rename) {
        snprintf(app->group_name_buf, sizeof(app->group_name_buf), "%s", app->cfg.groups[index].name);
    } else {
        snprintf(
            app->group_name_buf, sizeof(app->group_name_buf), "Group %u", (unsigned)(app->cfg.n_groups + 1));
    }
    text_input_set_header_text(app->group_name_input, rename ? "Rename group" : "Name the new group");
    text_input_set_result_callback(
        app->group_name_input, group_name_done, app, app->group_name_buf, sizeof(app->group_name_buf), !rename);
    view_dispatcher_switch_to_view(app->vd, ViewIdGroupName);
}

static void group_name_done(void* ctx) {
    App* app = ctx;
    uint8_t i = app->group_edit_index;
    if(i < app->cfg.n_groups) {
        snprintf(app->cfg.groups[i].name, GROUP_NAME_LEN, "%s", app->group_name_buf);
        config_save(app);
        groups_rebuild(app);
        group_control_rebuild(app, GroupCtlRename);
        view_dispatcher_switch_to_view(app->vd, ViewIdGroupControl);
        return;
    }
    if(app->cfg.n_groups >= MAX_GROUPS) {
        notification_message(app->notif, &sequence_error);
        view_dispatcher_switch_to_view(app->vd, ViewIdGroups);
        return;
    }
    LightGroup* g = &app->cfg.groups[app->cfg.n_groups];
    memset(g, 0, sizeof(*g));
    snprintf(g->name, sizeof(g->name), "%s", app->group_name_buf);
    g->level = app->cfg.level;
    g->fade_idx = app->cfg.fade_idx;
    app->group_sel = app->cfg.n_groups++;
    config_save(app);
    groups_rebuild(app);
    group_control_rebuild(app, GroupCtlLights);
    /* A new group has no lights yet: go straight to adding them. Back leads to its controls. */
    lights_rebuild(app);
    view_dispatcher_switch_to_view(app->vd, ViewIdLights);
}

static void group_confirm_delete(App* app) {
    LightGroup* g = cur_group(app);
    snprintf(app->confirm_text, sizeof(app->confirm_text), "Delete \"%s\"?", g->name);
    dialog_ex_set_header(app->confirm_dialog, "Delete group", 64, 2, AlignCenter, AlignTop);
    dialog_ex_set_text(app->confirm_dialog, app->confirm_text, 64, 28, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->confirm_dialog, "Cancel");
    dialog_ex_set_right_button_text(app->confirm_dialog, "Delete");
    view_dispatcher_switch_to_view(app->vd, ViewIdConfirm);
}

static void confirm_dialog_callback(DialogExResult result, void* ctx) {
    App* app = ctx;
    if(result == DialogExResultRight && app->group_sel < app->cfg.n_groups) {
        uint8_t i = app->group_sel;
        memmove(
            &app->cfg.groups[i],
            &app->cfg.groups[i + 1],
            (size_t)(app->cfg.n_groups - i - 1) * sizeof(LightGroup));
        app->cfg.n_groups--;
        app->group_sel = 0;
        config_save(app);
        groups_rebuild(app);
        notification_message(app->notif, &sequence_single_vibro);
        view_dispatcher_switch_to_view(app->vd, ViewIdGroups);
    } else if(result == DialogExResultLeft) {
        view_dispatcher_switch_to_view(app->vd, ViewIdGroupControl);
    }
}

static void group_control_enter(void* ctx, uint32_t index) {
    App* app = ctx;
    if(app->cfg.n_groups == 0) return;
    LightGroup* g = cur_group(app);
    bool ok = true;
    switch(index) {
    case GroupCtlOn:
        ok = request_tx_group(app, g, GroupCmdOn);
        break;
    case GroupCtlOff:
        ok = request_tx_group(app, g, GroupCmdOff);
        break;
    case GroupCtlSendLevel:
        ok = request_tx_group(app, g, GroupCmdLevel);
        break;
    case GroupCtlRaise:
        ok = request_tx_group(app, g, GroupCmdRaise);
        break;
    case GroupCtlLower:
        ok = request_tx_group(app, g, GroupCmdLower);
        break;
    case GroupCtlLights:
        lights_rebuild(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdLights);
        break;
    case GroupCtlRename:
        group_start_name(app, app->group_sel);
        break;
    case GroupCtlDelete:
        group_confirm_delete(app);
        break;
    default:
        break;
    }
    /* Refused: a send is already running, the group is empty, or (Send level) it has only Picos. */
    if(!ok) notification_message(app->notif, &sequence_error);
}

static void groups_menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == GROUPS_NEW_INDEX) {
        if(app->cfg.n_groups < MAX_GROUPS)
            group_start_name(app, app->cfg.n_groups);
        else
            notification_message(app->notif, &sequence_error);
        return;
    }
    if(index >= app->cfg.n_groups) return;
    app->group_sel = (uint8_t)index;
    group_control_rebuild(app, GroupCtlOn);
    view_dispatcher_switch_to_view(app->vd, ViewIdGroupControl);
}

/* ------------------------------------------------------------------ group lights editor */

static void light_describe(const GroupLight* l, char* out, size_t n, unsigned number) {
    if(l->kind == LightKindPico) {
        snprintf(out, n, "%u: Pico %02X%02X%02X%02X", number, l->id[0], l->id[1], l->id[2], l->id[3]);
    } else {
        snprintf(
            out,
            n,
            "%u: Vive %02X%02X%02X%02X z%02X",
            number,
            l->id[0],
            l->id[1],
            l->id[2],
            l->id[3],
            (unsigned)l->zone);
    }
}

static void lights_rebuild(App* app) {
    LightGroup* g = cur_group(app);
    submenu_reset(app->lights_menu);
    snprintf(
        app->lights_header,
        sizeof(app->lights_header),
        "Lights %u/%u",
        (unsigned)g->n_lights,
        (unsigned)MAX_LIGHTS);
    submenu_set_header(app->lights_menu, app->lights_header);
    if(g->n_lights < MAX_LIGHTS) {
        submenu_add_item(app->lights_menu, "+ Add Vive zone", LIGHTS_ADD_VIVE, lights_menu_callback, app);
        submenu_add_item(app->lights_menu, "+ Add Pico", LIGHTS_ADD_PICO, lights_menu_callback, app);
    }
    for(uint8_t i = 0; i < g->n_lights; i++) {
        light_describe(&g->lights[i], app->light_labels[i], sizeof(app->light_labels[i]), i + 1);
        submenu_add_item(app->lights_menu, app->light_labels[i], i, lights_menu_callback, app);
    }
}

/* Saves the light being edited (ID from light_id_buf, zone from light_zone_buf). */
static void light_commit(App* app) {
    LightGroup* g = cur_group(app);
    GroupLight entered;
    entered.kind = app->light_edit_kind;
    memcpy(entered.id, app->light_id_buf, 4);
    entered.zone = entered.kind == LightKindVive ? app->light_zone_buf[0] : 0;

    uint8_t i = app->light_edit_index;
    bool adding = i >= g->n_lights;
    bool duplicate = false;
    for(uint8_t k = 0; k < g->n_lights; k++) {
        const GroupLight* o = &g->lights[k];
        if(k != i && o->kind == entered.kind && memcmp(o->id, entered.id, 4) == 0 &&
           o->zone == entered.zone) {
            duplicate = true;
        }
    }

    if(duplicate || (adding && g->n_lights >= MAX_LIGHTS)) {
        notification_message(app->notif, &sequence_error);
    } else {
        if(adding) i = g->n_lights++;
        g->lights[i] = entered;
        config_save(app);
        notification_message(app->notif, &sequence_single_vibro);
    }
    lights_rebuild(app);
    group_control_rebuild(app, GroupCtlLights);
    view_dispatcher_switch_to_view(app->vd, ViewIdLights);
}

static void light_zone_done(void* ctx) {
    light_commit(ctx);
}

static void light_id_done(void* ctx) {
    App* app = ctx;
    if(app->light_edit_kind == LightKindPico) {
        light_commit(app);
        return;
    }
    byte_input_set_result_callback(
        app->light_zone_input, light_zone_done, NULL, app, app->light_zone_buf, 1);
    byte_input_set_header_text(app->light_zone_input, "Vive zone (pkt byte 12)");
    view_dispatcher_switch_to_view(app->vd, ViewIdLightZone);
}

static void light_start_edit(App* app, uint8_t index, uint8_t kind) {
    LightGroup* g = cur_group(app);
    app->light_edit_index = index;
    app->light_edit_kind = kind;
    if(index < g->n_lights) {
        memcpy(app->light_id_buf, g->lights[index].id, 4);
        app->light_zone_buf[0] = g->lights[index].zone;
    } else {
        /* New light: a Vive zone starts from this group's last Vive hub, since zones in a group
         * usually share one hub. Otherwise start blank. Sniff can add lights without typing. */
        memset(app->light_id_buf, 0, 4);
        app->light_zone_buf[0] = 0;
        if(kind == LightKindVive) {
            for(uint8_t k = 0; k < g->n_lights; k++) {
                if(g->lights[k].kind == LightKindVive) memcpy(app->light_id_buf, g->lights[k].id, 4);
            }
        }
    }
    byte_input_set_result_callback(app->light_id_input, light_id_done, NULL, app, app->light_id_buf, 4);
    byte_input_set_header_text(
        app->light_id_input, kind == LightKindPico ? "Pico ID (from a BTN line)" : "Vive hub ID (bytes 2-5)");
    view_dispatcher_switch_to_view(app->vd, ViewIdLightId);
}

static void lights_menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    LightGroup* g = cur_group(app);
    if(index == LIGHTS_ADD_VIVE || index == LIGHTS_ADD_PICO) {
        if(g->n_lights < MAX_LIGHTS)
            light_start_edit(app, g->n_lights, index == LIGHTS_ADD_PICO ? LightKindPico : LightKindVive);
        else
            notification_message(app->notif, &sequence_error);
        return;
    }
    if(index >= g->n_lights) return;

    app->light_sel = (uint8_t)index;
    const GroupLight* l = &g->lights[index];
    snprintf(
        app->light_dialog_header,
        sizeof(app->light_dialog_header),
        "Light %u of %u",
        (unsigned)(index + 1),
        (unsigned)g->n_lights);
    if(l->kind == LightKindPico) {
        snprintf(
            app->light_dialog_text,
            sizeof(app->light_dialog_text),
            "Pico %02X%02X%02X%02X",
            l->id[0],
            l->id[1],
            l->id[2],
            l->id[3]);
    } else {
        snprintf(
            app->light_dialog_text,
            sizeof(app->light_dialog_text),
            "Vive hub %02X%02X%02X%02X\nZone %02X",
            l->id[0],
            l->id[1],
            l->id[2],
            l->id[3],
            (unsigned)l->zone);
    }
    dialog_ex_set_header(app->light_dialog, app->light_dialog_header, 64, 2, AlignCenter, AlignTop);
    dialog_ex_set_text(app->light_dialog, app->light_dialog_text, 64, 28, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->light_dialog, "Delete");
    dialog_ex_set_right_button_text(app->light_dialog, "Edit");
    view_dispatcher_switch_to_view(app->vd, ViewIdLightEdit);
}

static void light_dialog_callback(DialogExResult result, void* ctx) {
    App* app = ctx;
    LightGroup* g = cur_group(app);
    uint8_t i = app->light_sel;
    if(i >= g->n_lights) {
        view_dispatcher_switch_to_view(app->vd, ViewIdLights);
        return;
    }
    if(result == DialogExResultLeft) {
        memmove(&g->lights[i], &g->lights[i + 1], (size_t)(g->n_lights - i - 1) * sizeof(GroupLight));
        g->n_lights--;
        config_save(app);
        lights_rebuild(app);
        group_control_rebuild(app, GroupCtlLights);
        notification_message(app->notif, &sequence_single_vibro);
        view_dispatcher_switch_to_view(app->vd, ViewIdLights);
    } else if(result == DialogExResultRight) {
        light_start_edit(app, i, g->lights[i].kind);
    }
}

/* ------------------------------------------------------------------ sniff: add to group */

/* Adds a light to group g and saves. Returns NULL on success, or a short reason it wasn't added. */
static const char* group_add_light(App* app, LightGroup* g, const GroupLight* light) {
    for(uint8_t k = 0; k < g->n_lights; k++) {
        const GroupLight* o = &g->lights[k];
        if(o->kind == light->kind && memcmp(o->id, light->id, 4) == 0 && o->zone == light->zone) {
            return "Already in that group";
        }
    }
    if(g->n_lights >= MAX_LIGHTS) return "Group is full";
    g->lights[g->n_lights++] = *light;
    config_save(app);
    return NULL;
}

/* Adds the pending light to g, then returns to Sniff with the result in its status line. */
static void sniff_add_finish(App* app, LightGroup* g) {
    const char* err = group_add_light(app, g, &app->pending_light);
    if(err) {
        snprintf(app->sniff_msg, sizeof(app->sniff_msg), "%s", err);
        notification_message(app->notif, &sequence_error);
    } else {
        snprintf(app->sniff_msg, sizeof(app->sniff_msg), "Added to %s", g->name);
        notification_message(app->notif, &sequence_success);
    }
    view_dispatcher_switch_to_view(app->vd, ViewIdSniff);
}

static void sniff_group_name_done(void* ctx) {
    App* app = ctx;
    if(app->cfg.n_groups >= MAX_GROUPS) {
        snprintf(app->sniff_msg, sizeof(app->sniff_msg), "No room for a new group");
        notification_message(app->notif, &sequence_error);
        view_dispatcher_switch_to_view(app->vd, ViewIdSniff);
        return;
    }
    LightGroup* g = &app->cfg.groups[app->cfg.n_groups++];
    memset(g, 0, sizeof(*g));
    snprintf(g->name, sizeof(g->name), "%s", app->sniff_group_name_buf);
    g->level = app->cfg.level;
    g->fade_idx = app->cfg.fade_idx;
    sniff_add_finish(app, g); /* saves the new group along with its first light */
}

static void sniff_add_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    if(index == GROUPS_NEW_INDEX) {
        snprintf(
            app->sniff_group_name_buf,
            sizeof(app->sniff_group_name_buf),
            "Group %u",
            (unsigned)(app->cfg.n_groups + 1));
        text_input_set_header_text(app->sniff_group_input, "Name the new group");
        text_input_set_result_callback(
            app->sniff_group_input,
            sniff_group_name_done,
            app,
            app->sniff_group_name_buf,
            sizeof(app->sniff_group_name_buf),
            true);
        view_dispatcher_switch_to_view(app->vd, ViewIdSniffNewGroup);
        return;
    }
    if(index < app->cfg.n_groups) sniff_add_finish(app, &app->cfg.groups[index]);
}

/* Opens the "add to group" menu for a light picked in Sniff. */
static void sniff_add_open(App* app, const GroupLight* light) {
    app->pending_light = *light;
    const uint8_t* id = light->id;
    if(light->kind == LightKindPico) {
        snprintf(
            app->sniff_add_header,
            sizeof(app->sniff_add_header),
            "Add Pico %02X%02X%02X%02X",
            id[0],
            id[1],
            id[2],
            id[3]);
    } else {
        snprintf(
            app->sniff_add_header,
            sizeof(app->sniff_add_header),
            "Add %02X%02X%02X%02X z%02X",
            id[0],
            id[1],
            id[2],
            id[3],
            (unsigned)light->zone);
    }
    submenu_reset(app->sniff_add_menu);
    submenu_set_header(app->sniff_add_menu, app->sniff_add_header);
    for(uint8_t i = 0; i < app->cfg.n_groups; i++) {
        submenu_add_item(app->sniff_add_menu, app->cfg.groups[i].name, i, sniff_add_callback, app);
    }
    if(app->cfg.n_groups < MAX_GROUPS) {
        submenu_add_item(app->sniff_add_menu, "+ New group", GROUPS_NEW_INDEX, sniff_add_callback, app);
    }
    view_dispatcher_switch_to_view(app->vd, ViewIdSniffAdd);
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

static uint32_t nav_sniff(void* ctx) {
    UNUSED(ctx);
    return ViewIdSniff;
}

static uint32_t nav_sniff_add(void* ctx) {
    UNUSED(ctx);
    return ViewIdSniffAdd;
}

static uint32_t nav_groups(void* ctx) {
    UNUSED(ctx);
    return ViewIdGroups;
}

static uint32_t nav_group_control(void* ctx) {
    UNUSED(ctx);
    return ViewIdGroupControl;
}

static uint32_t nav_lights(void* ctx) {
    UNUSED(ctx);
    return ViewIdLights;
}

static void menu_callback(void* ctx, uint32_t index) {
    App* app = ctx;
    switch(index) {
    case MenuSniff:
        view_dispatcher_switch_to_view(app->vd, ViewIdSniff);
        break;
    case MenuControl:
        groups_rebuild(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdGroups);
        break;
    case MenuSettings:
        settings_refresh(app);
        view_dispatcher_switch_to_view(app->vd, ViewIdSettings);
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

    /* Data from before the rename lives under the old app ID: move it over once, so saved
     * groups, logs and settings carry across. */
    if(storage_common_exists(app->storage, LEGACY_DATA_DIR) &&
       !storage_common_exists(app->storage, DATA_DIR "/config.txt")) {
        FS_Error err = storage_common_migrate(app->storage, LEGACY_DATA_DIR, DATA_DIR);
        FURI_LOG_I(TAG, "migrated %s -> %s: %d", LEGACY_DATA_DIR, DATA_DIR, (int)err);
    }

    config_load(app);

    app->vd = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->vd, app->gui, ViewDispatcherTypeFullscreen);

    /* Menu */
    app->menu = submenu_alloc();
    submenu_set_header(app->menu, "Lutron Controller");
    submenu_add_item(app->menu, "Sniff / Learn", MenuSniff, menu_callback, app);
    submenu_add_item(app->menu, "Control", MenuControl, menu_callback, app);
    submenu_add_item(app->menu, "Settings", MenuSettings, menu_callback, app);
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

    /* Sniff "add to group": group picker, then name entry for a new group */
    app->sniff_add_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->sniff_add_menu), nav_sniff);
    view_dispatcher_add_view(app->vd, ViewIdSniffAdd, submenu_get_view(app->sniff_add_menu));

    app->sniff_group_input = text_input_alloc();
    text_input_set_minimum_length(app->sniff_group_input, 1);
    view_set_previous_callback(text_input_get_view(app->sniff_group_input), nav_sniff_add);
    view_dispatcher_add_view(app->vd, ViewIdSniffNewGroup, text_input_get_view(app->sniff_group_input));

    /* Groups: list, per-group control screen, name entry, delete confirmation */
    app->groups_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->groups_menu), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdGroups, submenu_get_view(app->groups_menu));

    app->group_control = variable_item_list_alloc();
    view_set_previous_callback(variable_item_list_get_view(app->group_control), nav_groups);
    view_dispatcher_add_view(app->vd, ViewIdGroupControl, variable_item_list_get_view(app->group_control));

    app->group_name_input = text_input_alloc();
    text_input_set_minimum_length(app->group_name_input, 1);
    view_set_previous_callback(text_input_get_view(app->group_name_input), nav_groups);
    view_dispatcher_add_view(app->vd, ViewIdGroupName, text_input_get_view(app->group_name_input));

    app->confirm_dialog = dialog_ex_alloc();
    dialog_ex_set_context(app->confirm_dialog, app);
    dialog_ex_set_result_callback(app->confirm_dialog, confirm_dialog_callback);
    view_set_previous_callback(dialog_ex_get_view(app->confirm_dialog), nav_group_control);
    view_dispatcher_add_view(app->vd, ViewIdConfirm, dialog_ex_get_view(app->confirm_dialog));

    /* Group lights editor: list, per-light Delete/Edit dialog, ID then (Vive) zone byte entry */
    app->lights_menu = submenu_alloc();
    view_set_previous_callback(submenu_get_view(app->lights_menu), nav_group_control);
    view_dispatcher_add_view(app->vd, ViewIdLights, submenu_get_view(app->lights_menu));

    app->light_dialog = dialog_ex_alloc();
    dialog_ex_set_context(app->light_dialog, app);
    dialog_ex_set_result_callback(app->light_dialog, light_dialog_callback);
    view_set_previous_callback(dialog_ex_get_view(app->light_dialog), nav_lights);
    view_dispatcher_add_view(app->vd, ViewIdLightEdit, dialog_ex_get_view(app->light_dialog));

    app->light_id_input = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->light_id_input), nav_lights);
    view_dispatcher_add_view(app->vd, ViewIdLightId, byte_input_get_view(app->light_id_input));

    app->light_zone_input = byte_input_alloc();
    view_set_previous_callback(byte_input_get_view(app->light_zone_input), nav_lights);
    view_dispatcher_add_view(app->vd, ViewIdLightZone, byte_input_get_view(app->light_zone_input));
    groups_rebuild(app);

    /* Settings */
    app->settings = variable_item_list_alloc();
    app->item_channel =
        variable_item_list_add(app->settings, "Channel", N_CHANNELS, settings_channel_changed, app);
    app->item_slot = variable_item_list_add(app->settings, "TX slot", 8, settings_slot_changed, app);
    app->item_repeats = variable_item_list_add(app->settings, "Repeats", 16, settings_repeats_changed, app);
    app->item_log = variable_item_list_add(app->settings, "Log RX", 2, settings_log_changed, app);
    app->item_show_bad =
        variable_item_list_add(app->settings, "Show bad CRC", 2, settings_show_bad_changed, app);
    variable_item_list_add(app->settings, "Export raw", 0, NULL, app);
    variable_item_list_set_enter_callback(app->settings, settings_enter, app);
    view_set_previous_callback(variable_item_list_get_view(app->settings), nav_menu);
    view_dispatcher_add_view(app->vd, ViewIdSettings, variable_item_list_get_view(app->settings));


    settings_refresh(app);
    return app;
}

static void app_free(App* app) {
    view_dispatcher_remove_view(app->vd, ViewIdMenu);
    view_dispatcher_remove_view(app->vd, ViewIdSniff);
    view_dispatcher_remove_view(app->vd, ViewIdSettings);
    view_dispatcher_remove_view(app->vd, ViewIdSniffAdd);
    view_dispatcher_remove_view(app->vd, ViewIdSniffNewGroup);
    view_dispatcher_remove_view(app->vd, ViewIdGroups);
    view_dispatcher_remove_view(app->vd, ViewIdGroupControl);
    view_dispatcher_remove_view(app->vd, ViewIdGroupName);
    view_dispatcher_remove_view(app->vd, ViewIdConfirm);
    view_dispatcher_remove_view(app->vd, ViewIdLights);
    view_dispatcher_remove_view(app->vd, ViewIdLightEdit);
    view_dispatcher_remove_view(app->vd, ViewIdLightId);
    view_dispatcher_remove_view(app->vd, ViewIdLightZone);

    submenu_free(app->menu);
    view_free(app->sniff_view);
    variable_item_list_free(app->settings);
    submenu_free(app->sniff_add_menu);
    text_input_free(app->sniff_group_input);
    submenu_free(app->groups_menu);
    variable_item_list_free(app->group_control);
    text_input_free(app->group_name_input);
    dialog_ex_free(app->confirm_dialog);
    submenu_free(app->lights_menu);
    dialog_ex_free(app->light_dialog);
    byte_input_free(app->light_id_input);
    byte_input_free(app->light_zone_input);
    view_dispatcher_free(app->vd);

    furi_mutex_free(app->mutex);
    furi_record_close(RECORD_STORAGE);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_GUI);
    free(app);
}

int32_t lutron_controller_app(void* p) {
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
