# Lutron CCA for Flipper Zero

A Flipper Zero app that drives the internal CC1101 in **packet mode** to sniff, decode,
learn from, and transmit Lutron Clear Connect Type A (CCA) packets at 433 MHz.
Supports **Vive** hubs (hub ID + zone addressing, the default) and **Caseta / RA3** bridges
(hub ID + 4-byte load ID), selectable in Settings → System.

The stock Sub-GHz "Read RAW" app uses the CC1101's async pulse-timing path, which
cannot resolve CCA's 16 µs bits (62.5 kBaud 2-FSK). This app bypasses that and talks
to the chip over SPI directly, mirroring `firmware/src/cca/cc1101.c` from this repo:
hardware sync on the 0xAAAA preamble, fixed 80-byte FIFO captures, and a software
N81 + CRC-16 decoder.

## Build and install

Requires [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (`pip install ufbt`).
This was built against the official 1.4.3 SDK.

```bash
cd flipper/lutron_cca
ufbt            # builds dist/lutron_cca.fap
ufbt launch     # with the Flipper connected over USB: installs and starts the app
```

Or copy `dist/lutron_cca.fap` to `SD Card/apps/Sub-GHz/` manually.

Host-side codec tests (no Flipper needed):

```bash
cd flipper/lutron_cca/test
cc -std=c11 -Wall -Wextra -I.. -o codec_test codec_test.c ../cca_codec.c && ./codec_test
```

## Screens

**Sniff / Learn.** Live list of decoded packets with a one-line summary each
(`VIVE 75% z38`, `VIVE hold up z38`, `SET 75% >06FE8020`, `STATE 55% 8F902C08`,
`BTN ON prs 06FDEFF4`, `BEACON 91 ...`). Up/Down selects, Left/Right toggles a hex detail
view, OK learns IDs from the selected packet. Button actions other than the known press and
release values are shown as `aXX` with their raw action byte:

| Packet selected | What is saved |
| --- | --- |
| Vive hub command (type 0x89–0x8B, 0xEF at byte 13) | Hub ID = bytes 2–5, Zone = byte 12. Also switches System to Vive. This is the exact pair you need. |
| Caseta/RA3 SET_LEVEL (type 0x81–0x83, format 0x0E) | Hub ID = bytes 2–5, Target = bytes 9–12, both verbatim. Switches System to Caseta/RA3. |
| Dimmer state report (format 0x08) | Target = bytes 2–5 XOR `20 00 00 08` (load ID from RF transmit ID, per `docs/devices/index.md`). Marked "xor" because the byte order of that rule has not been verified on air. |
| Caseta pairing beacon (0x91–0x93) or Vive pairing beacon (0xB9/0xBA, format 0x11) | Hub ID = bytes 2–5. |

Packets whose CRC failed are hidden by default (they still count in the header and go to
the log). Turn on **Show bad CRC** in Settings to see them; they appear as `BAD tXX lenNN`
with a `?` at the right edge. Every packet is appended to
`SD Card/apps_data/lutron_cca/rx_log.txt` as `tick rssi=-62 crc=ok err=0 <hex>` when
logging is on.

**Control.** Named light sets for Vive. Each set is a list of up to 16 lights, and each light
is a hub ID (packet bytes 2–5) plus a zone (packet byte 12), so one set can span several hubs.
Up to 10 sets are stored in `config.txt`.

- **Pick a set** from the list to open its controls: **On**, **Off**, **Level** and **Fade**
  (left/right to change, remembered per set), **Send level**, **Raise**, **Lower**,
  **Edit lights**, **Rename** and **Delete set**. The top row shows the set's name and how many
  lights it has.
- **+ New set** asks for a name, then opens the light editor. **+ Add light** asks for the hub
  ID, then the zone. A new light starts from the set's last hub, or the Settings hub for the
  first one. Selecting a light offers **Delete** or **Edit**. Duplicate lights are refused.
- **On / Off / Send level** send one Vive level command per light, as a burst of `Repeats`
  copies. The copies are interleaved (copy 1 of every light, then copy 2, and so on) so every
  light switches within the first pass. Packets stay 75 ms apart, so a press takes
  lights × Repeats × 75 ms, for example 4 lights × 11 repeats ≈ 3.3 s.
- **Raise / Lower** send all the hold-start packets first, then all the dim steps, since a
  Vive dimmer ignores steps without a preceding hold-start. That is lights × 18 × 75 ms,
  about 5.4 s for 4 lights.
- A press is refused with a red flash if the set has no lights yet or another send is still
  running.

Configs from earlier builds that had a single "Vive pairs" list load it as a set named
**Lights**.

**Control advanced.** The single-target screen. Zone (Vive) or Target (Caseta) cycles through learned values, `*` marks the
manually entered one. Level (0–100 % in steps of 5), Fade (0.25 s to 10 s), then
Send level / Send ON / Send OFF, Send Pico ON / Send Pico OFF, and Raise / Lower for Vive.
Set the Pico ID in Settings to the 8-digit ID shown in a `BTN` packet, then select a Pico
action to transmit that press and release as the Pico. Each send transmits as the hub:

For a fixed group of Pico IDs, edit `PICO_OFF_IDS` in `lutron_cca.c`, rebuild, and use
**Start Pico OFF list**. The batch sends action byte `0x06` on each OFF press, followed by
the normal release packet. It cycles through the list repeatedly until **Stop Pico OFF list**
is selected; the list is limited to 20 IDs. The list ships with two placeholder IDs
(`01234567`, `89ABCDEF`) because an empty list does not compile; replace them with your own,
and keep real IDs out of public commits, since a Pico ID is all anyone needs to impersonate
that Pico. Each send transmits as the hub:

With **System** set to `Caseta/RA3`, **Start Target OFF list** uses the same hardcoded list
as target/load IDs and sends hub OFF commands to each one. It repeats until **Stop Target OFF
list** is selected. This requires the correct Hub ID in Settings. Each send transmits as the hub:
`Repeats` copies (default 11) spaced 75 ms apart, the sequence byte carrying the TX slot in
its low 3 bits and a retransmit counter above, and the type byte rotating between bursts
(0x89→0x8A→0x8B for Vive, 0x81→0x82→0x83 for Caseta) so the dimmer does not dedupe
successive commands. Raise/Lower follows the documented Vive two-phase sequence: 6
hold-start packets (format 0x09) then 12 dim-step packets (format 0x0B); the hold-start is
required or the dimmer ignores the steps. LED blinks blue while sending, then green (sent)
or red (radio refused, usually the Flipper's region lock).
Send level, ON, OFF, Raise and Lower here go only to the single zone or target selected at the
top. Use **Control** to switch groups of lights.

**Settings.** System (Vive / Caseta-RA3), Hub ID, Zone, Target ID, Pico ID (hex byte
entry), Channel (Lutron channels 5–56, default 26), TX slot (0–7), Repeats (1–16),
Log RX, Show bad CRC, Clear devices. Saved to `apps_data/lutron_cca/config.txt`.
The **Export raw** action writes the packet hex from `rx_log.txt` to
`apps_data/lutron_cca/raw_export.txt`.

## Getting the IDs without the app

**Vive.** Leave Sniff running until the hub sends any command: someone using the Vive app,
a Pico that is associated through the hub, an occupancy or daylight sensor driving a zone,
a schedule, or the Title 24 demand-response contact input. Press OK on the `VIVE` line and
both the hub ID and that zone are saved. Each zone you want to control needs one captured
command for that zone, or you can type the zone byte in Settings and try candidates.

Do not press the button on the back of a Vive hub to provoke traffic. Lutron's installation
guide documents only one function for it, a 10-second hold that resets the hub's login
password, and no short-press behaviour.

**Caseta / RA3.** Catch any hub command (schedule, Alexa, a bridge-paired Pico) and press OK
on the `SET` line. Or tap a dimmer's paddle and OK the `STATE` line for the target, and OK a
`BEACON` line for the hub ID if one appears. The bridge's back button is a network-pairing
authorization tap, not an RF pairing trigger, so it will not produce beacons.

Then Control → Send ON.

## Radio details

| | |
| --- | --- |
| Frequency | 431.0 MHz + channel × 100 kHz + 2844 Hz (channel 26 = 433.602844 MHz, matching the CC1101 word 0x10AD52 in the docs; the 2844 Hz offset is assumed to apply to other channels) |
| Modulation | 2-FSK, 62.5 kBaud, ±41.2 kHz deviation, 325 kHz RX filter |
| RX | SYNC=0xAAAA 15/16 match, fixed 80-byte packets, drained from the FIFO every 1 ms by a worker thread |
| TX | MDMCFG2 sync off; the N81 bitstream (32-bit preamble, FF FA DE, payload, CRC) is loaded verbatim. Packets over 64 encoded bytes use infinite-length mode with FIFO refill |
| TX power | PATABLE 0xC0 (+10 dBm) |

The register table lives in `cca_radio.c` and the protocol constants in `cca_codec.c`.
Both are commented with the source lines in the main firmware they were ported from.

## Files

- `lutron_cca.c` – app, GUI, worker thread
- `cca_radio.[ch]` – CC1101 packet-mode driver over `furi_hal_spi_bus_handle_subghz`
- `cca_codec.[ch]` – CRC-16 (0xCA0F), N81 encode/decode with error recovery, SET_LEVEL builder. Pure C.
- `test/codec_test.c` – host tests using the two real packets with CRCs quoted in `docs/`

## Known limits

- Transmit covers set-level for both systems and raise/lower for Vive. Caseta raise/lower,
  scenes, Pico imitation and pairing/config packets are not implemented, though the builders
  in `firmware/src/cca/cca_tx_builder.h` port straight across.
- Vive hubs also run their own pairing (DCD) and the dimmer's state-report format on Vive has
  not been characterised in this repo, so zones can only be learned from hub commands.
- No TDMA frame sync on transmit: the slot is fixed in settings rather than chosen from
  observed traffic. Hubs tolerate this; it only matters for collision avoidance.
- Two-byte N81 error recovery brute-forces up to 65536 CRCs on a 64 MHz Cortex-M4 and can
  take a few tens of ms. A burst of back-to-back retransmits can overflow the FIFO during that
  window; the packet will be caught on one of the other 10 copies.
- Not tested on hardware yet. The codec is tested on the host against real captured packets;
  the radio path mirrors working firmware but has only been compiled, not run.
