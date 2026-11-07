# lutron controller for flipper zero

a flipper zero app that drives the internal CC1101 to sniff, decode, learn from, and transmit Lutron Clear Connect Type A (CCA) packets at 433 MHz. you can control groups of lights - vive zones and picos - without the lutron app :)

the stock sub-ghz app can't actually read these signals (they're too fast for its raw mode), so this app talks to the radio chip directly instead.

_based on the reverse engineering in [lutron-protocols](https://github.com/alxgmpr/lutron-protocols), which is based on [Entropy512's lutron_hacks](https://github.com/Entropy512/lutron_hacks) and [Ceady's wireless interface writeup](https://hackaday.io/project/2291-integrated-room-sunrise-simulator/log/7223-the-wireless-interface)!_

## install

grab `lutron_controller.fap` from the [latest release](../../releases/latest) and copy it to `SD Card/apps/Sub-GHz/`. it shows up under apps → sub-ghz → lutron controller.

it's built for official flipper firmware - custom firmware will probably give "API mismatch", so build it yourself against that firmware instead.

## how to use

**groups.** make a group, name it, and add lights. a light is either a vive zone (hub id + zone) or a pico. pick a group to run on, off, level, raise, and lower commands for everything in the group at once. _(picos get skipped for level commands since they don't have a level button. raise/lower commands are also very granular, so they might be extremely slow to change!)_

**sniff.** shows every lutron packet nearby. press ok on a `VIVE` line (a hub command) or a `BTN` line (a pico press) and it asks which group to add that light to or if you want to a new one.

to catch a vive zone, leave sniff open near the hub until it sends something.

**settings.** radio channel (starts on 26 every time you open the app), how many times each packet repeats, logging to the sd card, and whether sniff shows corrupted packets.

## building the app

you need [ufbt](https://github.com/flipperdevices/flipperzero-ufbt) (`pip install ufbt`):

```sh
ufbt          # builds dist/lutron_controller.fap
ufbt launch   # installs it on a plugged-in flipper and opens it
```

the packet encoder/decoder has tests that run on your computer:

```sh
cc -std=c11 -Wall -Wextra -I. -o test/codec_test test/codec_test.c cca_codec.c && ./test/codec_test
```