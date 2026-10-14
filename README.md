# iPod Video 5.5G Firmware Reverse Engineering & Rebuilding Suite

A comprehensive reverse-engineering toolkit and documentation suite for the **Apple iPod Video 5.5G (iPod 5th Generation Enhanced)** firmware **1.3** (`iPod_25.1.3.ipsw` / `Firmware-25.6.3`).

This repository provides full technical specifications, reverse-engineered memory maps, resource extractors, binary patchers (e.g. EU volume limit removal), and a bit-exact firmware rebuilder that generates flashable partition images and `.ipsw` packages.

---

## Table of Contents

- [1. Hardware Architecture & Memory Map](#1-hardware-architecture--memory-map)
- [2. Firmware Container & Partition Layout](#2-firmware-container--partition-layout)
- [3. Sub-Image Breakdown](#3-sub-image-breakdown)
  - [3.1 OSOS (Operating System Binary)](#31-osos-operating-system-binary)
  - [3.2 Embedded UI Resource Block](#32-embedded-ui-resource-block)
  - [3.3 RSRC (FAT16 Resource Filesystem)](#33-rsrc-fat16-resource-filesystem)
- [4. Hardware Hacks & Modifications](#4-hardware-hacks--modifications)
  - [4.1 EU Volume Limit Hardware Clamp Removal](#41-eu-volume-limit-hardware-clamp-removal)
  - [4.2 UI Strings & Branding](#42-ui-strings--branding)
  - [4.3 UI Bitmaps & Boot Graphics](#43-ui-bitmaps--boot-graphics)
- [5. Tool Usage (`ipod_tool.py`)](#5-tool-usage-ipod_toolpy)
  - [5.1 Setup & Prerequisites](#51-setup--prerequisites)
  - [5.2 Unpack Firmware](#52-unpack-firmware)
  - [5.3 Check & Uncap Volume](#53-check--uncap-volume)
  - [5.4 Edit UI Strings](#54-edit-ui-strings)
  - [5.5 Edit Bitmaps & Icons](#55-edit-bitmaps--icons)
  - [5.6 Pack & Rebuild](#56-pack--rebuild)
  - [5.7 Drop & Sync Media](#57-drop--sync-media)
- [6. Drop-and-Play Media Engine (Add Songs Without iTunes)](#6-drop-and-play-media-engine-add-songs-without-itunes)
  - [6.1 How It Works](#61-how-it-works)
  - [6.2 Workflow & Usage](#62-workflow--usage)
  - [6.3 On-Device Portable AutoSync](#63-on-device-portable-autosync)
  - [6.4 Supported Audio Formats & Tags](#64-supported-audio-formats--tags)
- [7. Flashing Guide](#7-flashing-guide)
  - [Method 1: Direct Partition Write with `dd` (Recommended)](#method-1-direct-partition-write-with-dd-recommended)
  - [Method 2: iTunes / Finder Restore](#method-2-itunes--finder-restore)
- [8. Repository Structure](#8-repository-structure)

---

## 1. Hardware Architecture & Memory Map

The 5th generation iPod Video (5.5G / Enhanced) uses PortalPlayer's dual-core architecture combined with dedicated coprocessors for display and audio:

| Subsystem | Component / Specification |
| :--- | :--- |
| **Main SoC** | PortalPlayer PP5022A (Dual ARM7TDMI cores @ up to 80 MHz) |
| **Primary Core (CPU)** | Core 0: General OS, UI event loop, scheduler, filesystem operations |
| **Coprocessor Core (COP)**| Core 1: I/O scheduling, hardware acceleration, buffer management |
| **Video Coprocessor** | Broadcom VideoCore II (BCM2722) handling H.264 / MPEG-4 decode & display overlay |
| **Audio DAC/Codec** | Wolfson Microelectronics WM8758 |
| **Power Management** | Philips/NXP PCF50607 PMU |
| **Storage Bus** | ATA-6 hard drive / CF / SD-iFlash interface |
| **SDRAM Base** | `0x10000000` (32 MB / 64 MB SDRAM) |
| **PortalPlayer MMIO**| `0x60000000` (Controller registers, clock gates, interrupt controllers) |

### Memory Map:
```
0x00000000 - 0x0000FFFF : Internal BootROM / Initial Vector Table
0x10000000 - 0x10736000 : SDRAM - OSOS Image (Bare-Metal ARM OS Kernel)
  0x10000000            : ARM Exception Vector Table
  0x100001F0            : Reset Handler & SoC Hardware Initialization
  0x100A0348            : Regional Volume Limiter Check Function
  0x100AF468            : Main UI Event Loop & Task Dispatcher
  0x10331DA0            : Resource Block Header (Bitmaps, Strings, Menus, Views)
0x60000000 - 0x6000FFFF : PortalPlayer PP5022 Memory-Mapped I/O Registers
```

---

## 2. Firmware Container & Partition Layout

The release package `iPod_25.1.3.ipsw` is a standard ZIP archive containing:
- `manifest.plist`: XML metadata specifying `BuildID=103841792`, `VisibleBuildID=19955712`, `FamilyID=6`, and `UpdaterFamilyID=25`.
- `Firmware-25.6.3`: The raw 13,905,920-byte flashable firmware partition container.

### 2.1 Master Header (Sector 0)
- **Offset `0x0000` - `0x00FF`**: ASCII Apple STOP Sign Art and copyright string:
  ```
  {{~~  /-----\   {{~~ /       \  {{~~|         | {{~~| S T O P | ... Copyright(C) 2001 Apple Computer, Inc.
  ```
- **Offset `0x0100` - `0x0103`**: 4-byte magic signature **`]ih[`** (`0x5B68695D`, little-endian `[hi]`).
- **Offset `0x0104` - `0x0107`**: `diroffset_raw` = `0x00004000`. The partition directory starts at `diroffset_raw + 0x200 = 0x4200`.
- **Offset `0x010A` - `0x010B`**: Firmware format version = `3` (`0x0003`).

### 2.2 Directory Entries (Offset `0x4200`)
For firmware version 3 on 2048-byte sector devices, an image padding of `0x800` (2048 bytes) is applied between `devOffset` and the data. Each directory entry is exactly 40 bytes:

| Field | Offset | Size | Description |
| :--- | :--- | :--- | :--- |
| `sig` | `+0x00` | 4 bytes | `!ATA` (`0x41544121`) or `DNAN` |
| `type` | `+0x04` | 4 bytes | `soso` (`OSOS`), `crsr` (`RSRC`), or `dpua` (`AUPD`) |
| `id` | `+0x08` | 4 bytes | Image identifier integer (typically `0`) |
| `devOffset` | `+0x0C` | 4 bytes | Relative sector/block byte offset |
| `len` | `+0x10` | 4 bytes | Exact image payload length in bytes |
| `addr` | `+0x14` | 4 bytes | DRAM memory load target address |
| `entryOffset` | `+0x18` | 4 bytes | Execution entry offset relative to image start |
| `chksum` | `+0x1C` | 4 bytes | 32-bit unsigned sum of all bytes in payload |
| `vers` | `+0x20` | 4 bytes | Image version integer (`0x0000b012`) |
| `loadAddr` | `+0x24` | 4 bytes | Hardware load address (`0x187c0008`) |

### Observed Partition Table in iPod Video 5.5G:
```
Index  Type    ID   devOffset     Length (bytes)  Load Address  Entry Offset  Checksum    File Offset
------------------------------------------------------------------------------------------------------
0      OSOS    0    0x00004800    7,561,216       0x10000000    0x00000000    0x2C7C48F3  0x00005000
1      RSRC    0    0x0073B000    5,244,928       0x00000000    0x00000600    0x18319BAB  0x0073B800
2      AUPD    0    0x00C3C000    1,075,200       0x10000000    0x00000000    0x0B19DB1C  0x00C3C800
```

---

## 3. Sub-Image Breakdown

### 3.1 OSOS (Operating System Binary)
- **Base Address**: `0x10000000`
- **Reset Vector**:
  ```arm
  0x10000000:  b       #0x100001f0       ; Reset Exception
  0x10000004:  b       #0x100001a8       ; Undefined Instruction
  0x10000008:  ldr     pc, [pc, #0xdc]   ; Software Interrupt (SWI)
  0x1000000c:  b       #0x100001c0       ; Prefetch Abort
  0x10000010:  b       #0x100001d8       ; Data Abort
  0x10000014:  b       #0x10000014       ; Reserved / Infinite Loop
  0x10000018:  b       #0x10000180       ; IRQ
  0x1000001c:  b       #0x1000015c       ; FIQ
  ```
- **Reset Handler (`0x100001F0`)**:
  - Initializes memory controllers, buses, and caches.
  - Queries PortalPlayer SoC identifier at MMIO `0x60000000`: `ldrb r2, [r0]`, `cmp r2, #0x55`.
  - Configures C runtime stacks and ThreadX-derived RTOS structures.
  - Spawns core system threads: `RtcTaskClass`, `PowerManager`, `DiskReaderTask`, `AudioCodecs`, and the UI Event Loop at `0x100af468`.

### 3.2 Embedded UI Resource Block
At offset `0x00331DA0` (RAM `0x10331DA0`) in `osos_raw.bin`:
- **Header**: `z1 = 0x00000003`, `length = 26708` bytes, `num_sections = 8`.
- **Sections**:
  1. `paMB` (`BMap`): **403 UI Bitmaps** (Battery meters, play status, scrollbars, menus, clicker graphics, Apple boot logos).
  2. `stiB` (`Bits`): 1 item (Bitfield definitions).
  3. `mTDL` (`LDTm`): 1 item (Language/Date-Time localization matrix).
  4. `uneM` (`Menu`): **40 System Menus** (Hierarchy and navigation trees).
  5. ` rtS` (`Str `): **991 Localized UI Strings** (ASCII/Latin-1 strings for all labels).
  6. `dmCT` (`TCmd`): 1 item (Command dispatch table).
  7. `epyT` (`Type`): 158 Type descriptors.
  8. `weiV` (`View`): **619 View Layouts** (Coordinates and window hierarchies).

### 3.3 RSRC (FAT16 Resource Filesystem)
The `RSRC` partition contains a standard FAT16 filesystem starting at offset `0x0600` inside the partition (`0x0073BE00` in the firmware file):
- Volume Label: `IPODRESOURC`
- File System: FAT16, 2048 bytes per cluster.
- **Directory Hierarchy**:
  - `Resources/Fonts/`: TrueType fonts:
    - `PodiumSans18.ttf`, `Helvetica_17.ttf`, `Helvetica_23.ttf`, `MonoHope_*.ttf`, `CJK.ttf` (Asian font glyphs).
  - `Resources/VideoCore/Boot/`:
    - `vmcs.bin`: Broadcom VideoCore microcode / system firmware.
    - `RenderServer.bin`: Display pipeline and compositor server.
  - `Resources/VideoCore/Library/`:
    - `h264dec.vll`: H.264 video hardware decoder library.
    - `mpg4dec.vll`: MPEG-4 Simple Profile video decoder library.
    - `aacdec.vll`: AAC audio acceleration library.
    - `mplayer.vll`, `slideshow.vll`, `passthruhandler.vll`.

---

## 4. Hardware Hacks & Modifications

### 4.1 EU Volume Limit Hardware Clamp Removal
European models enforce an 82 dB sound ceiling via an acoustic limit flag:

- **Check Function Location**: `0x100A0348` in RAM (`0x000A0348` in `osos_raw.bin`):
  ```arm
  0x100a0348:  ldr      r0, [pc, #8]      ; Load hardware region block
  0x100a034c:  ldr      r0, [r0, #0x94]   ; Read region flag byte
  0x100a0350:  and      r0, r0, #1        ; Test EU limiter bit (01 00 00 e2)
  0x100a0354:  bx       lr
  ```
- **The Patch**:
  Replace `and r0, r0, #1` (`01 00 00 e2`) with `mov r0, #0` (`00 00 a0 e3`).
  - Result: The function unconditionally returns `0`, causing the sound driver to configure the Wolfson DAC at full US headphone output power (+3 dB to +6 dB louder, zero software clipping).

### 4.2 UI Strings & Branding
All 991 UI strings in `ui_strings.json` can be edited in-place:
- Modify menu names, owner info, or custom branding on "About" screens.
- In-place string injection ensures memory safety and preserves zero-padding.

### 4.3 UI Bitmaps & Boot Graphics
All 403 bitmaps are extracted as standard 24-bit Windows `.bmp` files. Modified bitmaps of matching dimensions are automatically converted back into Apple's packed 16-bit RGB565 / RGBA4444 format upon injection.

---

## 5. Tool Usage (`ipod_tool.py`)

### 5.1 Setup & Prerequisites
Make sure Python 3 and Capstone are installed:
```bash
pip install capstone
```

### 5.2 Unpack Firmware
```bash
./ipod_tool.py unpack iPod_25.1.3.ipsw -o unpacked_fw
```
Extracts:
- `unpacked_fw/images/osos_raw.bin` (Main ARM OS binary)
- `unpacked_fw/images/rsrc.fat` (FAT16 resource partition)
- `unpacked_fw/rsrc_extracted/` (Extracted TrueType fonts and VideoCore libraries)
- `unpacked_fw/ui_strings.json` (991 UI strings with IDs and offsets)
- `unpacked_fw/bitmaps/` (403 extracted UI bitmaps as `.bmp`)

### 5.3 Check & Uncap Volume
```bash
# Check status:
./ipod_tool.py volume unpacked_fw/images/osos_raw.bin

# Permanently uncap:
./ipod_tool.py volume unpacked_fw/images/osos_raw.bin --uncap -o unpacked_fw/images/osos_raw.bin
```

### 5.4 Edit UI Strings
1. Open `unpacked_fw/ui_strings.json` in any text editor.
2. Edit any string's `"text"` field.
3. Inject the modified strings:
   ```bash
   ./ipod_tool.py inject-strings unpacked_fw/images/osos_raw.bin unpacked_fw/ui_strings.json unpacked_fw/images/osos_raw.bin
   ```

### 5.5 Edit Bitmaps & Icons
1. Edit any bitmap in `unpacked_fw/bitmaps/` (e.g. using GIMP, Aseprite, Photoshop, or Paint). Preserve original width, height, and save as 24-bit BMP.
2. Inject the modified image back:
   ```bash
   ./ipod_tool.py inject-bitmap unpacked_fw/images/osos_raw.bin <index> <path_to_bmp> -o unpacked_fw/images/osos_raw.bin
   ```

### 5.6 Pack & Rebuild
```bash
./ipod_tool.py pack unpacked_fw -o custom_iPod_25.1.3.ipsw
```
This recomputes all 32-bit checksums, updates directory headers at `0x4200`, and outputs:
- `unpacked_fw/firmware_partition.bin` (Raw partition image for `dd`)
- `custom_iPod_25.1.3.ipsw` (Complete update archive for iTunes/Finder)

### 5.7 Drop & Sync Media
```bash
# Sync an iPod mounted at /media/user/IPOD (or E: on Windows)
./ipod_tool.py sync /media/user/IPOD

# Move loose files into iPod_Control/Music shards instead of copying
./ipod_tool.py sync /media/user/IPOD --move

# Preview files that would be indexed without writing to disk
./ipod_tool.py sync /media/user/IPOD --dry-run
```

---

## 6. Drop-and-Play Media Engine (Add Songs Without iTunes)

In stock Apple iPod firmware, dropping music files onto the iPod filesystem does **not** make them visible in the Music menu because the OS kernel exclusively reads a compiled binary database located at `/iPod_Control/iTunes/iTunesDB`.

We reverse-engineered the entire `iTunesDB` binary format and implemented a **100% pure-Python, zero-dependency engine** (`ipod_indexer.py` / `ipod_tool.py sync`). It allows you to drag-and-drop your audio files directly to the iPod as a standard USB flash drive from any operating system (Linux, macOS, Windows) and have them instantly playable on the stock firmware!

### 6.1 How It Works
1. **Drop Anywhere**: Put music files (.mp3, .m4a, .wav) into a `Music/` folder or anywhere on your iPod storage. Subfolders (e.g. `Music/Rock/`, `Music/Queen/`) are automatically imported as playlists.
2. **Metadata Extraction**: Built-in pure Python parsers extract:
   - **MP3**: ID3v2.2, ID3v2.3, ID3v2.4 (UTF-8, UTF-16, ISO-8859-1), ID3v1 fallback, and MPEG audio frame headers for duration & bitrate.
   - **M4A / AAC / ALAC**: MP4 atom box tree (`moov/udta/meta/ilst`) extracting `@nam` (Title), `@ART` (Artist), `@alb` (Album), `gnre` / `@gen` (Genre), `trkn` (Track/Total), and `©day` (Year).
   - **WAV**: RIFF/WAVE header parsing for PCM sample rate, channels, and duration.
   - **Playlists**: `.m3u` / `.m3u8` playlist files are automatically parsed into iPod playlists.
3. **Directory Sharding**: Loose files are automatically organized and sharded into FAT32 directories `iPod_Control/Music/F00` through `F49` to prevent FAT32 directory table performance degradation on the iPod hard drive.
4. **Binary `iTunesDB` Generation**: Generates compliant Apple database atoms:
   - `mhbd`: Root database header (version 25 / `0x19`, platform 2 = Windows FAT32).
   - `mhsd` Dataset 1: Track list (`mhlt` containing 624-byte `mhit` track descriptors and `mhod` string records for Title, iPod colon path, Album, Artist, Genre, and Encoding type).
   - `mhsd` Dataset 2: Playlist list (`mhlp` containing `mhyp` playlist records and `mhip` track index pointers).
   - Zero-filled `Play Counts` and valid `iPod_Control/Device/SysInfo` to prevent reset loops.

> [!NOTE]
> **No Cryptographic Hash Required**: While 6th Gen Classic and 3rd+ Gen Nano introduced cryptographic database hashing (Hash58/Hash72), the iPod Video 5.5G (PP5022A) accepts unhashed `iTunesDB` files directly, making this pure-Python implementation 100% native and permanent.

### 6.2 Workflow & Usage

#### Option A: Run from your Computer
```bash
# Simply pass the iPod drive mount point
./ipod_tool.py sync /media/user/IPOD
```

#### Option B: Standalone / Portable Execution
You can also run `ipod_indexer.py` directly without `ipod_tool.py`:
```bash
python3 ipod_indexer.py /media/user/IPOD
```

### 6.3 On-Device Portable AutoSync
When you run `sync` for the first time, `ipod_tool.py` automatically installs a standalone `AutoSync.py` onto the root of your iPod!
- Whenever you plug your iPod into *any* computer (Linux, Windows, macOS):
  1. Drag your songs into the iPod's `Music` folder.
  2. Double-click or run:
     ```bash
     python3 AutoSync.py
     ```
  3. Safely eject. All songs are immediately available in the iPod Music menu!

### 6.4 Supported Audio Formats & Tags
| Format | Extension | Codec Compatibility | Tag Extraction Support |
| :--- | :--- | :--- | :--- |
| **MP3** | `.mp3` | MPEG-1/2 Audio Layer III (up to 320 kbps) | ID3v2.2, ID3v2.3, ID3v2.4, ID3v1 |
| **AAC** | `.m4a`, `.aac` | Advanced Audio Coding (LC-AAC up to 320 kbps) | MP4 `moov/udta/meta/ilst` |
| **Apple Lossless** | `.m4a`, `.alac`| 16-bit 44.1kHz ALAC lossless audio | MP4 `moov/udta/meta/ilst` |
| **WAV** | `.wav` | Uncompressed PCM stereo 16-bit | RIFF/WAVE header chunk |

---

## 7. Flashing Guide

### Method 1: Direct Partition Write with `dd` (Recommended)
This method is the cleanest and most reliable way to flash custom firmware directly to the iPod without relying on iTunes.

1. Put your iPod into **Disk Mode**:
   - Hold **SELECT (Center) + MENU** for ~6 seconds until the Apple logo appears.
   - Immediately hold **SELECT (Center) + PLAY/PAUSE** until "Disk Mode" appears on screen.
2. Connect the iPod to your computer via USB.
3. Identify the block device:
   ```bash
   lsblk -f
   ```
   You will see two partitions:
   - Partition 1 (`/dev/sdX1`): **Firmware Partition** (~32 MB - 40 MB).
   - Partition 2 (`/dev/sdX2`): **Data Partition** (FAT32/HFS+ containing `/iPod_Control/` and music).
4. Flash the firmware partition:
   ```bash
   sudo dd if=unpacked_fw/firmware_partition.bin of=/dev/sdX1 bs=4096 status=progress conv=fsync
   ```
   > [!CAUTION]
   > Ensure `/dev/sdX1` is the firmware partition and **NOT** `/dev/sdX2` (your music partition) or `/dev/sdX` (the whole drive MBR).
5. Flush buffers and eject safely:
   ```bash
   sudo sync && sudo eject /dev/sdX
   ```
6. Reboot the iPod: Hold **SELECT + MENU** for 6 seconds. The bootloader boots directly into your modified firmware!

### Method 2: iTunes / Finder Restore
1. Open iTunes (or Finder on macOS Catalina+).
2. While holding **Shift** (Windows) or **Option** (macOS), click **"Restore iPod..."**.
3. Select `custom_iPod_25.1.3.ipsw`.
4. Allow iTunes to flash the custom package.

---

## 8. Repository Structure

```
├── ipod_tool.py               # Complete unpacking, patching, and rebuilding CLI tool
├── ipod_indexer.py            # Standalone zero-dependency Drop & Sync iTunesDB engine
├── iPod_25.1.3.ipsw           # Stock Apple iPod Video 5.5G Firmware 1.3
├── iPodDocumentation_25.1.3.ipd # Stock Apple iPod documentation package
├── rea_evidence.json          # REA formal analysis evidence bundle
├── references/                # Historical source reference implementations
│   ├── ipod_fw.c              # Rockbox iPod firmware extraction utility
│   ├── ipodpatcher.c          # Rockbox bootloader installer & partition writer
│   ├── firmware.h             # iPodWizard firmware definitions & resource types
│   ├── ipodwizard_firmware.cpp# iPodWizard resource scanner & patcher
│   └── Picture.cpp            # iPodWizard bitmap graphic decoder
└── .gitignore                 # Excludes ephemeral build binaries & extracted dumps
```

---

## License & Credits
- Reverse engineering & tooling suite built with **REA (Reverse Engineer Anything)**.
- Firmware format specifications derived from community projects including **iPodLinux**, **Rockbox**, and **iPodWizard**.
- iPod is a registered trademark of Apple Inc. This toolkit is intended for device modding, preservation, and research.
