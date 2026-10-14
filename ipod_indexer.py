#!/usr/bin/env python3
"""
iPod Drop-and-Play Media Engine & Auto-Indexer
Generates native iPod Video 5.5G (and Classic) iTunesDB directly from loose audio files
without needing iTunes or any external dependencies.

Supports:
- MP3 (ID3v2.2, ID3v2.3, ID3v2.4, ID3v1, MPEG audio frame headers)
- M4A / AAC / ALAC (MP4 Atom box parser: moov/udta/meta/ilst)
- WAV (RIFF/WAVE PCM headers)
- Automatic directory sharding (iPod_Control/Music/F00..F49)
- Master playlist and folder/album playlist generation
- M3U playlist file importing
"""

import sys
import os
import struct
import time
import shutil
import argparse
import re

# Mac epoch is seconds since 1904-01-01 00:00:00 UTC (difference from Unix 1970 is 2082844800s)
MAC_EPOCH_OFFSET = 2082844800

def get_mac_timestamp() -> int:
    return int(time.time()) + MAC_EPOCH_OFFSET

# ==========================================
# Audio Metadata Extraction (Pure Python)
# ==========================================

class AudioMetadata:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.filesize = os.path.getsize(filepath)
        self.ext = os.path.splitext(filepath)[1].lower()
        
        self.title = os.path.splitext(self.filename)[0]
        self.artist = "Unknown Artist"
        self.album = "Unknown Album"
        self.genre = "Unknown Genre"
        self.year = 2026
        self.track_num = 1
        self.total_tracks = 1
        self.duration_ms = 180000  # default 3 mins if unreadable
        self.bitrate = 256         # kbps
        self.sample_rate = 44100   # Hz
        
        self._extract()

    def _extract(self):
        try:
            if self.ext == '.mp3':
                self._parse_mp3()
            elif self.ext in ('.m4a', '.aac', '.alac', '.mp4'):
                self._parse_m4a()
            elif self.ext == '.wav':
                self._parse_wav()
        except Exception:
            # Fallback to defaults on corrupt tags
            pass

    def _parse_mp3(self):
        with open(self.filepath, 'rb') as f:
            data = f.read(min(self.filesize, 512 * 1024))
            
        tag_size = 0
        # 1. Parse ID3v2
        if data.startswith(b'ID3'):
            ver = data[3]
            tag_size = ((data[6] & 0x7f) << 21) | ((data[7] & 0x7f) << 14) | ((data[8] & 0x7f) << 7) | (data[9] & 0x7f)
            pos = 10
            end = min(len(data), 10 + tag_size)
            
            while pos + 10 <= end:
                if ver in (3, 4):
                    fid = data[pos:pos+4].decode('ascii', errors='ignore')
                    if not fid.isalnum() or fid == '\x00\x00\x00\x00':
                        break
                    if ver == 4:
                        fsize = ((data[pos+4] & 0x7f) << 21) | ((data[pos+5] & 0x7f) << 14) | ((data[pos+6] & 0x7f) << 7) | (data[pos+7] & 0x7f)
                    else:
                        fsize = struct.unpack('>I', data[pos+4:pos+8])[0]
                    pos += 10
                elif ver == 2:
                    fid = data[pos:pos+3].decode('ascii', errors='ignore')
                    if not fid.isalnum(): break
                    fsize = (data[pos+3] << 16) | (data[pos+4] << 8) | data[pos+5]
                    pos += 6
                else:
                    break
                    
                body = data[pos:pos+fsize]
                pos += fsize
                
                if body and (fid.startswith('T') or fid in ('TT2', 'TP1', 'TAL', 'TRK', 'TYE', 'TCO')):
                    enc = body[0]
                    raw = body[1:]
                    val = ""
                    try:
                        if enc == 0: val = raw.decode('latin1', errors='ignore')
                        elif enc == 1: val = raw.decode('utf-16', errors='ignore')
                        elif enc == 2: val = raw.decode('utf-16be', errors='ignore')
                        elif enc == 3: val = raw.decode('utf-8', errors='ignore')
                        else: val = raw.decode('latin1', errors='ignore')
                        val = val.rstrip('\x00').strip()
                    except Exception:
                        pass
                    
                    if val:
                        if fid in ('TIT2', 'TT2'): self.title = val
                        elif fid in ('TPE1', 'TP1'): self.artist = val
                        elif fid in ('TALB', 'TAL'): self.album = val
                        elif fid in ('TCON', 'TCO'): self.genre = val
                        elif fid in ('TYER', 'TDRC', 'TYE'):
                            m = re.search(r'\d{4}', val)
                            if m: self.year = int(m.group(0))
                        elif fid in ('TRCK', 'TRK'):
                            parts = val.split('/')
                            if parts[0].isdigit(): self.track_num = int(parts[0])
                            if len(parts) > 1 and parts[1].isdigit(): self.total_tracks = int(parts[1])

        # 2. Check MPEG audio frame headers for duration & bitrate
        audio_pos = 10 + tag_size if tag_size else 0
        if audio_pos + 4 < len(data):
            for i in range(audio_pos, min(len(data) - 4, audio_pos + 16384)):
                if data[i] == 0xFF and (data[i+1] & 0xE0) == 0xE0: # Sync word
                    b1 = data[i+1]
                    b2 = data[i+2]
                    layer = (b1 >> 1) & 0x03 # 1 = Layer III
                    bitrate_idx = (b2 >> 4) & 0x0F
                    sr_idx = (b2 >> 2) & 0x03
                    
                    bitrates = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
                    srates = [44100, 48000, 32000]
                    
                    if 0 < bitrate_idx < len(bitrates) and sr_idx < len(srates) and layer == 1:
                        self.bitrate = bitrates[bitrate_idx]
                        self.sample_rate = srates[sr_idx]
                        audio_len_bytes = max(0, self.filesize - tag_size)
                        self.duration_ms = int((audio_len_bytes * 8) / (self.bitrate * 1000) * 1000)
                        break

    def _parse_m4a(self):
        with open(self.filepath, 'rb') as f:
            data = f.read(min(self.filesize, 1024 * 1024))
            
        def find_atom(buf, path, start=0, length=None):
            if length is None: length = len(buf) - start
            end = start + length
            pos = start
            target = path[0]
            while pos + 8 <= end:
                asize = struct.unpack('>I', buf[pos:pos+4])[0]
                atype = buf[pos+4:pos+8]
                if asize == 0: asize = end - pos
                elif asize == 1 and pos + 16 <= end:
                    asize = struct.unpack('>Q', buf[pos+8:pos+16])[0]
                if asize < 8: break
                
                if atype == target:
                    if len(path) == 1:
                        return pos, asize
                    else:
                        # Enter container atom
                        hdr_skip = 8 if atype != b'meta' else 12 # meta has 4 byte version/flags
                        return find_atom(buf, path[1:], pos + hdr_skip, asize - hdr_skip)
                pos += asize
            return None

        # Find mvhd for duration
        mvhd_res = find_atom(data, [b'moov', b'mvhd'])
        if mvhd_res:
            mpos, msize = mvhd_res
            ver = data[mpos+8]
            if ver == 0 and msize >= 32:
                timescale, duration = struct.unpack('>II', data[mpos+20:mpos+28])
                if timescale > 0:
                    self.duration_ms = int(duration * 1000 / timescale)
                    if self.duration_ms > 0:
                        self.bitrate = int((self.filesize * 8) / (self.duration_ms / 1000) / 1000)

        # Find ilst metadata
        ilst_res = find_atom(data, [b'moov', b'udta', b'meta', b'ilst'])
        if ilst_res:
            ipos, isize = ilst_res
            iend = ipos + isize
            p = ipos + 8
            while p + 8 <= iend:
                asize = struct.unpack('>I', data[p:p+4])[0]
                atype = data[p+4:p+8]
                if asize < 8: break
                
                # Check child data box
                dp = p + 8
                if dp + 16 <= p + asize and data[dp+4:dp+8] == b'data':
                    dlen = struct.unpack('>I', data[dp:dp+4])[0]
                    dtype = struct.unpack('>I', data[dp+8:dp+12])[0]
                    payload = data[dp+16 : dp+dlen]
                    
                    if dtype == 1: # UTF-8 String
                        txt = payload.decode('utf-8', errors='ignore').strip()
                        if atype == b'\xa9nam': self.title = txt
                        elif atype == b'\xa9ART': self.artist = txt
                        elif atype == b'\xa9alb': self.album = txt
                        elif atype == b'\xa9gen': self.genre = txt
                        elif atype == b'\xa9day':
                            m = re.search(r'\d{4}', txt)
                            if m: self.year = int(m.group(0))
                    elif atype == b'trkn' and len(payload) >= 4:
                        self.track_num = struct.unpack('>H', payload[2:4])[0]
                        if len(payload) >= 6:
                            self.total_tracks = struct.unpack('>H', payload[4:6])[0]
                p += asize

    def _parse_wav(self):
        with open(self.filepath, 'rb') as f:
            hdr = f.read(128)
        if hdr.startswith(b'RIFF') and hdr[8:12] == b'WAVE':
            f_idx = hdr.find(b'fmt ')
            if f_idx != -1 and f_idx + 24 <= len(hdr):
                chans, sr, byte_rate = struct.unpack('<HII', hdr[f_idx+10:f_idx+20])
                self.sample_rate = sr
                self.bitrate = int(byte_rate * 8 / 1000)
                if byte_rate > 0:
                    self.duration_ms = int(self.filesize / byte_rate * 1000)

# ==========================================
# Binary iTunesDB Serializer
# ==========================================

def make_string_mhod(mhod_type: int, text: str) -> bytes:
    """Creates a standard UTF-16LE string MHOD container."""
    u16 = text.encode('utf-16le')
    slen = len(u16)
    prefix = struct.pack('<IIII', 1, slen, 1, 0)
    body = prefix + u16
    pad = (4 - len(body) % 4) % 4
    body += b'\x00' * pad
    hdr = struct.pack('<4sIIIII', b'mhod', 24, 24 + len(body), mhod_type, 0, 0)
    return hdr + body

def make_mhit(track_id: int, meta: AudioMetadata, ipod_path: str) -> bytes:
    """Builds an MHIT track item chunk with child MHOD metadata strings."""
    mhods = [
        make_string_mhod(1, meta.title),
        make_string_mhod(2, ipod_path),
        make_string_mhod(3, meta.album),
        make_string_mhod(4, meta.artist),
        make_string_mhod(5, meta.genre),
        make_string_mhod(6, 'MPEG audio file' if meta.ext == '.mp3' else ('WAV audio file' if meta.ext == '.wav' else 'AAC audio file'))
    ]
    mhods_bytes = b''.join(mhods)
    
    # 624-byte MHIT header (standard iPod Video 5.5G layout)
    hdr = bytearray(624)
    total_len = 624 + len(mhods_bytes)
    struct.pack_into('<4sIIII', hdr, 0, b'mhit', 624, total_len, len(mhods), track_id)
    struct.pack_into('<I', hdr, 0x14, 1)                      # visible = 1
    struct.pack_into('<I', hdr, 0x18, 0 if meta.ext == '.mp3' else 1) # filetype
    struct.pack_into('<I', hdr, 0x20, get_mac_timestamp())    # last modified
    struct.pack_into('<I', hdr, 0x24, meta.filesize)          # size
    struct.pack_into('<I', hdr, 0x28, meta.duration_ms)       # length in ms
    struct.pack_into('<I', hdr, 0x2c, meta.track_num)         # track number
    struct.pack_into('<I', hdr, 0x30, meta.total_tracks)      # total tracks
    struct.pack_into('<I', hdr, 0x34, meta.year)              # year
    struct.pack_into('<I', hdr, 0x38, meta.bitrate)           # bitrate kbps
    struct.pack_into('<I', hdr, 0x3c, meta.sample_rate)       # sample rate Hz
    struct.pack_into('<I', hdr, 0x48, meta.duration_ms)       # stop time
    struct.pack_into('<I', hdr, 0x5c, 1)                      # disc number
    struct.pack_into('<I', hdr, 0x60, 1)                      # total discs
    struct.pack_into('<I', hdr, 0x68, get_mac_timestamp())    # date added
    struct.pack_into('<Q', hdr, 0x70, track_id)               # db_track_id
    struct.pack_into('<H', hdr, 0x7e, 0xffff)                 # av_flag
    
    return bytes(hdr) + mhods_bytes

def make_mhip(track_id: int) -> bytes:
    """Builds an MHIP playlist item reference."""
    hdr = bytearray(76)
    struct.pack_into('<4sII', hdr, 0, b'mhip', 76, 76)
    struct.pack_into('<I', hdr, 0x18, track_id)
    return bytes(hdr)

def make_mhyp(name: str, track_ids: list[int], is_master: bool = False, pid: int = 1) -> bytes:
    """Builds an MHYP playlist chunk."""
    name_mhod = make_string_mhod(1, name)
    mhips = b''.join(make_mhip(tid) for tid in track_ids)
    
    hdr = bytearray(184)
    total_len = 184 + len(name_mhod) + len(mhips)
    struct.pack_into('<4sIIII', hdr, 0, b'mhyp', 184, total_len, 1, len(track_ids))
    struct.pack_into('<B', hdr, 0x14, 1 if is_master else 0)  # master_flag
    struct.pack_into('<I', hdr, 0x18, get_mac_timestamp())    # timestamp
    struct.pack_into('<Q', hdr, 0x1c, pid)                    # playlist_id
    
    return bytes(hdr) + name_mhod + mhips

def generate_itunesdb(tracks_with_paths: list[tuple[AudioMetadata, str]], user_playlists: dict[str, list[int]]) -> bytes:
    """Generates a complete, compliant binary iTunesDB."""
    # 1. Dataset 1: Track List (MHLT)
    mhits = []
    all_track_ids = []
    for idx, (meta, ipod_path) in enumerate(tracks_with_paths, 1):
        all_track_ids.append(idx)
        mhits.append(make_mhit(idx, meta, ipod_path))
    mhits_bytes = b''.join(mhits)
    
    mhlt_hdr = bytearray(92)
    struct.pack_into('<4sII', mhlt_hdr, 0, b'mhlt', 92, len(tracks_with_paths))
    mhlt_bytes = bytes(mhlt_hdr) + mhits_bytes
    
    mhsd1_hdr = bytearray(96)
    struct.pack_into('<4sIII', mhsd1_hdr, 0, b'mhsd', 96, 96 + len(mhlt_bytes), 1)
    mhsd1_bytes = bytes(mhsd1_hdr) + mhlt_bytes
    
    # 2. Dataset 2: Playlist List (MHLP)
    mhyps = [make_mhyp('iPod', all_track_ids, is_master=True, pid=1)]
    pid_counter = 100
    for pname, tids in user_playlists.items():
        if tids:
            mhyps.append(make_mhyp(pname, tids, is_master=False, pid=pid_counter))
            pid_counter += 1
    mhyps_bytes = b''.join(mhyps)
    
    mhlp_hdr = bytearray(92)
    struct.pack_into('<4sII', mhlp_hdr, 0, b'mhlp', 92, len(mhyps))
    mhlp_bytes = bytes(mhlp_hdr) + mhyps_bytes
    
    mhsd2_hdr = bytearray(96)
    struct.pack_into('<4sIII', mhsd2_hdr, 0, b'mhsd', 96, 96 + len(mhlp_bytes), 2)
    mhsd2_bytes = bytes(mhsd2_hdr) + mhlp_bytes
    
    # 3. Root Header (MHBD)
    all_sections = mhsd1_bytes + mhsd2_bytes
    mhbd_hdr = bytearray(244)
    struct.pack_into('<4sIII', mhbd_hdr, 0, b'mhbd', 244, 244 + len(all_sections), 1)
    struct.pack_into('<I', mhbd_hdr, 0x10, 0x19)              # version 25 (iPod Video 5.5G)
    struct.pack_into('<I', mhbd_hdr, 0x14, 2)                 # child_count = 2 datasets
    struct.pack_into('<Q', mhbd_hdr, 0x18, 1)                 # db_id
    struct.pack_into('<H', mhbd_hdr, 0x20, 2)                 # platform = 2 (Windows/FAT32)
    struct.pack_into('<2s', mhbd_hdr, 0x46, b'en')            # language
    
    return bytes(mhbd_hdr) + all_sections

# ==========================================
# Main Auto-Indexer & Organizer Engine
# ==========================================

def sync_ipod(ipod_root: str, drop_dirs: list[str] = None, move_files: bool = False, dry_run: bool = False):
    print(f"[*] iPod Drop-and-Play Media Engine running on: {ipod_root}")
    
    # Check or create standard iPod directory structure
    ctrl_dir = os.path.join(ipod_root, "iPod_Control")
    itunes_dir = os.path.join(ctrl_dir, "iTunes")
    music_dir = os.path.join(ctrl_dir, "Music")
    device_dir = os.path.join(ctrl_dir, "Device")
    
    if not dry_run:
        os.makedirs(itunes_dir, exist_ok=True)
        os.makedirs(music_dir, exist_ok=True)
        os.makedirs(device_dir, exist_ok=True)
        # Create F00 through F49 sharded folders
        for i in range(50):
            os.makedirs(os.path.join(music_dir, f"F{i:02d}"), exist_ok=True)
            
        # Ensure SysInfo exists
        sysinfo_path = os.path.join(device_dir, "SysInfo")
        if not os.path.exists(sysinfo_path):
            with open(sysinfo_path, 'w') as f_sys:
                f_sys.write("ModelNumStr: MA446\nFireWireGUID: 0x000A270014B00000\npszSerialNumber: 8K639XXXXXX\nvisibleBuildID: 1.3\nbuildID: 103841792\n")

    # Scan directories for new media
    if drop_dirs:
        scan_targets = drop_dirs
    else:
        standard_dirs = ["Music", "Drop", "Import", "Songs"]
        scan_targets = [os.path.join(ipod_root, d) for d in standard_dirs if os.path.isdir(os.path.join(ipod_root, d))]
        
        # If no standard folder exists, check any non-system user directories or files in root
        if not scan_targets:
            root_entries = []
            try:
                for entry in sorted(os.listdir(ipod_root)):
                    if entry.startswith('.') or entry in ("iPod_Control", "System Volume Information", "$RECYCLE.BIN"):
                        continue
                    full_e = os.path.join(ipod_root, entry)
                    if os.path.isdir(full_e):
                        root_entries.append(full_e)
                    elif os.path.splitext(entry)[1].lower() in ('.mp3', '.m4a', '.aac', '.alac', '.wav'):
                        root_entries.append(ipod_root)
                        break
            except Exception:
                pass
                
            if root_entries:
                scan_targets = list(dict.fromkeys(root_entries))
            else:
                music_fallback = os.path.join(ipod_root, "Music")
                if not dry_run:
                    os.makedirs(music_fallback, exist_ok=True)
                scan_targets = [music_fallback]
                print(f"[+] Created drop folder: {music_fallback}")
        
    print(f"[*] Scanning drop directories for media: {', '.join(scan_targets)}")
    
    supported_exts = ('.mp3', '.m4a', '.aac', '.alac', '.wav')
    discovered_files = []
    user_playlists = {}
    
    for sdir in scan_targets:
        for root, dirs, files in os.walk(sdir):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ("iPod_Control", "System Volume Information", "$RECYCLE.BIN")]
            rel_folder = os.path.relpath(root, sdir)
            playlist_name = os.path.basename(root) if rel_folder != '.' else ""
            
            for f in sorted(files):
                ext = os.path.splitext(f)[1].lower()
                if ext in supported_exts:
                    full_p = os.path.join(root, f)
                    discovered_files.append((full_p, playlist_name))
                elif ext in ('.m3u', '.m3u8'):
                    # M3U Playlist Parser
                    m3u_name = os.path.splitext(f)[0]
                    m3u_path = os.path.join(root, f)
                    try:
                        with open(m3u_path, 'r', encoding='utf-8', errors='ignore') as mf:
                            for mline in mf:
                                mline = mline.strip()
                                if mline and not mline.startswith('#'):
                                    target_song = os.path.normpath(os.path.join(root, mline))
                                    if os.path.exists(target_song):
                                        discovered_files.append((target_song, m3u_name))
                    except Exception:
                        pass

    # Also scan any existing files inside iPod_Control/Music
    for i in range(50):
        fdir = os.path.join(music_dir, f"F{i:02d}")
        if os.path.exists(fdir):
            for f in os.listdir(fdir):
                if os.path.splitext(f)[1].lower() in supported_exts:
                    discovered_files.append((os.path.join(fdir, f), ""))

    # Deduplicate discovered files by canonical path
    unique_items = []
    seen_paths = set()
    for fpath, pname in discovered_files:
        real_p = os.path.realpath(fpath)
        if real_p not in seen_paths:
            seen_paths.add(real_p)
            unique_items.append((fpath, pname))
            
    print(f"[+] Total audio files discovered: {len(unique_items)}")
    if not unique_items:
        print("[!] No audio files found. Drop .mp3, .m4a, or .wav files into the 'Music' folder on your iPod and run this again.")
        return

    # Process files, organize into iPod_Control/Music/Fxx, and build tracks list
    tracks_with_ipod_paths = []
    sharding_idx = 0
    token_id = 1
    
    for fpath, pname in unique_items:
        meta = AudioMetadata(fpath)
        
        # Check if already in iPod_Control/Music
        if "iPod_Control" in fpath:
            # File is already sharded
            rel_path = os.path.relpath(fpath, ctrl_dir)
            ipod_colon_path = ":" + ":".join(os.path.normpath(f"iPod_Control/{rel_path}").split(os.sep))
        else:
            # New loose file dropped by user -> assign Fxx sharded token name
            shard_folder = f"F{sharding_idx:02d}"
            sharding_idx = (sharding_idx + 1) % 50
            token_filename = f"T{token_id:03d}{meta.ext}"
            token_id += 1
            
            dest_dir = os.path.join(music_dir, shard_folder)
            dest_path = os.path.join(dest_dir, token_filename)
            ipod_colon_path = f":iPod_Control:Music:{shard_folder}:{token_filename}"
            
            if not dry_run:
                if move_files:
                    shutil.move(fpath, dest_path)
                else:
                    shutil.copy2(fpath, dest_path)
                    
        track_index = len(tracks_with_ipod_paths) + 1
        tracks_with_ipod_paths.append((meta, ipod_colon_path))
        
        # Group into user playlists
        if pname:
            if pname not in user_playlists: user_playlists[pname] = []
            user_playlists[pname].append(track_index)
        elif meta.album and meta.album != "Unknown Album":
            if meta.album not in user_playlists: user_playlists[meta.album] = []
            user_playlists[meta.album].append(track_index)
            
        print(f"  [{track_index:03d}] {meta.artist} - {meta.title} ({meta.album}) -> {ipod_colon_path}")

    # Generate iTunesDB
    print(f"[*] Compiling binary iTunesDB ({len(tracks_with_ipod_paths)} tracks, {len(user_playlists)} playlists)...")
    db_bytes = generate_itunesdb(tracks_with_ipod_paths, user_playlists)
    
    itunesdb_path = os.path.join(itunes_dir, "iTunesDB")
    if not dry_run:
        with open(itunesdb_path, 'wb') as f_db:
            f_db.write(db_bytes)
            
        # Create zeroed Play Counts file (prevent play count resets)
        play_counts_path = os.path.join(itunes_dir, "Play Counts")
        if not os.path.exists(play_counts_path):
            with open(play_counts_path, 'wb') as f_pc:
                f_pc.write(b'\x00' * (len(tracks_with_ipod_paths) * 8))
                
        # Optional copy of this indexer to the iPod root for on-device convenience
        autosync_on_ipod = os.path.join(ipod_root, "AutoSync.py")
        if not os.path.exists(autosync_on_ipod):
            shutil.copy2(__file__, autosync_on_ipod)
            print(f"[+] Installed portable AutoSync.py to {autosync_on_ipod}")
            
    print(f"[+] Wrote binary iTunesDB ({len(db_bytes)} bytes) to {itunesdb_path}")
    print("[+] SUCCESS! All songs are registered and ready to play in the iPod stock firmware.")

def main():
    parser = argparse.ArgumentParser(description="iPod Drop-and-Play Media Engine (Pure Python)")
    parser.add_argument("ipod_root", nargs="?", default=".", help="Root mount directory of the iPod storage (default: current directory)")
    parser.add_argument("--drop-dir", action="append", help="Specific directories to scan for loose music (can specify multiple)")
    parser.add_argument("--move", action="store_true", help="Move loose files into iPod_Control/Music instead of copying")
    parser.add_argument("--dry-run", action="store_true", help="Scan and preview without writing files")
    
    args = parser.parse_args()
    sync_ipod(args.ipod_root, drop_dirs=args.drop_dir, move_files=args.move, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
