#!/usr/bin/env python3
"""
iPod Video 5.5G (iPod 5G Enhanced) Firmware Reverse Engineering & Rebuilding Suite
Reverses, modifies, repacks, and prepares firmware for flashing on iPod 5th / 5.5th Gen.
"""

import sys
import os
import struct
import json
import zipfile
import shutil
import argparse

# Constants for iPod Video 5.5G (PP5022A / Firmware-25.6.3)
APPLE_STOP_SIGN = b"{{~~  /-----\\   {{~~ /       \\  {{~~|         | {{~~| S T O P | {{~~|         | {{~~ \\       /  {{~~  \\-----/   Copyright(C) 2001 Apple Computer, Inc.---------------------------------------------------------------------------------------------------------"
IH_MAGIC = b"]ih["
DIR_OFFSET_HEADER = 0x104
VERSION_HEADER = 0x10a
IMAGE_PADDING_V3 = 2048  # 2048-byte sector padding for fw_version 3
RESOURCE_BLOCK_OFFSET = 0x00331da0
LOAD_ADDR_OSOS = 0x10000000

def compute_checksum(data: bytes) -> int:
    """32-bit sum of unsigned bytes modulo 2^32."""
    return sum(data) & 0xFFFFFFFF

def parse_firmware_header(fw_bytes: bytes):
    if not fw_bytes.startswith(b"{{~~  /-----\\"):
        raise ValueError("Invalid Apple firmware: missing stop sign signature")
    if fw_bytes[0x100:0x104] != IH_MAGIC:
        raise ValueError("Invalid Apple firmware: missing ]ih[ magic signature at 0x100")
    
    diroffset_raw = struct.unpack('<I', fw_bytes[0x104:0x108])[0]
    fw_version = struct.unpack('<H', fw_bytes[0x10a:0x10c])[0]
    diroffset = diroffset_raw + 0x200
    
    entries = []
    p = diroffset
    while p + 40 <= len(fw_bytes):
        sig = fw_bytes[p:p+4]
        if sig not in (b'!ATA', b'DNAN'):
            break
        ftype = fw_bytes[p+4:p+8]
        (img_id, devOffset, length, addr, entryOffset, chksum, vers, loadAddr) = struct.unpack('<IIIIIIII', fw_bytes[p+8:p+40])
        entries.append({
            "sig": sig.decode(errors='ignore'),
            "type_raw": ftype,
            "type": ftype[::-1].decode(errors='ignore'),
            "id": img_id,
            "devOffset": devOffset,
            "len": length,
            "addr": addr,
            "entryOffset": entryOffset,
            "chksum": chksum,
            "vers": vers,
            "loadAddr": loadAddr,
            "entry_index": len(entries)
        })
        p += 40
        
    return {
        "diroffset_raw": diroffset_raw,
        "diroffset": diroffset,
        "fw_version": fw_version,
        "entries": entries
    }

def unpack_ipsw(ipsw_path: str, out_dir: str):
    print(f"[*] Unpacking IPSW archive: {ipsw_path} -> {out_dir}")
    os.makedirs(out_dir, exist_ok=True)
    
    with zipfile.ZipFile(ipsw_path, 'r') as z:
        z.extractall(out_dir)
        
    fw_name = None
    for name in os.listdir(out_dir):
        if name.startswith("Firmware-"):
            fw_name = name
            break
            
    if not fw_name:
        raise FileNotFoundError("Firmware payload not found in unpacked IPSW")
        
    fw_path = os.path.join(out_dir, fw_name)
    with open(fw_path, 'rb') as f:
        fw_bytes = f.read()
        
    info = parse_firmware_header(fw_bytes)
    print(f"[+] Found {len(info['entries'])} sub-images in {fw_name} (fw_version={info['fw_version']}):")
    
    extracted_images_dir = os.path.join(out_dir, "images")
    os.makedirs(extracted_images_dir, exist_ok=True)
    
    for entry in info["entries"]:
        tname = entry["type"].lower()
        devOff = entry["devOffset"]
        length = entry["len"]
        
        file_off = devOff + (IMAGE_PADDING_V3 if info["fw_version"] == 3 else 0)
        img_data = fw_bytes[file_off : file_off + length]
        computed_sum = compute_checksum(img_data)
        
        print(f"    - Image [{entry['type']}] (devOffset=0x{devOff:08x}, len={length} bytes, addr=0x{entry['addr']:08x})")
        print(f"      File offset: 0x{file_off:08x}, Checksum: 0x{entry['chksum']:08x} (matches: {computed_sum == entry['chksum']})")
        
        img_out = os.path.join(extracted_images_dir, f"{tname}_raw.bin")
        with open(img_out, 'wb') as f:
            f.write(img_data)
            
        # Specific sub-image handlers
        if tname == "rsrc":
            # Extract FAT16 filesystem (offset 0x600 in RSRC)
            entry_off = entry["entryOffset"]
            fat_data = img_data[entry_off:]
            fat_path = os.path.join(extracted_images_dir, "rsrc.fat")
            with open(fat_path, 'wb') as f:
                f.write(fat_data)
            print(f"      [+] Extracted FAT16 filesystem to {fat_path} ({len(fat_data)} bytes)")
            
            # Extract files from FAT16 using 7z if available
            rsrc_files_dir = os.path.join(out_dir, "rsrc_extracted")
            os.makedirs(rsrc_files_dir, exist_ok=True)
            ret = os.system(f"7z x -y -o{rsrc_files_dir} {fat_path} >/dev/null 2>&1")
            if ret == 0:
                print(f"      [+] Extracted FAT16 filesystem contents to {rsrc_files_dir}")
                
    # Save meta json
    meta = {
        "fw_name": fw_name,
        "fw_version": info["fw_version"],
        "diroffset_raw": info["diroffset_raw"],
        "diroffset": info["diroffset"],
        "entries": [
            {
                "sig": e["sig"],
                "type": e["type"],
                "type_raw": e["type_raw"].decode(errors='latin1'),
                "id": e["id"],
                "devOffset": e["devOffset"],
                "len": e["len"],
                "addr": e["addr"],
                "entryOffset": e["entryOffset"],
                "chksum": e["chksum"],
                "vers": e["vers"],
                "loadAddr": e["loadAddr"]
            } for e in info["entries"]
        ]
    }
    with open(os.path.join(out_dir, "firmware_meta.json"), 'w') as f:
        json.dump(meta, f, indent=2)
        
    print(f"[+] Saved metadata to {os.path.join(out_dir, 'firmware_meta.json')}")
    
    # Extract strings and bitmaps from osos_raw.bin
    osos_path = os.path.join(extracted_images_dir, "osos_raw.bin")
    if os.path.exists(osos_path):
        dump_strings(osos_path, os.path.join(out_dir, "ui_strings.json"))
        dump_bitmaps(osos_path, os.path.join(out_dir, "bitmaps"))

def dump_strings(osos_path: str, out_json_path: str):
    print(f"[*] Extracting UI strings from {osos_path}...")
    with open(osos_path, 'rb') as f:
        data = f.read()
        
    off = RESOURCE_BLOCK_OFFSET
    z1, length, num_sections = struct.unpack('<III', data[off:off+12])
    data_start = off + length
    
    p = off + 12
    sections = []
    for s in range(num_sections):
        stype, num_items, t1, start = struct.unpack('<4sIII', data[p:p+16])
        sections.append((stype, num_items, t1, start))
        p += 16
        
    # Find Section ' rtS'
    str_sec_idx = None
    items_before = 0
    for idx, (stype, num_items, t1, start) in enumerate(sections):
        if stype == b' rtS':
            str_sec_idx = idx
            break
        items_before += num_items
        
    if str_sec_idx is None:
        print("[!] No ' rtS' string section found!")
        return
        
    num_strings = sections[str_sec_idx][1]
    res_base = off + 12 + 16 * num_sections
    str_res_base = res_base + items_before * 12
    
    strings_list = []
    for i in range(num_strings):
        res_id, unk1, r_off, r_size = struct.unpack('<hhII', data[str_res_base + i*12 : str_res_base + (i+1)*12])
        raw_str = data[data_start + r_off : data_start + r_off + r_size]
        clean_str = raw_str.split(b'\x00')[0].decode('latin1', errors='ignore')
        strings_list.append({
            "index": i,
            "id": res_id,
            "offset_in_data": r_off,
            "abs_offset_in_bin": data_start + r_off,
            "size": r_size,
            "text": clean_str
        })
        
    with open(out_json_path, 'w', encoding='utf-8') as f:
        json.dump(strings_list, f, indent=2, ensure_ascii=False)
        
    print(f"[+] Dumped {len(strings_list)} UI strings to {out_json_path}")

def inject_strings(osos_path: str, in_json_path: str, out_osos_path: str):
    print(f"[*] Injecting modified UI strings from {in_json_path} into {out_osos_path}...")
    with open(osos_path, 'rb') as f:
        data = bytearray(f.read())
        
    with open(in_json_path, 'r', encoding='utf-8') as f:
        strings_list = json.load(f)
        
    modified_count = 0
    for item in strings_list:
        abs_off = item["abs_offset_in_bin"]
        max_size = item["size"]
        new_text = item["text"].encode('latin1') + b'\x00'
        
        if len(new_text) > max_size:
            print(f"[!] Warning: string #{item['index']} '{item['text']}' length {len(new_text)} exceeds max {max_size}! Truncating.")
            new_text = new_text[:max_size-1] + b'\x00'
            
        old_bytes = data[abs_off : abs_off + len(new_text)]
        if old_bytes != new_text:
            data[abs_off : abs_off + len(new_text)] = new_text
            # Zero out remaining bytes up to max_size
            for z in range(abs_off + len(new_text), abs_off + max_size):
                data[z] = 0
            modified_count += 1
            
    with open(out_osos_path, 'wb') as f:
        f.write(data)
        
    print(f"[+] Injected strings: {modified_count} strings updated. Written to {out_osos_path}")

def dump_bitmaps(osos_path: str, out_dir: str):
    print(f"[*] Extracting UI bitmaps from {osos_path} -> {out_dir}...")
    os.makedirs(out_dir, exist_ok=True)
    
    with open(osos_path, 'rb') as f:
        data = f.read()
        
    off = RESOURCE_BLOCK_OFFSET
    z1, length, num_sections = struct.unpack('<III', data[off:off+12])
    data_start = off + length
    
    res_base = off + 12 + 16 * num_sections
    # Section 0 is BMap (paMB)
    bmap_count = 403
    
    meta_bitmaps = []
    for i in range(bmap_count):
        res_id, unk1, r_off, r_size = struct.unpack('<hhII', data[res_base + i*12 : res_base + (i+1)*12])
        bmp_payload = data[data_start + r_off : data_start + r_off + r_size]
        tex_fmt, d5, bpr, bdepth, b1, h, w, blen = struct.unpack('<HHHH8sIII', bmp_payload[:28])
        raw_pixels = bmp_payload[28:28 + blen]
        
        # Save as BMP file
        bmp_filename = f"bmp_{i:03d}_id{res_id}_{w}x{h}_fmt0x{tex_fmt:x}.bmp"
        bmp_path = os.path.join(out_dir, bmp_filename)
        
        if bdepth == 16 and (tex_fmt == 0x565 or tex_fmt == 0x1444):
            # Decode 16-bit to 24-bit BMP
            rgb24 = bytearray()
            for y in range(h):
                row_bytes = raw_pixels[y*bpr : y*bpr + w*2]
                row_bgr = bytearray()
                for x in range(w):
                    if x*2+2 <= len(row_bytes):
                        pix = struct.unpack('<H', row_bytes[x*2:x*2+2])[0]
                        if tex_fmt == 0x565:
                            r = ((pix >> 11) & 0x1f) << 3
                            g = ((pix >> 5) & 0x3f) << 2
                            b = (pix & 0x1f) << 3
                        else: # 0x1444 (RGBA4444)
                            r = ((pix >> 8) & 0x0f) << 4
                            g = ((pix >> 4) & 0x0f) << 4
                            b = (pix & 0x0f) << 4
                    else:
                        r, g, b = 0, 0, 0
                    row_bgr.extend([b, g, r])
                pad = (4 - (w * 3) % 4) % 4
                row_bgr.extend([0] * pad)
                rgb24 = row_bgr + rgb24
                
            filesize = 14 + 40 + len(rgb24)
            bmp_hdr = struct.pack('<2sIHHI', b'BM', filesize, 0, 0, 54)
            dib_hdr = struct.pack('<IIIHHIIIIII', 40, w, h, 1, 24, 0, len(rgb24), 2835, 2835, 0, 0)
            with open(bmp_path, 'wb') as f_bmp:
                f_bmp.write(bmp_hdr + dib_hdr + rgb24)
        else:
            # Save raw binary for custom depth
            raw_path = os.path.join(out_dir, f"raw_{i:03d}_id{res_id}_{w}x{h}_d{bdepth}.bin")
            with open(raw_path, 'wb') as f_raw:
                f_raw.write(raw_pixels)
                
        meta_bitmaps.append({
            "index": i,
            "id": res_id,
            "offset_in_data": r_off,
            "abs_offset_in_bin": data_start + r_off,
            "size": r_size,
            "width": w,
            "height": h,
            "bytes_per_row": bpr,
            "bit_depth": bdepth,
            "texture_format": hex(tex_fmt),
            "filename": bmp_filename
        })
        
    with open(os.path.join(out_dir, "bitmaps_meta.json"), 'w') as f_meta:
        json.dump(meta_bitmaps, f_meta, indent=2)
        
    print(f"[+] Dumped {bmap_count} bitmaps to {out_dir}")

def inject_bitmap(osos_path: str, index: int, in_bmp_path: str, out_osos_path: str):
    print(f"[*] Injecting custom bitmap from {in_bmp_path} into bitmap index #{index}...")
    with open(osos_path, 'rb') as f:
        data = bytearray(f.read())
        
    off = RESOURCE_BLOCK_OFFSET
    z1, length, num_sections = struct.unpack('<III', data[off:off+12])
    data_start = off + length
    res_base = off + 12 + 16 * num_sections
    
    res_id, unk1, r_off, r_size = struct.unpack('<hhII', data[res_base + index*12 : res_base + (index+1)*12])
    target_off = data_start + r_off
    
    tex_fmt, d5, bpr, bdepth, b1, h, w, blen = struct.unpack('<HHHH8sIII', data[target_off:target_off+28])
    print(f"    Target bitmap #{index}: {w}x{h}, bpp={bdepth}, fmt=0x{tex_fmt:x}, blen={blen}")
    
    with open(in_bmp_path, 'rb') as f_bmp:
        bmp_data = f_bmp.read()
        
    if not bmp_data.startswith(b'BM'):
        raise ValueError("Provided file is not a valid BMP image")
        
    bits_offset = struct.unpack('<I', bmp_data[10:14])[0]
    in_w, in_h = struct.unpack('<II', bmp_data[18:26])
    in_bpp = struct.unpack('<H', bmp_data[28:30])[0]
    
    if in_w != w or in_h != h:
        raise ValueError(f"Bitmap dimensions mismatch: provided {in_w}x{in_h}, expected {w}x{h}")
    if in_bpp != 24:
        raise ValueError("Please provide a 24-bit RGB Windows BMP file")
        
    pixel_data = bmp_data[bits_offset:]
    row_stride = ((w * 3 + 3) // 4) * 4
    
    new_raw = bytearray()
    for y in range(h):
        # BMP is bottom-up: top row in image corresponds to row (h - 1 - y)
        row_start = (h - 1 - y) * row_stride
        row_16 = bytearray()
        for x in range(w):
            b = pixel_data[row_start + x*3]
            g = pixel_data[row_start + x*3 + 1]
            r = pixel_data[row_start + x*3 + 2]
            if tex_fmt == 0x565:
                p16 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            else: # 0x1444
                p16 = 0xF000 | ((r >> 4) << 8) | ((g >> 4) << 4) | (b >> 4)
            row_16.extend(struct.pack('<H', p16))
        new_raw.extend(row_16)
        
    if len(new_raw) > blen:
        raise ValueError("Converted pixel data exceeds allocated blockLen")
        
    data[target_off + 28 : target_off + 28 + len(new_raw)] = new_raw
    with open(out_osos_path, 'wb') as f_out:
        f_out.write(data)
        
    print(f"[+] Successfully injected bitmap #{index} into {out_osos_path}")

def check_volume_cap(osos_path: str):
    with open(osos_path, 'rb') as f:
        data = f.read()
    pattern = bytes([0x08, 0x00, 0x9f, 0xe5, 0x94, 0x00, 0x90, 0xe5])
    pos = 0
    cap_offsets = []
    while True:
        idx = data.find(pattern, pos)
        if idx == -1: break
        val = data[idx+8 : idx+12]
        cap_offsets.append((idx, val))
        pos = idx + 1

    target_idx = None
    for idx, val in cap_offsets:
        if val == bytes([0x01, 0x00, 0x00, 0xe2]): # and r0, r0, #1
            target_idx = idx
            break
        elif val == bytes([0x00, 0x00, 0xa0, 0xe3]): # mov r0, #0
            target_idx = idx
            break

    if target_idx is None:
        print("[?] Volume cap function not identified.")
        return None

    val = data[target_idx+8 : target_idx+12]
    print(f"[*] Volume cap check function found at offset 0x{target_idx:08x} (RAM 0x{LOAD_ADDR_OSOS + target_idx:08x})")
    if val == bytes([0x01, 0x00, 0x00, 0xe2]):
        print("[!] Status: CAPPED (EU Volume Limit hardware clamp enabled: and r0, r0, #1)")
        return "capped"
    elif val == bytes([0x00, 0x00, 0xa0, 0xe3]):
        print("[+] Status: UNCAPPED (Volume limit removed: mov r0, #0)")
        return "uncapped"
    else:
        print(f"[?] Status: Custom instruction {val.hex(' ')}")
        return "custom"

def uncap_volume(osos_path: str, out_osos_path: str):
    print(f"[*] Uncapping EU volume limit in {osos_path}...")
    with open(osos_path, 'rb') as f:
        data = bytearray(f.read())
    pattern = bytes([0x08, 0x00, 0x9f, 0xe5, 0x94, 0x00, 0x90, 0xe5])
    pos = 0
    target_idx = None
    while True:
        idx = data.find(pattern, pos)
        if idx == -1: break
        val = data[idx+8 : idx+12]
        if val in (bytes([0x01, 0x00, 0x00, 0xe2]), bytes([0x00, 0x00, 0xa0, 0xe3])):
            target_idx = idx
            break
        pos = idx + 1

    if target_idx is None:
        raise ValueError("Volume cap pattern not found!")

    # Patch: replace 'and r0, r0, #1' (01 00 00 e2) with 'mov r0, #0' (00 00 a0 e3)
    data[target_idx+8 : target_idx+12] = bytes([0x00, 0x00, 0xa0, 0xe3])
    with open(out_osos_path, 'wb') as f:
        f.write(data)
    print(f"[+] Successfully patched instruction at 0x{target_idx+8:08x} -> mov r0, #0")
    print(f"[+] Saved uncapped OS binary to {out_osos_path}")

def pack_firmware(unpacked_dir: str, output_ipsw_path: str):
    print(f"[*] Repacking firmware from {unpacked_dir} -> {output_ipsw_path}...")
    meta_path = os.path.join(unpacked_dir, "firmware_meta.json")
    with open(meta_path, 'r') as f:
        meta = json.load(f)
        
    fw_name = meta["fw_name"]
    fw_version = meta["fw_version"]
    images_dir = os.path.join(unpacked_dir, "images")
    
    # Read sub-images
    subimages = {}
    for entry in meta["entries"]:
        tname = entry["type"].lower()
        img_path = os.path.join(images_dir, f"{tname}_raw.bin")
        if not os.path.exists(img_path):
            raise FileNotFoundError(f"Missing required image file: {img_path}")
        with open(img_path, 'rb') as f:
            subimages[tname] = f.read()
            
    # Original firmware template for initial sectors
    orig_fw_path = os.path.join(unpacked_dir, fw_name)
    with open(orig_fw_path, 'rb') as f:
        orig_fw = f.read()
        
    fw_buffer = bytearray(orig_fw)
    
    # Update directory entries at diroffset
    diroffset = meta["diroffset"]
    p = diroffset
    for i, entry in enumerate(meta["entries"]):
        tname = entry["type"].lower()
        img_bytes = subimages[tname]
        
        # Calculate new checksum (for aupd, preserve original if unmodified)
        if tname == "aupd":
            new_chksum = entry["chksum"]
        else:
            new_chksum = compute_checksum(img_bytes)
            
        new_len = len(img_bytes)
        
        # Write back to directory entry
        # len is at offset +16, chksum at offset +28
        struct.pack_into('<I', fw_buffer, p + 16, new_len)
        struct.pack_into('<I', fw_buffer, p + 28, new_chksum)
        
        # Place the image in fw_buffer
        file_off = entry["devOffset"] + (IMAGE_PADDING_V3 if fw_version == 3 else 0)
        fw_buffer[file_off : file_off + new_len] = img_bytes
        
        print(f"    [+] Updated partition entry [{entry['type']}]: len={new_len}, checksum=0x{new_chksum:08x} at file offset 0x{file_off:08x}")
        p += 40
        
    # Write rebuilt Firmware binary
    rebuilt_fw_path = os.path.join(unpacked_dir, "Firmware_rebuilt")
    with open(rebuilt_fw_path, 'wb') as f:
        f.write(fw_buffer)
    print(f"[+] Wrote rebuilt raw firmware image ({len(fw_buffer)} bytes) to {rebuilt_fw_path}")
    
    # Also write standalone firmware partition image for dd / ipodpatcher
    raw_part_path = os.path.join(unpacked_dir, "firmware_partition.bin")
    with open(raw_part_path, 'wb') as f:
        f.write(fw_buffer)
    print(f"[+] Wrote direct flash partition binary: {raw_part_path}")
    
    # Pack into IPSW (ZIP)
    manifest_path = os.path.join(unpacked_dir, "manifest.plist")
    with zipfile.ZipFile(output_ipsw_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.write(rebuilt_fw_path, arcname=fw_name)
        if os.path.exists(manifest_path):
            z.write(manifest_path, arcname="manifest.plist")
            
    print(f"[+] Successfully built custom IPSW: {output_ipsw_path}")

def main():
    parser = argparse.ArgumentParser(description="iPod Video 5.5G Firmware RE & Rebuilding Toolkit")
    subparsers = parser.add_subparsers(dest="command")
    
    # unpack
    p_unpack = subparsers.add_parser("unpack", help="Unpack IPSW firmware into components, strings, and bitmaps")
    p_unpack.add_argument("ipsw", help="Path to iPod IPSW file")
    p_unpack.add_argument("-o", "--out", default="unpacked_firmware", help="Output directory")
    
    # dump-strings
    p_dstrings = subparsers.add_parser("dump-strings", help="Extract UI strings to JSON")
    p_dstrings.add_argument("osos", help="Path to osos_raw.bin")
    p_dstrings.add_argument("-o", "--out", default="ui_strings.json", help="Output JSON path")
    
    # inject-strings
    p_istrings = subparsers.add_parser("inject-strings", help="Inject modified strings into osos_raw.bin")
    p_istrings.add_argument("osos", help="Path to original osos_raw.bin")
    p_istrings.add_argument("json", help="Path to modified ui_strings.json")
    p_istrings.add_argument("-o", "--out", default="osos_raw_mod.bin", help="Output modified osos_raw.bin")
    
    # dump-bitmaps
    p_dbitmaps = subparsers.add_parser("dump-bitmaps", help="Extract UI bitmaps to BMP files")
    p_dbitmaps.add_argument("osos", help="Path to osos_raw.bin")
    p_dbitmaps.add_argument("-o", "--out", default="bitmaps", help="Output directory for bitmaps")
    
    # inject-bitmap
    p_ibitmap = subparsers.add_parser("inject-bitmap", help="Inject custom BMP into osos_raw.bin")
    p_ibitmap.add_argument("osos", help="Path to osos_raw.bin")
    p_ibitmap.add_argument("index", type=int, help="Bitmap index (0-402)")
    p_ibitmap.add_argument("bmp", help="Path to replacement 24-bit BMP image")
    p_ibitmap.add_argument("-o", "--out", default="osos_raw_mod.bin", help="Output modified osos_raw.bin")
    
    # volume
    p_vol = subparsers.add_parser("volume", help="Check or uncap EU volume limit")
    p_vol.add_argument("osos", help="Path to osos_raw.bin")
    p_vol.add_argument("--uncap", action="store_true", help="Remove volume cap")
    p_vol.add_argument("-o", "--out", default="osos_raw_uncapped.bin", help="Output modified binary")
    
    # pack
    p_pack = subparsers.add_parser("pack", help="Reassemble and package firmware into IPSW and partition binary")
    p_pack.add_argument("unpacked_dir", help="Directory containing unpacked firmware components")
    p_pack.add_argument("-o", "--out", default="custom_iPod_25.1.3.ipsw", help="Output IPSW path")
    
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
        
    if args.command == "unpack":
        unpack_ipsw(args.ipsw, args.out)
    elif args.command == "dump-strings":
        dump_strings(args.osos, args.out)
    elif args.command == "inject-strings":
        inject_strings(args.osos, args.json, args.out)
    elif args.command == "dump-bitmaps":
        dump_bitmaps(args.osos, args.out)
    elif args.command == "inject-bitmap":
        inject_bitmap(args.osos, args.index, args.bmp, args.out)
    elif args.command == "volume":
        check_volume_cap(args.osos)
        if args.uncap:
            uncap_volume(args.osos, args.out)
    elif args.command == "pack":
        pack_firmware(args.unpacked_dir, args.out)

if __name__ == "__main__":
    main()
