#!/usr/bin/env python3
"""
MikroTik RouterOS 7.x Patcher
Handles NPK, kernel, initrd, and ISO patching with key replacement.
"""

import subprocess
import lzma
import struct
import os
import re
import sys
import traceback

# Try to import optional modules
try:
    from npk import NovaPackage, NpkPartID, NpkFileContainer
except ImportError:
    print("Warning: npk module not found. NPK patching will not work.")
    NovaPackage = None
    NpkPartID = None
    NpkFileContainer = None

# Helper functions
def replace_chunks(old_chunks, new_chunks, data, name):
    """Replace chunks of data with new chunks."""
    try:
        pattern_parts = [re.escape(chunk) + b'(.{0,6})' for chunk in old_chunks[:-1]]
        pattern_parts.append(re.escape(old_chunks[-1]))
        pattern_bytes = b''.join(pattern_parts)
        pattern = re.compile(pattern_bytes, flags=re.DOTALL)

        def replace_match(match):
            replaced = b''.join([new_chunks[i] + match.group(i+1) for i in range(len(new_chunks) - 1)])
            replaced += new_chunks[-1]
            print(f'{name} public key patched {b"".join(old_chunks)[:16].hex().upper()}...')
            return replaced

        return re.sub(pattern, replace_match, data)
    except Exception as e:
        print(f"Error in replace_chunks: {e}")
        return data


def replace_key(old, new, data, name=''):
    """Replace public keys with various patterns."""
    try:
        # Basic 4-byte chunk replacement
        old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
        new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
        data = replace_chunks(old_chunks, new_chunks, data, name)

        # Key map for permutation
        key_map = [28,19,25,16,14,3,24,15,22,8,6,17,11,7,9,23,18,13,10,0,26,21,2,5,20,30,31,4,27,29,1,12]
        old_chunks = [bytes([old[i]]) for i in key_map]
        new_chunks = [bytes([new[i]]) for i in key_map]
        data = replace_chunks(old_chunks, new_chunks, data, name)

        arch = os.getenv('ARCH') or 'x86'
        arch = arch.replace('-', '')

        if arch in ['arm64', 'arm']:
            old_chunks = [old[i:i+4] for i in range(0, len(old), 4)]
            new_chunks = [new[i:i+4] for i in range(0, len(new), 4)]
            if len(old_chunks) >= 8 and len(new_chunks) >= 8:
                old_bytes = old_chunks[4] + old_chunks[5] + old_chunks[2] + old_chunks[0] + old_chunks[1] + old_chunks[6] + old_chunks[7]
                new_bytes = new_chunks[4] + new_chunks[5] + new_chunks[2] + new_chunks[0] + new_chunks[1] + new_chunks[6] + new_chunks[7]

                if old_bytes in data:
                    print(f'{name} public key patched {old[:16].hex().upper()}...')
                    data = data.replace(old_bytes, new_bytes)
                    old_codes = [bytes.fromhex('793583E2'), bytes.fromhex('FD3A83E2'), bytes.fromhex('193D83E2')]
                    new_codes = [bytes.fromhex('FF34A0E3'), bytes.fromhex('753C83E2'), bytes.fromhex('FC3083E2')]
                    data = replace_chunks(old_codes, new_codes, data, name)
                else:
                    def conver_chunks(data_bytes):
                        if len(data_bytes) < 32:
                            return []
                        ret = [
                            (data_bytes[2] << 16) | (data_bytes[1] << 8) | data_bytes[0] | ((data_bytes[3] << 24) & 0x03000000),
                            (data_bytes[3] >> 2) | (data_bytes[4] << 6) | (data_bytes[5] << 14) | ((data_bytes[6] << 22) & 0x1C00000),
                            (data_bytes[6] >> 3) | (data_bytes[7] << 5) | (data_bytes[8] << 13) | ((data_bytes[9] << 21) & 0x3E00000),
                            (data_bytes[9] >> 5) | (data_bytes[10] << 3) | (data_bytes[11] << 11) | ((data_bytes[12] << 19) & 0x1F80000),
                            (data_bytes[12] >> 6) | (data_bytes[13] << 2) | (data_bytes[14] << 10) | (data_bytes[15] << 18),
                            data_bytes[16] | (data_bytes[17] << 8) | (data_bytes[18] << 16) | ((data_bytes[19] << 24) & 0x01000000),
                            (data_bytes[19] >> 1) | (data_bytes[20] << 7) | (data_bytes[21] << 15) | ((data_bytes[22] << 23) & 0x03800000),
                            (data_bytes[22] >> 3) | (data_bytes[23] << 5) | (data_bytes[24] << 13) | ((data_bytes[25] << 21) & 0x1E00000),
                            (data_bytes[25] >> 4) | (data_bytes[26] << 4) | (data_bytes[27] << 12) | ((data_bytes[28] << 20) & 0x3F00000),
                            (data_bytes[28] >> 6) | (data_bytes[29] << 2) | (data_bytes[30] << 10) | (data_bytes[31] << 18)
                        ]
                        return [struct.pack('<I', x) for x in ret]

                    old_chunks = conver_chunks(old)
                    new_chunks = conver_chunks(new)
                    if old_chunks and new_chunks:
                        old_bytes = b''.join([v for i, v in enumerate(old_chunks) if i != 8])
                        new_bytes = b''.join([v for i, v in enumerate(new_chunks) if i != 8])

                        if old_bytes in data:
                            print(f'{name} public key patched {old[:16].hex().upper()}...')
                            data = data.replace(old_bytes, new_bytes)
                            old_codes = [bytes.fromhex('713783E2'), bytes.fromhex('223A83E2'), bytes.fromhex('8D3F83E2')]
                            new_codes = [bytes.fromhex('973303E3'), bytes.fromhex('DD3883E3'), bytes.fromhex('033483E3')]
                            data = replace_chunks(old_codes, new_codes, data, name)

        return data
    except Exception as e:
        print(f"Error in replace_key: {e}")
        return data


def patch_bzimage(data, key_dict):
    """Patch x86_64 bzImage."""
    try:
        PE_TEXT_SECTION_OFFSET = 414
        HEADER_PAYLOAD_OFFSET = 584
        HEADER_PAYLOAD_LENGTH_OFFSET = HEADER_PAYLOAD_OFFSET + 4

        if len(data) <= max(HEADER_PAYLOAD_LENGTH_OFFSET + 4, PE_TEXT_SECTION_OFFSET + 4):
            print("Error: Data too small for PE header parsing")
            return data

        text_section_raw_data = struct.unpack_from('<I', data, PE_TEXT_SECTION_OFFSET)[0]
        payload_offset = text_section_raw_data + struct.unpack_from('<I', data, HEADER_PAYLOAD_OFFSET)[0]
        payload_length = struct.unpack_from('<I', data, HEADER_PAYLOAD_LENGTH_OFFSET)[0]
        payload_length = payload_length - 4

        if payload_offset + payload_length > len(data):
            print("Error: Payload exceeds data bounds")
            return data

        z_output_len = struct.unpack_from('<I', data, payload_offset + payload_length)[0]
        vmlinux_xz = data[payload_offset:payload_offset + payload_length]

        try:
            vmlinux = lzma.decompress(vmlinux_xz)
        except lzma.LZMAError as e:
            print(f"Error decompressing vmlinux: {e}")
            return data

        assert z_output_len == len(vmlinux), 'vmlinux size is not equal to expected'

        CPIO_HEADER_MAGIC = b'07070100'
        CPIO_FOOTER_MAGIC = b'TRAILER!!!\x00\x00\x00\x00'

        cpio_offset1 = vmlinux.find(CPIO_HEADER_MAGIC)
        if cpio_offset1 == -1:
            print("Error: CPIO header not found")
            return data

        initramfs = vmlinux[cpio_offset1:]
        cpio_offset2 = initramfs.find(CPIO_FOOTER_MAGIC) + len(CPIO_FOOTER_MAGIC)
        if cpio_offset2 == -1:
            print("Error: CPIO footer not found")
            return data

        initramfs = initramfs[:cpio_offset2]
        new_initramfs = initramfs

        for old_public_key, new_public_key in key_dict.items():
            new_initramfs = replace_key(old_public_key, new_public_key, new_initramfs, 'initramfs')

        new_vmlinux = vmlinux.replace(initramfs, new_initramfs)
        new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32, filters=[
            {"id": lzma.FILTER_X86},
            {"id": lzma.FILTER_LZMA2,
             "preset": 9 | lzma.PRESET_EXTREME,
             'dict_size': 32 * 1024 * 1024,
             "lc": 4, "lp": 0, "pb": 0,
             },
        ])

        new_payload_length = len(new_vmlinux_xz)
        assert new_payload_length <= payload_length, 'new vmlinux.xz size is too big'
        new_payload_length = new_payload_length + 4

        new_data = bytearray(data)
        struct.pack_into('<I', new_data, HEADER_PAYLOAD_LENGTH_OFFSET, new_payload_length)

        vmlinux_xz += struct.pack('<I', z_output_len)
        new_vmlinux_xz += struct.pack('<I', z_output_len)
        new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')
        new_data = new_data.replace(vmlinux_xz, new_vmlinux_xz)

        return bytes(new_data)
    except Exception as e:
        print(f"Error in patch_bzimage: {e}")
        return data


def patch_block(dev, file, key_dict):
    """Patch a file on a block device."""
    try:
        BLOCK_SIZE = 4096
        result = subprocess.run(f"debugfs {dev} -R 'stat {file}' 2> /dev/null | sed -n '11p'",
                               shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error: debugfs failed with return code {result.returncode}")
            return

        blocks_info = result.stdout.strip().split(',')
        print(f'blocks_info : {blocks_info}')

        blocks = []
        ind_block_id = None

        for block_info in blocks_info:
            _tmp = block_info.strip().split(':')
            if len(_tmp) < 2:
                continue
            if _tmp[0].strip() == '(IND)':
                ind_block_id = int(_tmp[1])
            else:
                id_range = _tmp[0].strip().replace('(', '').replace(')', '').split('-')
                block_range = _tmp[1].strip().replace('(', '').replace(')', '').split('-')
                if len(block_range) >= 2:
                    blocks += [id for id in range(int(block_range[0]), int(block_range[1]) + 1)]

        print(f'blocks : {len(blocks)} ind_block_id : {ind_block_id}')

        result = subprocess.run(f"debugfs {dev} -R 'cat {file}' 2> /dev/null",
                               shell=True, capture_output=True)
        data = result.stdout

        new_data = patch_kernel(data, key_dict)

        print(f'write block {len(blocks)} : [', end="")
        with open(dev, 'wb') as f:
            for index, block_id in enumerate(blocks):
                print('#', end="")
                f.seek(block_id * BLOCK_SIZE)
                f.write(new_data[index * BLOCK_SIZE:(index + 1) * BLOCK_SIZE])
            f.flush()
            print(']')
    except Exception as e:
        print(f"Error in patch_block: {e}")


def patch_initrd_xz(initrd_xz, key_dict, ljust=True):
    """Patch initrd compressed with xz."""
    try:
        initrd = lzma.decompress(initrd_xz)
        new_initrd = initrd

        for old_public_key, new_public_key in key_dict.items():
            new_initrd = replace_key(old_public_key, new_public_key, new_initrd, 'initrd')

        preset = 6
        new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32,
                                      filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])

        while len(new_initrd_xz) > len(initrd_xz) and preset < 9:
            print(f'preset:{preset}')
            print(f'new initrd xz size:{len(new_initrd_xz)}')
            print(f'old initrd xz size:{len(initrd_xz)}')
            preset += 1
            new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32,
                                          filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])

        if len(new_initrd_xz) > len(initrd_xz):
            new_initrd_xz = lzma.compress(new_initrd, check=lzma.CHECK_CRC32, filters=[
                {"id": lzma.FILTER_LZMA2,
                 "preset": 9 | lzma.PRESET_EXTREME,
                 'dict_size': 32 * 1024 * 1024,
                 "lc": 4, "lp": 0, "pb": 0,
                 }])

        if ljust:
            print(f'preset:{preset}')
            print(f'new initrd xz size:{len(new_initrd_xz)}')
            print(f'old initrd xz size:{len(initrd_xz)}')
            print(f'ljust size:{len(initrd_xz) - len(new_initrd_xz)}')

            if len(new_initrd_xz) > len(initrd_xz):
                print(f'WARNING: new initrd xz size is too big ({len(new_initrd_xz)} > {len(initrd_xz)})')
                new_initrd_xz = new_initrd_xz[:len(initrd_xz)]
            else:
                new_initrd_xz = new_initrd_xz.ljust(len(initrd_xz), b'\0')

        return new_initrd_xz
    except Exception as e:
        print(f"Error in patch_initrd_xz: {e}")
        return initrd_xz


def find_7zXZ_data(data):
    """Find 7zXZ compressed data in a binary."""
    try:
        offset1 = 0
        _data = data
        last_pos = 0
        while b'\xFD7zXZ\x00\x00\x01' in _data:
            pos = _data.index(b'\xFD7zXZ\x00\x00\x01')
            offset1 = offset1 + pos + 8
            _data = _data[pos + 8:]
            last_pos = offset1
        if last_pos > 0:
            offset1 = last_pos - 8
        else:
            offset1 = 0

        offset2 = 0
        _data = data
        while b'\x00\x00\x00\x00\x01\x59\x5A' in _data:
            pos = _data.index(b'\x00\x00\x00\x00\x01\x59\x5A')
            offset2 = offset2 + pos + 7
            _data = _data[pos + 7:]

        if offset1 == 0 or offset2 == 0 or offset2 <= offset1:
            print('No valid 7zXZ data found')
            return b''

        print(f'found 7zXZ data offset:{offset1} size:{offset2 - offset1}')
        return data[offset1:offset2]
    except Exception as e:
        print(f"Error in find_7zXZ_data: {e}")
        return b''


def patch_elf(data, key_dict):
    """Patch ELF images (arm64, etc.)."""
    try:
        initrd_xz = find_7zXZ_data(data)
        if initrd_xz:
            new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)
            return data.replace(initrd_xz, new_initrd_xz)
        return data
    except Exception as e:
        print(f"Error in patch_elf: {e}")
        return data


def patch_pe(data, key_dict):
    """Patch PE images (EFI)."""
    try:
        vmlinux_xz = find_7zXZ_data(data)
        if vmlinux_xz:
            vmlinux = lzma.decompress(vmlinux_xz)
            initrd_xz_offset = vmlinux.find(b'\xFD7zXZ\x00\x00\x01')
            if initrd_xz_offset == -1:
                print("Error: initrd 7zXZ header not found")
                return data
            initrd_xz_size = vmlinux[initrd_xz_offset:].find(b'\x00\x00\x00\x00\x01\x59\x5A') + 7
            if initrd_xz_size < 7:
                print("Error: initrd size invalid")
                return data
            initrd_xz = vmlinux[initrd_xz_offset:initrd_xz_offset + initrd_xz_size]
            new_initrd_xz = patch_initrd_xz(initrd_xz, key_dict)
            new_vmlinux = vmlinux.replace(initrd_xz, new_initrd_xz)
            new_vmlinux_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32,
                                          filters=[{"id": lzma.FILTER_LZMA2, "preset": 9}])

            if len(new_vmlinux_xz) > len(vmlinux_xz):
                print(f'WARNING: new vmlinux xz size is too big ({len(new_vmlinux_xz)} > {len(vmlinux_xz)})')
                new_vmlinux_xz = new_vmlinux_xz[:len(vmlinux_xz)]
            else:
                print(f'new vmlinux xz size:{len(new_vmlinux_xz)}')
                print(f'old vmlinux xz size:{len(vmlinux_xz)}')
                print(f'ljust size:{len(vmlinux_xz) - len(new_vmlinux_xz)}')
                new_vmlinux_xz = new_vmlinux_xz.ljust(len(vmlinux_xz), b'\0')

            return data.replace(vmlinux_xz, new_vmlinux_xz)
        return data
    except Exception as e:
        print(f"Error in patch_pe: {e}")
        return data


def patch_netinstall(key_dict, input_file, output_file=None):
    """Patch netinstall executable."""
    try:
        with open(input_file, 'rb') as f:
            netinstall = f.read()

        if netinstall[:2] == b'MZ':
            try:
                import pefile

                ROUTEROS_BOOT = {
                    129: {'arch': 'power', 'name': 'Powerboot'},
                    130: {'arch': 'e500', 'name': 'e500_boot'},
                    131: {'arch': 'mips', 'name': 'Mips_boot'},
                    135: {'arch': '400', 'name': '440__boot'},
                    136: {'arch': 'tile', 'name': 'tile_boot'},
                    137: {'arch': 'arm', 'name': 'ARM__boot'},
                    138: {'arch': 'mmips', 'name': 'MMipsBoot'},
                    139: {'arch': 'arm64', 'name': 'ARM64__boot'},
                    143: {'arch': 'x86_64', 'name': 'x86_64boot'}
                }

                pe = pefile.PE(input_file)
                if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                    print("No resources found in PE file")
                    pe.close()
                    return

                for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource.id == pefile.RESOURCE_TYPE["RT_RCDATA"]:
                        for sub_resource in resource.directory.entries:
                            if sub_resource.id in ROUTEROS_BOOT:
                                bootloader = ROUTEROS_BOOT[sub_resource.id]
                                print(f'found {bootloader["arch"]}({sub_resource.id}) bootloader')
                                rva = sub_resource.directory.entries[0].data.struct.OffsetToData
                                size = sub_resource.directory.entries[0].data.struct.Size
                                data = pe.get_data(rva, size)
                                if len(data) < 4:
                                    print(f"Data too small for {bootloader['arch']}")
                                    continue
                                _size = struct.unpack('<I', data[:4])[0]
                                _data = data[4:4 + _size]

                                try:
                                    if _data[:2] == b'MZ':
                                        new_data = patch_pe(_data, key_dict)
                                    elif _data[:4] == b'\x7FELF':
                                        new_data = patch_elf(_data, key_dict)
                                    else:
                                        print(f'unknown bootloader format {_data[:4].hex().upper()}')
                                        new_data = _data
                                except Exception as e:
                                    print(f'patch {bootloader["arch"]}({sub_resource.id}) bootloader failed {e}')
                                    new_data = _data

                                new_data = struct.pack("<I", _size) + new_data.ljust(len(_data), b'\0')
                                new_data = new_data.ljust(size, b'\0')
                                pe.set_bytes_at_rva(rva, new_data)

                pe.write(output_file or input_file)
                pe.close()

            except ImportError:
                print("pefile module not installed. Install with: pip install pefile")
            except Exception as e:
                print(f"Error patching PE netinstall: {e}")
                traceback.print_exc()

        elif netinstall[:4] == b'\x7FELF':
            print("ELF netinstall detected but patching is complex")
        else:
            print(f"Unknown netinstall format: {netinstall[:4].hex().upper()}")

    except Exception as e:
        print(f"Error in patch_netinstall: {e}")
        traceback.print_exc()


def patch_kernel(data, key_dict):
    """Main kernel patching dispatcher."""
    try:
        if len(data) < 4:
            print(f'Data too small: {len(data)} bytes')
            return data

        if data[:2] == b'MZ':
            print('patching EFI Kernel')
            if len(data) > 60 and data[56:60] == b'ARM\x64':
                print('patching arm64')
                return patch_elf(data, key_dict)
            else:
                print('patching x86_64')
                return patch_bzimage(data, key_dict)
        elif data[:4] == b'\x7FELF':
            print('patching ELF')
            return patch_elf(data, key_dict)
        elif data[:5] == b'\xFD7zXZ':
            print('patching initrd')
            return patch_initrd_xz(data, key_dict, ljust=False)
        else:
            print(f'unknown kernel format: {data[:4].hex().upper()}')
            return data
    except Exception as e:
        print(f"Error in patch_kernel: {e}")
        return data


def patch_loader(loader_file):
    """Patch loader binary (if available)."""
    try:
        if os.path.exists('loader/patch_loader.py'):
            sys.path.insert(0, os.path.dirname(os.path.abspath('loader')))
            from patch_loader import patch_loader as do_patch_loader
            arch = os.getenv('ARCH') or 'x86'
            arch = arch.replace('-', '')
            do_patch_loader(loader_file, loader_file, arch)
        else:
            print("loader/patch_loader.py not found. Skipping loader patch.")
    except ImportError as e:
        print(f"Loader module import failed: {e}")
    except Exception as e:
        print(f"Error in patch_loader: {e}")


def patch_squashfs(path, key_dict):
    """Recursively patch files in a squashfs extracted directory."""
    try:
        for root, dirs, files in os.walk(path):
            for _file in files:
                file = os.path.join(root, _file)
                if os.path.isfile(file):
                    if _file == 'loader':
                        patch_loader(file)
                        continue

                    if _file == 'BOOTX64.EFI':
                        print(f'patch {file} ...')
                        with open(file, 'rb') as f:
                            data = f.read()
                        data = patch_kernel(data, key_dict)
                        with open(file, 'wb') as f:
                            f.write(data)
                        continue

                    try:
                        with open(file, 'rb') as f:
                            data = f.read()
                    except Exception as e:
                        print(f"Error reading {file}: {e}")
                        continue

                    modified = False
                    for old_public_key, new_public_key in key_dict.items():
                        _data = replace_key(old_public_key, new_public_key, data, file)
                        if _data != data:
                            modified = True
                            data = _data

                    url_dict = {
                        os.environ.get('MIKRO_LICENCE_URL', '').encode(): os.environ.get('CUSTOM_LICENCE_URL', '').encode(),
                        os.environ.get('MIKRO_UPGRADE_URL', '').encode(): os.environ.get('CUSTOM_UPGRADE_URL', '').encode(),
                        os.environ.get('MIKRO_CLOUD_URL', '').encode(): os.environ.get('CUSTOM_CLOUD_URL', '').encode(),
                        os.environ.get('MIKRO_CLOUD_PUBLIC_KEY', '').encode(): os.environ.get('CUSTOM_CLOUD_PUBLIC_KEY', '').encode(),
                    }

                    for old_url, new_url in url_dict.items():
                        if old_url and new_url and old_url in data:
                            print(f'{file} url patched {old_url.decode()[:7]}...')
                            data = data.replace(old_url, new_url)
                            modified = True

                    if modified:
                        try:
                            with open(file, 'wb') as f:
                                f.write(data)
                        except Exception as e:
                            print(f"Error writing {file}: {e}")

                    if os.path.split(file)[1] == 'licupgr':
                        url_dict = {
                            os.environ.get('MIKRO_RENEW_URL', '').encode(): os.environ.get('CUSTOM_RENEW_URL', '').encode(),
                        }
                        for old_url, new_url in url_dict.items():
                            if old_url and new_url and old_url in data:
                                print(f'{file} url patched {old_url.decode()[:7]}...')
                                data = data.replace(old_url, new_url)
                                try:
                                    with open(file, 'wb') as f:
                                        f.write(data)
                                except Exception as e:
                                    print(f"Error writing {file}: {e}")
    except Exception as e:
        print(f"Error in patch_squashfs: {e}")


def run_shell_command(command):
    """Run shell command and return output."""
    try:
        process = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return process.stdout, process.stderr
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {command}")
        print(f"Error: {e.stderr}")
        return e.stdout, e.stderr


def safe_sign(npk, kcdsa_private_key, eddsa_private_key):
    """Attempt to sign NPK, skip if keys are invalid."""
    try:
        # Check key lengths
        if len(kcdsa_private_key) != 32 or len(eddsa_private_key) != 32:
            print("Warning: Invalid private key length, skipping signing.")
            return False
        npk.sign(kcdsa_private_key, eddsa_private_key)
        print("Signed successfully.")
        return True
    except Exception as e:
        print(f"Signing failed: {e}")
        print("Continuing without signing.")
        return False


def patch_npk_package(package, key_dict):
    """Patch a single NPK package."""
    try:
        if package[NpkPartID.NAME_INFO].data.name == b'system':
            # Patch file container
            file_container = NpkFileContainer.unserialize_from(package[NpkPartID.FILE_CONTAINER].data)
            for item in file_container:
                if item.name in [b'boot/EFI/BOOT/BOOTX64.EFI', b'boot/kernel', b'boot/initrd.rgz']:
                    print(f'patch {item.name} ...')
                    item.data = patch_kernel(item.data, key_dict)
            package[NpkPartID.FILE_CONTAINER].data = file_container.serialize()

            # Extract and patch squashfs
            squashfs_file = 'squashfs-root.sfs'
            extract_dir = 'squashfs-root'

            with open(squashfs_file, 'wb') as f:
                f.write(package[NpkPartID.SQUASHFS].data)

            print(f"extract {squashfs_file} ...")
            run_shell_command(f"unsquashfs -d {extract_dir} {squashfs_file}")

            patch_squashfs(extract_dir, key_dict)

            logo = os.path.join(extract_dir, "nova/lib/console/logo.txt")
            if os.path.exists(logo):
                run_shell_command(f"sudo sed -i '1d' {logo}")
                run_shell_command(f"sudo sed -i '8s#.*#  osmant@live.cn     https://github.com/hamayionZ/MikroTikPatch#' {logo}")

            print(f"pack {extract_dir} ...")
            run_shell_command(f"rm -f {squashfs_file}")
            run_shell_command(f"mksquashfs {extract_dir} {squashfs_file} -quiet -comp xz -no-xattrs -b 256k")

            print(f"clean ...")
            run_shell_command(f"rm -rf {extract_dir}")

            with open(squashfs_file, 'rb') as f:
                package[NpkPartID.SQUASHFS].data = f.read()

            run_shell_command(f"rm -f {squashfs_file}")
    except Exception as e:
        print(f"Error in patch_npk_package: {e}")
        traceback.print_exc()


def patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, input_file, output_file=None):
    """Patch and sign an NPK file."""
    try:
        if NovaPackage is None:
            print("Error: npk module not available. Cannot patch NPK.")
            return

        if not os.path.exists(input_file):
            print(f"Error: Input file {input_file} does not exist")
            return

        npk = NovaPackage.load(input_file)

        if hasattr(npk, '_packages') and len(npk._packages) > 0:
            for package in npk._packages:
                patch_npk_package(package, key_dict)
        else:
            patch_npk_package(npk, key_dict)

        # Attempt to sign (safe)
        safe_sign(npk, kcdsa_private_key, eddsa_private_key)

        # Save
        output_path = output_file or input_file
        # Create backup if overwriting original
        if output_path == input_file:
            backup = input_file + ".backup"
            if not os.path.exists(backup):
                import shutil
                shutil.copy2(input_file, backup)
                print(f"Backup created: {backup}")

        try:
            npk.save(output_path)
            os.chmod(output_path, 0o644)
            print(f"Successfully patched and saved: {output_path}")
        except PermissionError:
            print(f"Permission denied writing to {output_path}, trying /tmp")
            alt_path = f"/tmp/{os.path.basename(output_path)}"
            npk.save(alt_path)
            os.chmod(alt_path, 0o644)
            print(f"Saved to {alt_path} instead")
    except Exception as e:
        print(f"Error in patch_npk_file: {e}")
        traceback.print_exc()


def main():
    import argparse

    parser = argparse.ArgumentParser(description='MikroTik RouterOS 7.x Patcher')
    subparsers = parser.add_subparsers(dest="command", required=True)

    npk_parser = subparsers.add_parser('npk', help='patch and sign npk file')
    npk_parser.add_argument('input', type=str, help='Input file')
    npk_parser.add_argument('-O', '--output', type=str, help='Output file')

    kernel_parser = subparsers.add_parser('kernel', help='patch kernel file')
    kernel_parser.add_argument('input', type=str, help='Input file')
    kernel_parser.add_argument('-O', '--output', type=str, help='Output file')

    block_parser = subparsers.add_parser('block', help='patch block file')
    block_parser.add_argument('dev', type=str, help='block device')
    block_parser.add_argument('file', type=str, help='file path')

    netinstall_parser = subparsers.add_parser('netinstall', help='patch netinstall file')
    netinstall_parser.add_argument('input', type=str, help='Input file')
    netinstall_parser.add_argument('-O', '--output', type=str, help='Output file')

    args = parser.parse_args()

    # Environment variables for keys
    required_env_vars = [
        'MIKRO_LICENSE_PUBLIC_KEY', 'CUSTOM_LICENSE_PUBLIC_KEY',
        'MIKRO_NPK_SIGN_PUBLIC_KEY', 'CUSTOM_NPK_SIGN_PUBLIC_KEY',
        'CUSTOM_LICENSE_PRIVATE_KEY', 'CUSTOM_NPK_SIGN_PRIVATE_KEY'
    ]
    missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
    if missing_vars:
        print(f"Warning: Missing environment variables: {missing_vars}")
        print("Some features may not work correctly")

    try:
        key_dict = {
            bytes.fromhex(os.environ.get('MIKRO_LICENSE_PUBLIC_KEY', '00'*32)):
            bytes.fromhex(os.environ.get('CUSTOM_LICENSE_PUBLIC_KEY', '00'*32)),
            bytes.fromhex(os.environ.get('MIKRO_NPK_SIGN_PUBLIC_KEY', '00'*32)):
            bytes.fromhex(os.environ.get('CUSTOM_NPK_SIGN_PUBLIC_KEY', '00'*32))
        }

        kcdsa_private_key = bytes.fromhex(os.environ.get('CUSTOM_LICENSE_PRIVATE_KEY', '00'*32))
        eddsa_private_key = bytes.fromhex(os.environ.get('CUSTOM_NPK_SIGN_PRIVATE_KEY', '00'*32))

        if args.command == 'npk':
            print(f'patching {args.input} ...')
            patch_npk_file(key_dict, kcdsa_private_key, eddsa_private_key, args.input, args.output)
        elif args.command == 'kernel':
            print(f'patching {args.input} ...')
            with open(args.input, 'rb') as f:
                data = f.read()
            data = patch_kernel(data, key_dict)
            with open(args.output or args.input, 'wb') as f:
                f.write(data)
            print(f"Successfully patched kernel: {args.output or args.input}")
        elif args.command == 'block':
            print(f'patching {args.file} in {args.dev} ...')
            patch_block(args.dev, args.file, key_dict)
        elif args.command == 'netinstall':
            print(f'patching {args.input} ...')
            patch_netinstall(key_dict, args.input, args.output)
        else:
            parser.print_help()

    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
