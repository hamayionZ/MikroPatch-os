import lzma, struct, os, re, argparse
from npk import NovaPackage, NpkPartID, NpkFileContainer

def replace_chunks(old_chunks, new_chunks, data, name):
    if not all(chunk in data for chunk in old_chunks):
        return data
    pattern_parts = [re.escape(chunk) + b'(.{0,6})' for chunk in old_chunks[:-1]]
    pattern_parts.append(re.escape(old_chunks[-1])) 
    pattern_bytes = b''.join(pattern_parts)
    pattern = re.compile(pattern_bytes, flags=re.DOTALL) 
    def replace_match(match):
        replaced = b''.join([new_chunks[i] + match.group(i+1) for i in range(len(new_chunks) - 1)])
        replaced += new_chunks[-1]
        print(f'[+] {name} patched at offset...')
        return replaced
    return re.sub(pattern, replace_match, data)

def replace_key(old, new, data, name=''):
    if len(old) < 32 or len(new) < 32: return data
    # Standard 4-byte chunks
    old_chunks = [old[i:i+4] for i in range(0, 32, 4)]
    new_chunks = [new[i:i+4] for i in range(0, 32, 4)]
    data = replace_chunks(old_chunks, new_chunks, data, name)
    # Shuffled key map for ROS7
    key_map = [28,19,25,16,14,3,24,15,22,8,6,17,11,7,9,23,18,13,10,0,26,21,2,5,20,30,31,4,27,29,1,12]
    try:
        old_shf = [bytes([old[i]]) for i in key_map]
        new_shf = [bytes([new[i]]) for i in key_map]
        data = replace_chunks(old_shf, new_shf, data, name + "_shf")
    except: pass
    return data

def patch_bzimage(data:bytes, key_dict:dict):
    try:
        PE_TEXT_OFFSET = 414
        HDR_PAYLOAD_OFF = 584
        text_raw = struct.unpack_from('<I',data,PE_TEXT_OFFSET)[0]
        pay_off = text_raw + struct.unpack_from('<I',data,HDR_PAYLOAD_OFF)[0]
        pay_len = struct.unpack_from('<I',data,HDR_PAYLOAD_OFF+4)[0] - 4
        vmlinux_xz = data[pay_off:pay_off+pay_len]
        vmlinux = lzma.decompress(vmlinux_xz)
        new_vmlinux = vmlinux
        for ok, nk in key_dict.items():
            new_vmlinux = replace_key(ok, nk, new_vmlinux, 'vmlinux')
        new_xz = lzma.compress(new_vmlinux, check=lzma.CHECK_CRC32, filters=[
            {"id": lzma.FILTER_X86}, {"id": lzma.FILTER_LZMA2, "preset": 9}
        ])
        return data.replace(vmlinux_xz, new_xz.ljust(len(vmlinux_xz), b'\0'))
    except Exception as e:
        print(f"[-] bzImage Fail: {e}"); return data

def patch_kernel(data:bytes, key_dict):
    if data[:2] == b'MZ':
        return patch_bzimage(data, key_dict)
    elif data[:4] == b'\x7FELF':
        # Simple ELF key replacement
        for ok, nk in key_dict.items(): data = replace_key(ok, nk, data, 'elf')
        return data
    return data

def patch_npk_file(key_dict, k_priv, e_priv, inf, outf=None):
    npk = NovaPackage.load(inf)
    pkgs = npk._packages if len(npk._packages) > 0 else [npk]
    for p in pkgs:
        if p[NpkPartID.NAME_INFO].data.name == 'system':
            fc = NpkFileContainer.unserialize_from(p[NpkPartID.FILE_CONTAINER].data)
            for item in fc:
                if item.name in [b'boot/EFI/BOOT/BOOTX64.EFI', b'boot/kernel']:
                    item.data = patch_kernel(item.data, key_dict)
            p[NpkPartID.FILE_CONTAINER].data = fc.serialize()
    npk.sign(k_priv, e_priv)
    npk.save(outf or inf)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    p_npk = subparsers.add_parser('npk'); p_npk.add_argument('input'); p_npk.add_argument('-O','--output')
    p_ker = subparsers.add_parser('kernel'); p_ker.add_argument('input'); p_ker.add_argument('-O','--output')
    args = parser.parse_args()
    
    m_lic = bytes.fromhex(os.getenv('MIKRO_LICENSE_PUBLIC_KEY', '4a595133644d6736523959326e5535354d6d4a4d6b6e4d50516b32693836374a'))
    c_lic = bytes.fromhex(os.getenv('CUSTOM_LICENSE_PUBLIC_KEY', '10'*32))
    m_npk = bytes.fromhex(os.getenv('MIKRO_NPK_SIGN_PUBLIC_KEY', 'c33b9347898862f18390885141e6b3531b402868c78c3c4343166443685e1327'))
    c_npk = bytes.fromhex(os.getenv('CUSTOM_NPK_SIGN_PUBLIC_KEY', 'a1'*32))
    
    key_dict = { m_lic: c_lic, m_npk: c_npk }
    k_priv = bytes.fromhex(os.getenv('CUSTOM_LICENSE_PRIVATE_KEY', '0'*64))
    e_priv = bytes.fromhex(os.getenv('CUSTOM_NPK_SIGN_PRIVATE_KEY', '0'*64))

    if args.command == 'npk':
        patch_npk_file(key_dict, k_priv, e_priv, args.input, args.output)
    elif args.command == 'kernel':
        d = patch_kernel(open(args.input, 'rb').read(), key_dict)
        open(args.output or args.input, 'wb').write(d)
    print("[+] Done.")
