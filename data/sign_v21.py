import zipfile, struct, hashlib, base64, plistlib, sys, asyncio
from pathlib import Path
sys.path.insert(0, r'C:\Users\User\AppData\Roaming\Python\Python311\site-packages')
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
import asn1crypto.cms as cms_mod

NEW_IPA      = Path('data/fengshui_v19_adhoc.ipa')
TEMPLATE_IPA = Path('data/AllocatorProbe_v15_v26c_r2.ipa')
OUT_IPA      = Path('data/fengshui_v19_signed.ipa')
KEY_PEM      = Path(r'C:\Users\User\AppData\Roaming\Sideloadly\key.pem')
UDID         = '00008150-0019381E1A23401C'

key = load_pem_private_key(KEY_PEM.read_bytes(), password=None, backend=default_backend())

# Extract from template IPA (team cert signing material)
with zipfile.ZipFile(TEMPLATE_IPA) as z:
    tmpl_bin  = bytearray(z.read('Payload/AllocatorProbe_v15.app/AllocatorProbe_v15'))
    tmpl_cr   = z.read('Payload/AllocatorProbe_v15.app/_CodeSignature/CodeResources')
    profile   = z.read('Payload/AllocatorProbe_v15.app/embedded.mobileprovision')

# Extract v19 binary from adhoc IPA
with zipfile.ZipFile(NEW_IPA) as z:
    new_bin  = bytearray(z.read('Payload/App.app/App'))
    new_plist = z.read('Payload/App.app/Info.plist')

print(f"template binary: {len(tmpl_bin)} bytes  v19 binary: {len(new_bin)} bytes")

# For v19, no extra resources (JS is embedded in binary)
# CodeResources stays the same as template (no file additions needed)
cr_plist = plistlib.loads(tmpl_cr)

# Remove v15-specific html resource if present
for key_name in list(cr_plist.get('files', {}).keys()):
    if key_name.endswith('.html'):
        del cr_plist['files'][key_name]
for key_name in list(cr_plist.get('files2', {}).keys()):
    if key_name.endswith('.html'):
        del cr_plist['files2'][key_name]

new_cr = plistlib.dumps(cr_plist, fmt=plistlib.FMT_XML, sort_keys=True)
new_cr_hash = hashlib.sha256(new_cr).digest()
print(f"New CodeResources SHA256: {new_cr_hash.hex()[:16]}...")

# Parse template code signature
def find_cs(binary):
    ncmds = struct.unpack_from('<I', binary, 16)[0]
    off = 32
    for _ in range(ncmds):
        cmd, csz = struct.unpack_from('<II', binary, off)
        if cmd == 0x1D:
            return struct.unpack_from('<II', binary, off+8)
        off += csz
    return 0, 0

tmpl_cs_off, tmpl_cs_sz = find_cs(tmpl_bin)
tmpl_cs = bytes(tmpl_bin[tmpl_cs_off:tmpl_cs_off+tmpl_cs_sz])
_, _, count = struct.unpack_from('>III', tmpl_cs)
tmpl_blobs = {}
for i in range(count):
    bt, bo = struct.unpack_from('>II', tmpl_cs, 12+i*8)
    bl = struct.unpack_from('>I', tmpl_cs, bo+4)[0]
    tmpl_blobs[bt] = tmpl_cs[bo:bo+bl]

old_cd_blob = tmpl_blobs[0]
old_cms_der = tmpl_blobs[0x10000][8:]

# Parse template CD fields
cd = old_cd_blob
(magic, length, version, flags, hash_off, ident_off,
 n_special, n_code, code_limit, hash_size, hash_type,
 platform, page_size, spare2) = struct.unpack_from('>IIIIIIIIIBBBBI', cd)
print(f"template CD: n_special={n_special} n_code={n_code} hash_off={hash_off} "
      f"code_limit=0x{code_limit:X} hash_size={hash_size}")

# Find v19 code signature location
new_cs_off, new_cs_sz = find_cs(new_bin)
new_code_limit = new_cs_off
print(f"v19 code_limit=0x{new_code_limit:X} cs_size={new_cs_sz}")

PAGE = 4096
new_n_code = (new_code_limit + PAGE - 1) // PAGE
print(f"v19 n_code={new_n_code}")

# Compute v19 code slots (last page: no zero-padding — only actual code bytes)
code_slots = []
for i in range(new_n_code):
    end = min((i+1)*PAGE, new_code_limit)
    chunk = bytes(new_bin[i*PAGE:end])
    code_slots.append(hashlib.sha256(chunk).digest())

# Build new CodeDirectory from template structure
new_cd = bytearray(old_cd_blob)

# Update CodeResources special slot (slot 3)
slot3_off = hash_off - 3 * hash_size
new_cd[slot3_off:slot3_off+hash_size] = new_cr_hash

# Update n_code and code_limit
struct.pack_into('>I', new_cd, 28, new_n_code)
struct.pack_into('>I', new_cd, 32, new_code_limit)

# Write code slots
for i, slot in enumerate(code_slots):
    off = hash_off + i * hash_size
    new_cd[off:off+hash_size] = slot

new_length = hash_off + new_n_code * hash_size
struct.pack_into('>I', new_cd, 4, new_length)
new_cd = new_cd[:new_length]
new_cd_blob = bytes(new_cd)

print(f"New CD: length={new_length} n_code={new_n_code}")

# Rebuild CMS signature
old_cdhash = hashlib.sha256(old_cd_blob).digest()
new_cdhash = hashlib.sha256(new_cd_blob).digest()
print(f"Old CDHash: {old_cdhash.hex()[:16]}...")
print(f"New CDHash: {new_cdhash.hex()[:16]}...")

ci = cms_mod.ContentInfo.load(old_cms_der)
sd = ci['content']
si = list(sd['signer_infos'])[0]
old_sa_der = si['signed_attrs'].dump()

sa = old_sa_der.replace(old_cdhash, new_cdhash)
old_trunc = base64.b64encode(old_cdhash[:20])
new_trunc = base64.b64encode(new_cdhash[:20])
sa = sa.replace(old_trunc, new_trunc)
sa_for_sig = b'\x31' + sa[1:]
new_sig = key.sign(sa_for_sig, asym_padding.PKCS1v15(), hashes.SHA256())

def enc_len(n):
    if n < 0x80:   return bytes([n])
    if n < 0x100:  return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])

old_sig_bytes = si['signature'].native
old_octet = b'\x04' + enc_len(len(old_sig_bytes)) + old_sig_bytes
new_octet = b'\x04' + enc_len(len(new_sig))        + new_sig
assert len(old_octet) == len(new_octet), \
    f"Sig length mismatch: {len(old_octet)} vs {len(new_octet)}"

new_cms = bytearray(old_cms_der)
sa_pos  = old_cms_der.find(old_sa_der)
new_cms[sa_pos:sa_pos+len(old_sa_der)] = sa
sig_pos = bytes(new_cms).find(old_octet)
new_cms[sig_pos:sig_pos+len(old_octet)] = new_octet
cms_blob = struct.pack('>II', 0xFADE0B01, len(new_cms)+8) + bytes(new_cms)

# Rebuild SuperBlob
blobs_out = [(bt, tmpl_blobs[bt]) for bt in sorted(tmpl_blobs) if bt != 0 and bt != 0x10000]
blobs_out = [(0, new_cd_blob)] + blobs_out + [(0x10000, cms_blob)]

hdr = 12 + 8 * len(blobs_out)
offset = hdr; index = []; parts = []
for bt, bd in blobs_out:
    index.append((bt, offset)); parts.append(bd); offset += len(bd)

sb = struct.pack('>III', 0xFADE0CC0, offset, len(blobs_out))
for bt, bo in index: sb += struct.pack('>II', bt, bo)
sb += b''.join(parts)

if len(sb) > new_cs_sz:
    print(f"ERROR: SuperBlob {len(sb)} > cs_size {new_cs_sz}")
    sys.exit(1)

padded = sb + b'\x00' * (new_cs_sz - len(sb))
new_bin[new_cs_off:new_cs_off+new_cs_sz] = padded
print(f"SuperBlob: {len(sb)}/{new_cs_sz} OK")

# Package IPA: template structure with v19 binary
SKIP = {'Payload/AllocatorProbe_v15.app/agxfire_v15.html',
        'Payload/AllocatorProbe_v15.app/_CodeSignature/CodeResources'}

with zipfile.ZipFile(TEMPLATE_IPA) as zin, zipfile.ZipFile(OUT_IPA, 'w', zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        if item.filename in SKIP:
            continue
        new_name = item.filename.replace('AllocatorProbe_v15.app', 'AllocatorProbe_v16.app')
        info = zipfile.ZipInfo(new_name)
        info.external_attr = item.external_attr
        info.compress_type = zipfile.ZIP_DEFLATED
        if item.filename.endswith('AllocatorProbe_v15') and not item.filename.endswith('/'):
            zout.writestr(info, bytes(new_bin))
        else:
            zout.writestr(info, zin.read(item.filename))
    # Updated CodeResources
    cr_info = zipfile.ZipInfo('Payload/AllocatorProbe_v16.app/_CodeSignature/CodeResources')
    cr_info.compress_type = zipfile.ZIP_DEFLATED
    zout.writestr(cr_info, new_cr)

print(f"IPA: {OUT_IPA} ({OUT_IPA.stat().st_size} bytes)")

# Install
async def install():
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.installation_proxy import InstallationProxyService
    lockdown = create_using_usbmux(serial=UDID)
    print(f"Connected: {lockdown.product_version}")
    svc = InstallationProxyService(lockdown=lockdown)
    def progress(x, *a): print(f"  {x}", flush=True)
    svc.install_from_local(str(OUT_IPA), handler=progress)
    print("INSTALLED")

asyncio.run(install())
