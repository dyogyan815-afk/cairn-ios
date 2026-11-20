#!/usr/bin/env python3
"""Generates synthetic IPA fixtures (no real apps are bundled). Run: python3 scripts/make-fixtures.py"""
import zipfile, plistlib, struct, os, zlib, random, hashlib
OUT = os.path.join(os.path.dirname(__file__), '..', 'tests', 'fixtures'); os.makedirs(OUT, exist_ok=True)
random.seed(7)

def macho(encrypted=False, fat=False):
    def thin():
        cmds = b''
        def lc(cmd, body): 
            body += b'\0' * ((-(8 + len(body))) % 8)
            return struct.pack('<II', cmd, 8 + len(body)) + body
        seg = b'__TEXT'.ljust(16, b'\0') + struct.pack('<QQQQiiII', 0x100000000, 0x4000, 0, 0x4000, 5, 5, 0, 0)
        cmds += lc(0x19, seg)
        d = b'/usr/lib/libSystem.B.dylib\0'; cmds += lc(0xc, struct.pack('<IIII', 24, 2, 0x10000, 0x10000) + d)
        d = b'@rpath/libswiftCore.dylib\0'; cmds += lc(0xc, struct.pack('<IIII', 24, 2, 0x50000, 0x10000) + d)
        cmds += lc(0x1b, bytes(range(16)))
        cmds += lc(0x32, struct.pack('<IIII', 2, 0x000f0000, 0x00110000, 0))
        cmds += lc(0x2c, struct.pack('<IIII', 0x4000, 0x8000, 1 if encrypted else 0, 0))
        n = cmds.count  # noqa
        count = 6
        hdr = struct.pack('<IiiIIIII', 0xfeedfacf, 0x0100000c, 0, 2, count, len(cmds), 0x200085, 0)
        return hdr + cmds + os.urandom(2000)
    t = thin()
    if not fat: return t
    off = 0x4000
    return struct.pack('>IIiiIII', 0xcafebabe, 1, 0x0100000c, 0, off, len(t), 14) + b'\0' * (off - 28) + t

def png(w=4, h=4):
    raw = b''.join(b'\0' + bytes([255, 0, 0, 255]) * w for _ in range(h))
    def ch(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    return b'\x89PNG\r\n\x1a\n' + ch(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) + ch(b'IDAT', zlib.compress(raw)) + ch(b'IEND', b'')

def cgbi_png(w=4, h=4):  # Apple style: CgBI chunk, raw deflate, BGRA premultiplied. Pixel = (R200,G100,B50,A128) premult
    px = bytes([25, 50, 100, 128])  # B,G,R premultiplied by 128/255, A
    raw = b''.join(b'\0' + px * w for _ in range(h))
    co = zlib.compressobj(9, zlib.DEFLATED, -15); idat = co.compress(raw) + co.flush()
    def ch(t, d): return struct.pack('>I', len(d)) + t + d + struct.pack('>I', zlib.crc32(t + d))
    return b'\x89PNG\r\n\x1a\n' + ch(b'CgBI', b'\x50\x00\x20\x06') + ch(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) + ch(b'IDAT', idat) + ch(b'IEND', b'')

def prov():
    pl = plistlib.dumps({'Name': 'Test Profile', 'TeamName': 'Test Team', 'TeamIdentifier': ['ABCDE12345'], 'UUID': 'x', 'ProvisionedDevices': ['a', 'b'], 'Entitlements': {'get-task-allow': True, 'application-identifier': 'ABCDE12345.com.example.demo'}})
    return b'0\x82\x01\x00junk-cms-header' + pl + b'\x00trailer-cms'

def build(name, many=0, big=0, encrypted=False, fat=False, weird=True, plugins=1, framework_nesting=True, binary_plist=True):
    app = 'Payload/Demo.app/'
    z = zipfile.ZipFile(os.path.join(OUT, name), 'w', zipfile.ZIP_DEFLATED)
    info = {'CFBundleName': 'Demo', 'CFBundleDisplayName': 'Demo App', 'CFBundleIdentifier': 'com.example.demo', 'CFBundleShortVersionString': '1.2.3', 'CFBundleVersion': '45', 'MinimumOSVersion': '15.0', 'CFBundleExecutable': 'Demo', 'UIDeviceFamily': [1, 2], 'CFBundleURLTypes': [{'CFBundleURLSchemes': ['demoapp']}], 'NSCameraUsageDescription': 'Take photos', 'NSLocationWhenInUseUsageDescription': 'Maps', 'CFBundleIcons': {'CFBundlePrimaryIcon': {'CFBundleIconFiles': ['AppIcon60x60']}}}
    z.writestr(app + 'Info.plist', plistlib.dumps(info, fmt=plistlib.FMT_BINARY if binary_plist else plistlib.FMT_XML))
    z.writestr(app + 'Demo', macho(encrypted, fat))
    z.writestr(app + 'AppIcon60x60@2x.png', cgbi_png(60, 60))
    z.writestr(app + 'embedded.mobileprovision', prov())
    z.writestr(app + '_CodeSignature/CodeResources', plistlib.dumps({'files': {}}))
    z.writestr(app + 'en.lproj/Localizable.strings', '"hello" = "Hello";\n')
    z.writestr(app + 'Assets.car', b'BOMStore' + os.urandom(3000))
    z.writestr(app + 'Base.lproj/Main.storyboardc/Info.plist', plistlib.dumps({'a': 1}, fmt=plistlib.FMT_BINARY))
    z.writestr(app + 'config.json', '{"k": 1}')
    z.writestr(app + 'unknown.bin', os.urandom(777))
    z.writestr(zipfile.ZipInfo(app + 'noext'), b'plain data without extension\n', compress_type=zipfile.ZIP_STORED)
    z.writestr(app + '.hidden_file', b'hidden')
    z.writestr(app + 'Fonts/Brand.ttf', b'\0\1\0\0' + os.urandom(500))
    z.writestr(app + 'Sounds/click.caf', b'caff' + os.urandom(300))
    z.writestr(app + 'Source/Leftover.swift', 'import UIKit\n// shipped by mistake\n')
    z.writestr(zipfile.ZipInfo(app + 'EmptyDir/'), b'')
    if weird:
        for n in ['Ünïcödé résumé.txt', 'space in name.txt', '日本語/ファイル.txt', 'emoji-😀.txt', 'a#b%c&d.txt', 'dots...txt']:
            z.writestr(app + 'Weird/' + n, 'x' + n)
    f = app + 'Frameworks/Core.framework/'
    z.writestr(f + 'Info.plist', plistlib.dumps({'CFBundleIdentifier': 'com.example.core', 'CFBundleExecutable': 'Core', 'CFBundleShortVersionString': '9'}, fmt=plistlib.FMT_BINARY)); z.writestr(f + 'Core', macho())
    if framework_nesting:
        g = f + 'Frameworks/Inner.framework/'; z.writestr(g + 'Info.plist', plistlib.dumps({'CFBundleIdentifier': 'com.example.inner'})); z.writestr(g + 'Inner', macho())
    for i in range(plugins):
        p = app + f'PlugIns/Ext{i}.appex/'
        z.writestr(p + 'Info.plist', plistlib.dumps({'CFBundleIdentifier': f'com.example.demo.ext{i}', 'CFBundleExecutable': f'Ext{i}', 'NSExtension': {'NSExtensionPointIdentifier': 'com.apple.widgetkit-extension'}}, fmt=plistlib.FMT_BINARY)); z.writestr(p + f'Ext{i}', macho())
    for i in range(many): z.writestr(app + f'Many/d{i // 100}/file_{i}.txt', f'file {i}\n' * (i % 7 + 1))
    if big: z.writestr(app + 'Big.dat', random.randbytes(big // 2) + b'\0' * (big // 2))
    z.close()

build('small.ipa', weird=False, plugins=0, framework_nesting=False)
build('many.ipa', many=1500)
build('big.ipa', big=24 * 1024 * 1024)
build('multi-ext.ipa', plugins=4, encrypted=True, fat=True, binary_plist=False)
build('encrypted.ipa', encrypted=True)
# damaged: truncated copy + garbage
data = open(os.path.join(OUT, 'small.ipa'), 'rb').read()
open(os.path.join(OUT, 'truncated.ipa'), 'wb').write(data[: len(data) // 2])
open(os.path.join(OUT, 'notzip.ipa'), 'wb').write(b'this is not a zip file' * 50)
# a bit-flipped entry (CRC mismatch) while directory is intact
b = bytearray(data); i = b.find(b'plain data without extension'); b[i] ^= 0xFF; open(os.path.join(OUT, 'corrupt-entry.ipa'), 'wb').write(bytes(b))
# duplicate names
z = zipfile.ZipFile(os.path.join(OUT, 'duplicates.ipa'), 'w'); z.writestr('Payload/D.app/a.txt', '1'); import warnings; warnings.simplefilter('ignore'); z.writestr('Payload/D.app/a.txt', '2'); z.close()
print('fixtures written to', OUT)
