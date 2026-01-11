# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# 如果有 capstone_helpers.py，请加入 datas 或作为模块分析
# 这里的 hiddenimports 确保动态加载的库被包含
hidden_imports = [
    'frida',
    'capstone',
    'PyQt5',
    'layered_detector',
    'frida_enhanced',
    'utils'
]

a = Analysis(
    ['gui_scanner.py'],  # 这里指定你的入口，如果想打GUI版选 gui_scanner.py
    pathex=[],
    binaries=[],
    datas=[],  # 如果有额外的非代码文件（如 rules.yara），加在这里
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CryptoScanner',  # 输出exe的名字
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 如果安装了UPX可以压缩体积
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI版本设为 False，CLI版本设为 True
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)