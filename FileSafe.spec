# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs

block_cipher = None

# Collect theme JSONs, fonts, and native tkdnd shared libraries
datas = []
datas += collect_data_files("customtkinter")
datas += collect_data_files("tkinterdnd2")

binaries = []
binaries += collect_dynamic_libs("tkinterdnd2")

a = Analysis(
    ["app.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=[
        "cryptography.hazmat.bindings._rust",
        "tkinterdnd2",
        "customtkinter",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Exclude unused heavy or network-capable stdlib modules to reduce attack surface
    excludes=[
        "unittest",
        "pydoc",
        "pdb",
        "xmlrpc",
        "ftplib",
        "telnetlib",
        "http.server",
        "sqlite3",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# Using --onedir mode instead of --onefile for security & reliability
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FileSafe",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # Disabled UPX to prevent AV false positives and binary mutation
    console=False,  # Windowed GUI mode (no background cmd prompt)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="FileSafe",
)