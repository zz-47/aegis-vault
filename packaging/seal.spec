# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Seal — run from project root: pyinstaller packaging/seal.spec"""

import sys
from pathlib import Path

block_cipher = None
ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"

a = Analysis(
    [str(SRC / "aegis" / "cli.py")],
    pathex=[str(SRC)],
    binaries=[],
    datas=[],
    hiddenimports=[
        # aegis submodules (lazy imports inside CLI commands)
        "aegis.cipher",
        "aegis.key_manager",
        "aegis.crypt_storage",
        "aegis.audit",
        "aegis.canary",
        "aegis.report",
        "aegis.biometric",
        "aegis.sharing",
        "aegis._errors",
        # TUI (launched lazily from `seal tui`)
        "aegis.tui",
        "aegis.tui.app",
        "aegis.tui.screens",
        "aegis.tui.screens.login",
        "aegis.tui.screens.vault",
        "aegis.tui.screens.entry",
        "aegis.tui.screens.generator",
        "aegis.tui.widgets",
        "aegis.tui.widgets.strength",
        # GUI (launched lazily from `seal gui`)
        "aegis.gui",
        "aegis.gui.app",
        # frameworks
        "tkinter",
        "tkinter.ttk",
        "tkinter.messagebox",
        "tkinter.simpledialog",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "numpy",
        "pandas",
        "scipy",
        "PIL",
        "pytest",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="seal",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
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
    upx=True,
    upx_exclude=[],
    name="seal",
)
