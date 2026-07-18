# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = ['aegis.cipher', 'aegis.key_manager', 'aegis.crypt_storage', 'aegis.audit', 'aegis.canary', 'aegis.report', 'aegis.biometric', 'aegis.sharing', 'aegis._errors', 'aegis.tui', 'aegis.tui.app', 'aegis.tui.screens', 'aegis.tui.screens.login', 'aegis.tui.screens.vault', 'aegis.tui.screens.entry', 'aegis.tui.screens.generator', 'aegis.tui.widgets', 'aegis.tui.widgets.strength', 'aegis.gui', 'aegis.gui.app', 'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.simpledialog']
tmp_ret = collect_all('textual')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['C:\\Users\\Admin\\OneDrive\\Documents\\Research_projects\\aegis-vault\\src\\aegis\\cli.py'],
    pathex=['C:\\Users\\Admin\\OneDrive\\Documents\\Research_projects\\aegis-vault\\src'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['matplotlib', 'numpy', 'pandas', 'scipy', 'PIL', 'pytest'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='seal',
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
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='seal',
)
