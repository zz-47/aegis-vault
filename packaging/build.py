#!/usr/bin/env python3
"""Cross-platform build script for Seal.

Usage:
    python packaging/build.py              # build for current platform
    python packaging/build.py --clean       # clean previous build first
    python packaging/build.py --onefile     # single-file executable (slower startup)
"""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "packaging" / "seal.spec"
BUILD_DIR = ROOT / "packaging" / "build"
DIST_DIR = ROOT / "packaging" / "dist"
SRC = ROOT / "src"


def _platform_tag() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "windows":
        return f"win-{machine}"
    if system == "darwin":
        return f"macos-{machine}"
    return f"linux-{machine}"


def clean():
    for d in [BUILD_DIR, DIST_DIR]:
        if d.exists():
            shutil.rmtree(d)
            print(f"  Removed {d}")


def build(onefile: bool = False):
    tag = _platform_tag()
    out_name = f"seal-{tag}"
    out_dir = DIST_DIR / out_name

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--workpath", str(BUILD_DIR),
        "--distpath", str(DIST_DIR),
        "--name", "seal",
        "--paths", str(SRC),
    ]

    if onefile:
        cmd.append("--onefile")
    else:
        cmd.append("--onedir")

    # hidden imports
    hidden = [
        "aegis.cipher", "aegis.key_manager", "aegis.crypt_storage",
        "aegis.audit", "aegis.canary", "aegis.report",
        "aegis.biometric", "aegis.sharing", "aegis._errors",
        "aegis.tui", "aegis.tui.app",
        "aegis.tui.screens", "aegis.tui.screens.login",
        "aegis.tui.screens.vault", "aegis.tui.screens.entry",
        "aegis.tui.screens.generator",
        "aegis.tui.widgets", "aegis.tui.widgets.strength",
        "aegis.gui", "aegis.gui.app",
        "tkinter", "tkinter.ttk", "tkinter.messagebox", "tkinter.simpledialog",
    ]
    for h in hidden:
        cmd.extend(["--hidden-import", h])

    # collect textual submodules
    cmd.extend(["--collect-all", "textual"])

    # exclude heavy unused packages
    for ex in ["matplotlib", "numpy", "pandas", "scipy", "PIL", "pytest"]:
        cmd.extend(["--exclude-module", ex])

    # entry point
    cmd.append(str(SRC / "aegis" / "cli.py"))

    print(f"\nBuilding Seal for {tag} …")
    print(f"  Command: {' '.join(cmd[-5:])}")
    print()

    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print(f"\nBuild FAILED (exit code {result.returncode})")
        sys.exit(1)

    # report
    if onefile:
        exe = DIST_DIR / ("seal.exe" if platform.system() == "Windows" else "seal")
        size_mb = exe.stat().st_size / (1024 * 1024) if exe.exists() else 0
        print(f"\nBuild complete: {exe}")
        print(f"  Size: {size_mb:.1f} MB")
    else:
        app_dir = DIST_DIR / "seal"
        if app_dir.exists():
            total = sum(f.stat().st_size for f in app_dir.rglob("*") if f.is_file())
            print(f"\nBuild complete: {app_dir}")
            print(f"  Size: {total / (1024 * 1024):.1f} MB (directory)")

    print(f"  Platform: {tag}")
    print(f"  Python: {platform.python_version()}")


def main():
    parser = argparse.ArgumentParser(description="Build Seal executable")
    parser.add_argument("--clean", action="store_true", help="Clean previous build")
    parser.add_argument("--onefile", action="store_true", help="Single-file executable")
    args = parser.parse_args()

    if args.clean:
        print("Cleaning previous builds …")
        clean()

    build(onefile=args.onefile)


if __name__ == "__main__":
    main()
