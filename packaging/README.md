# Seal — Packaging

Build standalone executables for Windows, macOS, and Linux.

## Quick Start

```bash
# Install build dependencies
pip install -e ".[dev]"

# Build (directory mode — faster startup)
python packaging/build.py

# Build (single-file mode — slower startup, one executable)
python packaging/build.py --onefile

# Clean previous build first
python packaging/build.py --clean
```

## Output

```
packaging/dist/
  seal-win-amd64/          # Windows
    seal.exe
    ...dependencies...
  seal-linux-x86_64/       # Linux
    seal
  seal-macos-arm64/        # macOS Apple Silicon
    seal
```

## How It Works

PyInstaller traces imports from `aegis.cli:cli` and bundles:
- All `aegis` modules (cipher, key_manager, audit, canary, report, sharing, biometric)
- TUI screens and widgets (Textual)
- Crypto libraries (cryptography C extensions)

The build is `--onedir` by default (faster startup). Use `--onefile` for a single
executable that extracts on each run.

## Cross-Platform Notes

| Platform | Notes |
|----------|-------|
| Windows | `.exe` extension |
| macOS | Console application |
| Linux | Standard terminal application |

PyInstaller **cannot cross-compile**. Build on each target platform.

## Excluded

Heavy packages not needed at runtime: matplotlib, numpy, pandas, scipy, PIL, pytest.
