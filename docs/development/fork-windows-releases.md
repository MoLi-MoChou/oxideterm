# MoLi-MoChou fork: Windows-only releases

This repository is a fork of [AnalyseDeCircuit/oxideterm](https://github.com/AnalyseDeCircuit/oxideterm).

## Updater

Built-in update endpoints in `crates/oxideterm-update` point at **MoLi-MoChou/oxideterm**:

- Stable: `https://github.com/MoLi-MoChou/oxideterm/releases/latest/download/latest.json`
- Beta: `https://github.com/MoLi-MoChou/oxideterm/releases/download/updater-beta/latest.json`

Signatures are verified with the fork minisign public key (`OXIDETERM_UPDATER_PUBKEY`).

## Packaging

Use [`.github/workflows/windows-release.yml`](../../.github/workflows/windows-release.yml) to build and publish **Windows x64 only** (`x86_64-pc-windows-msvc`). It reuses `scripts/release/package_native.py`, signs assets with the Tauri/minisign secrets, uploads exe/zip/sig/sha256sums, and writes a Windows-only `latest.json` (also copied to the `updater-beta` channel tag).

Do not use the full multi-platform `native-package.yml` path for fork releases unless macOS/Linux assets are intentionally produced.
