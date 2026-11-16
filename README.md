# Orchard 🍎

## Orchardって何？

**ZIPをAIに渡したり展開したりする前に、中の不審な指示を確認する無料・非商用のMacアプリです。** 既知SHA-256の限定10万件と照合する機能もあります。開発者向けには、`AGENTS.md`・`CLAUDE.md`・`GEMINI.md` などの変更を見守る機能があります。**検査結果は安全の保証ではありません。**

### はじめて使う方へ（日本語）

1. [**Orchard 0.4 r2 のダウンロードページ**](https://github.com/shin4141/orchard-zip-inspector/releases/tag/v0.4.0-r2)の **Assets** から `Orchard-0.4-build10-release-r2.zip` を選びます。GitHubが自動表示する `Source code (zip)` ではありません。
2. ZIPを**1回だけ展開**してできた `Orchard` フォルダを開きます。**Safariが自動で展開した場合は、ダウンロード先にある `Orchard` フォルダを探してください。** 二重に展開する必要はありません。
3. `Orchard` の中には **`Orchard.app`** と **`はじめに・説明書`** の2つがあります。使うときはアプリを開きます。macOSの警告が出たら[画像付きの初回起動手順](versions/0.4-build10-r2/INSTALL.ja.md)をご覧ください。
4. `SHA256SUMS` は**ダウンロードしたZIPの同一性を詳しく確かめたい方向け**の別ファイルです。毎日取得するデータではなく、アプリを使い始めるための必須操作でもありません。[照合方法](versions/0.4-build10-r2/VERIFY.md)。

対応：**Apple Silicon・macOS 26以降**。Appleによる公証はないため、起動時に個別承認が必要な場合があります。Mac全体の保護を無効にしないでください。

[詳しい日本語README](versions/0.4-build10-r2/README.ja.md) · [英語の導入手順](versions/0.4-build10-r2/INSTALL.md)

**Orchard 0.4 (Release 1)** is a free, noncommercial Mac app for checking ZIPs locally *before extraction* and noticing changes to AI instruction files in local development folders, including `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`, `CLAUDE.local.md`, and `GEMINI.md`. It uses limited suspicious-instruction rules and a fixed, bounded database of 100,000 known SHA-256 values. A match or nonmatch is **not** a safety verdict. No automatic database updates or ZIP uploads.

### Download Orchard 0.4 for Mac

**[Download Orchard 0.4 r2 — Release 1](https://github.com/shin4141/orchard-zip-inspector/releases/tag/v0.4.0-r2)**

- **Mac:** Apple Silicon and macOS 26 or later; Japanese interface.
- **Download:** `Orchard-0.4-build10-release-r2.zip`. Expand this ZIP **once** and open `Orchard`: it contains exactly **Orchard.app** and **はじめに・説明書** (guides and notices). Open the app to use it; open the other folder for Japanese/English instructions, images, examples, source and licenses. No separate Python or Homebrew installation.
- **First launch:** The app is ad-hoc signed, **not Apple-notarized**. macOS may block the first launch; verify the source before following the app-specific steps in [INSTALL.ja.md](versions/0.4-build10-r2/INSTALL.ja.md) or [INSTALL.md](versions/0.4-build10-r2/INSTALL.md) (see [Apple's official instructions](https://support.apple.com/en-us/102445)). Do not disable Gatekeeper globally.
- **Verification:** `SHA256SUMS` is an optional download-integrity checksum, **not** a virus-definition update. The included 100,000-hash dataset is a fixed subset, not current or complete coverage.

r2 changes only the distribution layout; the app remains Orchard 0.4 build10. The original [v0.4.0 release](https://github.com/shin4141/orchard-zip-inspector/releases/tag/v0.4.0) remains available. [日本語の同梱説明書](versions/0.4-build10-r2/README.ja.md)（配布キット内で読む前提の案内を含みます）。

Published release assets appear on the Releases page. The software code's MIT license and the bundled MalwareBazaar data's conditional permission are separate.

## Research milestone — Real-VM lifecycle closure (November 16, 2026)

**Research prototype only — not included in the downloadable Orchard 0.4 app.**

**Why this matters:** For future investigation of untrusted files inside an isolated virtual machine (VM), a process exiting is not enough: the VM must actually stop, its owned temporary resources must be accounted for, and the operation must have a verifiable end state. This milestone demonstrates those steps in one controlled real-VM run; **it is not a test of malicious-file containment**.

In one human-authorized run using Apple's Virtualization framework, Orchard's private research prototype demonstrated:

- **Real execution:** One production authorization/issue, one VM creation and start, and **zero retries**.
- **VM stopped (L2):** The VM reported a successful stop callback, and a separate check confirmed the `stopped` state.
- **Owned resources cleaned up (L3):** Managed handles and the VM object were released; the owned disk and area were confirmed absent.
- **Completion recorded and verified (D2):** The formal ledger reached `RESOLVED / TERMINAL_RESPONSIBILITY_CLOSED` with no unresolved host latch. Evidence was preserved and independently read back.

**Scope and limits:** This is one bounded real-VM lifecycle result, **not** general malware containment, protection against sandbox escape, or reliability across arbitrary files and environments. The parent process exit receipt alone did not prove the VM stopped; that conclusion relies on separate VM-bound evidence. Release of internal backing resources managed by the virtualization service was **not independently verified** (`serviceBacking=UNKNOWN`).

The VM implementation and underlying evidence remain private. **Orchard 0.4 does not provide VM inspection or VM execution**, and this repository's MIT license does not license the private VM prototype. Integration, distribution and licensing are separate future decisions.

## Maintainer

Orchard is maintained by [@shin4141](https://github.com/shin4141).

## Earlier developer sources

The existing standalone Python ZIP Inspector and the earlier `r1-macos` **source-only prototype** are preserved below. Their validation and build instructions are separate from the Orchard 0.4 prebuilt app.

| Component | Source | Build and use |
| --- | --- | --- |
| ZIP Inspector v0.1, standalone Python tool | [repository root](zip_inspector.py) | [Python instructions](#try-the-bundled-samples) |
| Earlier macOS source-only prototype | [versions/r1-macos/](versions/r1-macos/) | [Mac README](versions/r1-macos/README.md) and [BUILD.md](versions/r1-macos/BUILD.md) |

The earlier macOS source-only prototype has no prebuilt app or bundled Homebrew runtime binaries. Its source files are the approved 42-file packet, with a [source manifest](versions/r1-macos/SOURCE_MANIFEST.json), [SHA256SUMS](versions/r1-macos/SHA256SUMS), [MIT LICENSE](versions/r1-macos/LICENSE) and [third-party notices](versions/r1-macos/THIRD_PARTY_NOTICES.md). The existing root [MIT LICENSE](LICENSE) is byte-identical to that earlier Mac packet's LICENSE. The earlier Mac Build script copies runtime license texts from the developer's own Homebrew installation into a locally generated app.

## Earlier macOS source-only prototype: build and use

On an Apple Silicon Mac, install the Apple developer tools and the local
Homebrew formulas listed in [Mac BUILD.md](versions/r1-macos/BUILD.md). Then
run the source check and fresh Build from the Mac component directory:

```sh
cd versions/r1-macos
"$(brew --prefix python@3.14)/bin/python3.14" build.py --check
mkdir -p build
"$(brew --prefix python@3.14)/bin/python3.14" build.py --output build/first
```

Open a successful locally built `Orchard.app` once in Finder and follow the
[human launch instructions](versions/r1-macos/BUILD.md#human-launch). The
result is a new locally ad hoc signed artifact. It has not inherited the
native acceptance of the UI300 test binary. Read the [Mac scope and limits](versions/r1-macos/README.md#limits):
`NOT_DETECTED` is not a safety guarantee, and limited extraction requires a
separate human action after review.

Future versions can be added under `versions/<version>/` with their own
source, README, Build instructions, manifest and notices. No VM source or VM
integration is included in this publication.

## ZIP Inspector v0.1 (Python)

**Experimental first-pass aid, not a safety verdict.** This standalone offline tool checks bounded ZIP structure and looks for instruction-like text in selected documentation files using fixed English/Japanese heuristics. Paraphrases, obfuscation, and other languages can evade these rules. It never extracts files to disk, executes archive members, or sends archive data anywhere. Reports include a file inventory, input SHA-256, matched text with line numbers, and explicit reasons when inspection is incomplete.

Python standard library only. This release candidate is validated with synthetic samples; it is not a malware scanner or a sandbox. **License: MIT** ([LICENSE](LICENSE)); copyright (c) 2026 shin4141. The Python ZIP Inspector v0.1 is publicly available as an experimental component in this repository.

### Try the bundled samples

Use Python 3.11+ on a POSIX system with `O_NOFOLLOW` and `O_NONBLOCK`. No packages or API keys are needed. Tested in a fresh CPython 3.14 environment on macOS; other Python/OS combinations are not yet verified.

```sh
git clone https://github.com/shin4141/orchard-zip-inspector.git
cd orchard-zip-inspector
python3 -B test_zip_inspector.py
python3 -B zip_inspector.py samples/forged_instructions.zip > report.json
python3 -c 'import json; r=json.load(open("report.json")); print(r["prompt_injection"], len(r["findings"]), len({f["category"] for f in r["findings"]}))'
```

Expected: `DETECTED 10 7`. The report lists `README.md` and an inert `payload.sh`; only the selected README text is scanned. Each finding includes its category, path, 1-based line, character offsets, matched text, and `UNTRUSTED_ARCHIVE_DATA` role. Instruction-like strings are evidence, never commands or approvals.

The seven existing heuristic categories are instruction override, role spoofing, authority spoofing, privilege requests, data transmission requests, tool execution requests, and finding suppression. The demo uses generic synthetic text and a reserved `.invalid` address; nothing is sent there.

Try the benign and unsupported samples:

```sh
python3 -B zip_inspector.py samples/benign.zip
python3 -B zip_inspector.py samples/uninspectable_encrypted_flag.zip
```

The second command intentionally exits **2** and returns `UNKNOWN` / `UNINSPECTABLE`. It is a flag-only synthetic ZIP, not a real encryption/decryption test. Exit **0** means the bounded inspection completed, even when suspicious text was detected. It never means the archive is safe.

Full example reports are in [examples/](examples/). `python3 -B demo.py out` regenerates all three synthetic samples and reports in a new output folder. The library entry point is `from zip_inspector import inspect_zip`, then `inspect_zip(path)`.

### Scope and limits

The standard `zipfile` parser is preceded by bounded central-directory checks. Metadata checks cover counts, declared sizes and expansion ratios, paths/collisions, local headers, flags, encryption, member types, and supported compression.

| Bound | Value |
|---|---:|
| Archive / central directory | 8 MiB / 128 KiB |
| Entries / UTF-8 path bytes | 128 / 512 |
| Declared member / aggregate size | 2 MiB / 8 MiB |
| Declared expansion ratio | 100x |
| Selected text | 8 files; 64 KiB each; 256 KiB total |
| Findings / quoted match length | 64 / 240 characters |

Selected basenames are README, AGENTS, INSTRUCTIONS, CONTRIBUTING, and SECURITY, with no extension or `.md`, `.txt`, `.rst`, case-insensitively. Only UTF-8 text and Stored/Deflate compression are supported. Selected text is decompressed **in memory** under limits; no members are written to disk. Selected Deflate streams are checked against their actual bounded length as well as declared metadata.

### Interpret the result

- `DETECTED`: a fixed English/Japanese heuristic matched selected text, including possible quotations. This does not prove malicious intent or a successful attack.
- `NOT_DETECTED`: no rule matched the selected text that was read. **This is not a safety guarantee or proof of absence.**
- `UNINSPECTABLE`: no finding was established and required inspection was unavailable or incomplete.
- `inspection_status=UNKNOWN`: unsupported, unreadable, malformed, or over-limit input; inspect `unknown_conditions`. Findings already detected can coexist with UNKNOWN.

Encryption, ZIP64, split/self-extracting/trailing containers, unsupported flags/compression, unsafe paths, collisions, links/special members, nested archives, invalid text, limits, and no selected text produce UNKNOWN conditions. Nonselected content is not content-scanned; its CRC and actual decompressed size are not verified. Size/ratio fields are declared metadata unless selected text was read.

The `gate` field is a report label: `HOLD` for findings or UNKNOWN, `CAP` for a completed bounded report with no finding. **Neither grants permission to open, extract, execute, approve, or trust an archive.** `safety_proven` and `authorizes_actions` are always false.

Obfuscation, paraphrases, other languages, images/binary content, nested content, general malware, AI-model behavior, and OS isolation are outside the validated scope. Use the synthetic samples to reproduce this candidate; arbitrary real-world archives have not been qualified. Input bytes are read-only, but full filesystem-metadata immutability is not claimed.

See [REVIEW.md](REVIEW.md) for the v0.1 release review and [REPRODUCIBILITY.json](REPRODUCIBILITY.json) for its clean-environment results. Those files and [RELEASE_DECISION.md](RELEASE_DECISION.md) record the 2026-11-06 standalone release; historical scope and pending-status statements in them do not describe the later macOS source addition. The MIT license applies to the source in this repository subject to the notices for each component. The Python v0.1 validation does not qualify the macOS app.
