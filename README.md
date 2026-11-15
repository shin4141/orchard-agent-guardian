# Orchard

Orchard publishes two separate developer source components here. Each has its
own usage, verification and limits; a result from one does not qualify the
other.

| Component | Source | Build and use |
| --- | --- | --- |
| ZIP Inspector v0.1, standalone Python tool | [repository root](zip_inspector.py) | [Python instructions](#try-the-bundled-samples) |
| Orchard Release 1, local macOS ZIP reviewer | [versions/r1-macos/](versions/r1-macos/) | [Mac README](versions/r1-macos/README.md) and [BUILD.md](versions/r1-macos/BUILD.md) |

## Maintainer

Orchard is maintained by [@shin4141](https://github.com/shin4141).

The repository keeps the published Python v0.1 files at the root. Mac Release 1
is an additional source distribution under `versions/r1-macos/`; it has no
prebuilt app or bundled Homebrew runtime binaries. Its source files are the
approved 42-file packet, with a [source manifest](versions/r1-macos/SOURCE_MANIFEST.json),
[SHA256SUMS](versions/r1-macos/SHA256SUMS), [MIT LICENSE](versions/r1-macos/LICENSE)
and [third-party notices](versions/r1-macos/THIRD_PARTY_NOTICES.md).
The existing root [MIT LICENSE](LICENSE) is byte-identical to the Mac packet's
LICENSE. The Mac Build script copies runtime license texts from the developer's
own Homebrew installation into the locally generated app.

## Mac Release 1: build and use

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
