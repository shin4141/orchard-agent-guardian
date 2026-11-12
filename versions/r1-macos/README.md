**I trust my mother. But I don't trust her ZIP files.**

# Orchard Release 1

Orchard is a local macOS ZIP reviewer. A ZIP can contain text that tries to steer
a person or an AI assistant. Orchard inspects a bounded part of the archive,
shows the evidence and limits, and leaves the decision to you. It does not
upload the ZIP or hand its contents to an AI service.

## The result

- **DETECTED** means the local rules found suspicious instruction text.
- **UNKNOWN** means the selected content could not be assessed sufficiently.
- **NOT_DETECTED** means those rules found no match in the content they read. It
  does **not** mean the ZIP is safe.

The report identifies the input SHA-256, inspected scope, findings and unknown
conditions. Read those details before deciding. A result marked `CAP` permits a
static report only; it is not permission to open or trust the archive.

Choosing a ZIP does not inspect or extract it. After inspection, a human must
explicitly confirm the current result within the 300-second review window.
**Limited extraction is a separate action.** There is no automatic extraction
or AI handoff.

## Build and try it

This is a **source distribution**, with no prebuilt app or third-party runtime
binaries. See [BUILD.md](BUILD.md) for the Apple Silicon macOS toolchain,
Homebrew dependencies, source Build command and Finder launch steps. The Build
script makes a fresh, locally ad hoc signed app. A developer's new Build has
not inherited the native acceptance of the UI300 test binary.

## Limits

Orchard reads ZIP metadata and allowlisted UTF-8 text within fixed limits. It
does not content-scan nested archives, unselected files or binary payloads; it
does not verify every member CRC. It is not a malware scanner and cannot prove
that an archive contains no prompt injection or other dangerous content.

「alias・symlink・hardlinkは受け付けない。本物のファイルを選び直してください。」

The fixed rejection cases covered a physical `/tmp` path, a symlink and a
hardlink. Rejection of every macOS/Finder alias route has **not** been proven.
No safety guarantee follows from a rejection or a `NOT_DETECTED` result.

The source Build does not provision the G1 diagnostic canary outside the app.
Its “動作状態を記録” menu is therefore not a qualification test for a developer
Build and may enter HOLD. The locally built app has not been native accepted.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and [LICENSE](LICENSE) for
source notices. The Build script copies runtime license texts from the
developer's own Homebrew installation into the generated app.
