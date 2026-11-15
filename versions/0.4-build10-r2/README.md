# Orchard 🍎 0.4

**First launch:** Go back one folder to `Orchard` and open **Orchard.app**. If macOS blocks it, see the [illustrated app-specific approval steps](INSTALL.md#open-orchard). The [short Japanese starting page](00_はじめに.md) is also included.

A free, noncommercial open-source Mac app for static ZIP inspection and noticing changes to instruction files in a local development folder.
Suspicious-instruction rules and comparison with a stored 100,000-entry SHA-256 snapshot are separate functions.
SHA matches and nonmatches are early investigative leads, not conclusive safe/unsafe or execution verdicts.

**Release 1 (build10). The product version is Orchard 0.4.**
For Apple Silicon/macOS26+. CPython3.14.3 and SQLite3.53.3 are bundled; no separate Python/Homebrew installation is needed. The UI is Japanese.

## Start here

1. Obtain the kit and SHA256SUMS from the project Release and [verify them](VERIFY.md).
2. Expand the downloaded ZIP once, open **Orchard.app** directly inside `Orchard`, and follow the [illustrated first-launch steps](INSTALL.md). Then try the harmless ZIP in the [guide](GUIDE.md).
3. Read [stop and uninstall](UNINSTALL.md) before removing saved monitoring evidence.

The distribution is `Orchard-0.4-build10-release-r2.zip`. One extraction produces `Orchard` containing exactly **Orchard.app** and **はじめに・説明書** (guides and notices). All documentation, images, examples, licenses and source are in the latter. This is packaging revision r2; the app version, signature and functions are unchanged. Use the accompanying `SHA256SUMS` to verify it. The visible product version is Orchard 0.4.

## Read the results

| Result | Meaning |
| --- | --- |
| Suspicious instructions detected | A 24pt bold system-red warning and icon take priority over the SHA result. A rule matched; this is not a malware verdict |
| No suspicious instructions detected within the rules | Limited non-detection, not proof of safety |
| Instruction inspection incomplete | Distinct from non-detection |
| Known SHA match | A value exists in the bounded snapshot; intent or danger is not established |
| No match in the covered database | No match among successfully inspected files; not permission to open or execute |
| HOLD | Corruption, incomplete inspection, withdrawal, failed update or invalid time prevents the affected result; age alone does not |

Source/retrieval times and bounded coverage remain visible. Comparison against the stored 100,000 entries continues after 25 hours.
The snapshot retains 1,048 Recent entries plus 98,952 bounded Full selections. It is neither the newest 100,000 nor the whole corpus.
The validated Full input had 1,173,367 data rows, a separate count. Automatic updates are OFF; current or broad threat detection is not guaranteed. [Data conditions](DATA_SOURCES.md).

## Monitor a local folder

Developers who do not use GitHub can register a development folder on their Mac. No GitHub account or Git repository is needed.
Registration also works when no supported instruction MD exists yet; creating a supported file while monitoring produces an added-file change.
Supported names are AGENTS.md, AGENTS.override.md, CLAUDE.md, CLAUDE.local.md and GEMINI.md. Directory exclusions and depth/count/size limits apply.

The current version registers **one folder**. A new registration starts stopped; starting monitoring is manual. Continuous monitoring is not guaranteed, including while stopped or after the app exits.
「🍎 見守り」 means healthy monitoring with zero unreviewed changes. Japanese explanation, original text and diff support explicit baseline approval.
Stopping does not erase pending evidence. Login-item activation is disabled. The app does not prevent all AI writes or trace agent read/write provenance.

Signing is ad-hoc, without notarization. Apple publisher verification or safety review is not established.
Build10 passed limited changed-UI, detected-ZIP and benign-ZIP acceptance on macOS26.6.2. Sentinel and other previously accepted functions were not fully retested; prior evidence does not qualify the rebuilt app as a whole.
The maintainer confirmed app-specific approval, launch and inspection results using an actual browser download of the older nested kit. The extraction method was not recorded; Finder use is not asserted. The old download checksum and this single-extraction kit's static checks are separate evidence. They do not establish Mac acceptance of the new kit, another-Mac operation, a new user, runtime worker Sandbox enforcement or new OS menu-bar evidence.

[日本語](README.ja.md) · [Limits](LIMITS.md) · [Privacy](PRIVACY.md) · [Security](SECURITY.md) · [Licenses](THIRD_PARTY_NOTICES.md) · [Release notes](RELEASE_NOTES.md) · [Support/removal](SUPPORT.md) · [Backlog](BACKLOG.md)

The software's MIT license does not license the dataset. abuse.ch/Spamhaus grants conditional inclusion of a bounded subset only inside free, noncommercial OSS Orchard.
Attribution, prompt entry removal and written withdrawal apply. Standalone redistribution and AI training/customization are prohibited. [License scope](LICENSE_SCOPE.md).

Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe.
