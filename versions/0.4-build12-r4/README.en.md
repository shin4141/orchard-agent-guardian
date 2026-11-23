# Orchard 🍎 0.4 r4 — Getting started

Orchard 0.4 build12 r4 requires Apple Silicon and macOS 26 or later. The app is signed with Apple Developer ID and contains a stapled Apple notarization ticket.

1. Download `Orchard-0.4.0-r4-macos-arm64.zip` from the [GitHub release](https://github.com/shin4141/orchard-agent-guardian/releases/tag/v0.4.0-r4) Assets. The accompanying `SHA256SUMS` lets you verify the ZIP.
2. Expand the archive and open the `Orchard-0.4-r4` folder. The app, guides, licenses and data attribution are together in this folder.
3. Open `Orchard Final Verified.app`. The app includes its Python runtime.

To verify the download, put the ZIP and `SHA256SUMS` in the same folder and run `shasum -a 256 -c SHA256SUMS`.

Orchard statically examines suspicious instructions in ZIP files on your Mac. It can also report changes to instruction files such as `AGENTS.md` and `CLAUDE.md`. Check the result for uninspected content or structural errors. A nonmatch provides no safety guarantee. A person can compare, approve or defer detected changes. Monitoring neither stops an AI from reading or running files nor restores the files automatically.

[Japanese guide](README.ja.md) · [Software license](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md) · [Data terms and attribution](DATA_SOURCES.md) · [Support](SUPPORT.md)

[Source and build information](SOURCE_BUILD.md)
