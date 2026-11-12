# Build Orchard Release 1 from source

The script builds one fresh `Orchard.app` on an **Apple Silicon Mac**. It never
launches the app, downloads dependencies, uses Developer ID, or notarizes the
result. A Build from this packet is a new local artifact, not the UI300 accepted
binary.

## Requirements

- macOS with Xcode or Xcode Command Line Tools providing `swiftc`, `xcrun`, a
  macOS SDK and `codesign`. Full Xcode was **not** needed in the local check.
- Homebrew packages `python@3.14`, `openssl@3`, `xz`, and `zstd` installed for
  the same Apple Silicon architecture. The Build script copies selected runtime
  files and their license texts from these local installations.
- A fresh output directory. The Build script refuses to overwrite an existing
  directory or reuse an existing bundle identifier.

The local Build checks ran on macOS 26.6.2 arm64, Apple Swift 6.3.3, Python
3.14.3_1, OpenSSL 3.6.3, xz 5.8.3 and zstd 1.5.7_1. Both the macOS 15.5 SDK
used for UI300 and the selected macOS 26.5 SDK produced an ad hoc signed app
from this packet. Other Macs, Xcode releases, dependency versions and Intel
builds are unverified.

## Commands

Install the Apple developer tools and the four Homebrew formulas first:

```sh
xcode-select --install
brew install python@3.14 openssl@3 xz zstd
```

If Xcode or its Command Line Tools are already installed, the first command
is unnecessary. From the packet root, use the Homebrew Python interpreter:

```sh
"$(brew --prefix python@3.14)/bin/python3.14" build.py --check
mkdir -p build
"$(brew --prefix python@3.14)/bin/python3.14" build.py --output build/first
```

If installed Homebrew inputs differ from the UI300-tested bytes, the script
stops before creating an app. To **try** a Build with those local versions,
repeat the check and Build with `--allow-runtime-variant`. That result is an
unqualified runtime variant; the command does not make it UI300-equivalent.

`build/first/Orchard.app` is the output. `build/first/BUILD_REPORT.json`
records toolchain versions, source and runtime hashes, signatures and the
result. Verify the local signature with:

```sh
codesign --verify --strict build/first/Orchard.app
```

The script uses the selected SDK by default. To name an installed SDK
explicitly, add `--sdk-path /path/to/MacOSX.sdk`.

## Human launch

To try a successful local Build, open its `Orchard.app` **once in Finder**.
Select a regular ZIP, inspect it, read the full report and limits, and use the
separate confirmation and limited-extraction controls only if you understand
the result. Normal Quit closes the session. The app records first use of a
Build ID; it does not automatically resume or retry that session. A new
attempt needs a new Build output with a fresh ID.

This source packet's Build was verified through compilation, ad hoc signing
and strict signature checks. **It was not launched or native-tested.** If
macOS blocks the ad hoc app or the UI reports a preparation HOLD, stop there;
do not treat that as a passing run or bypass a system warning.

The Build script does not create the external G1 diagnostic canary. The
“動作状態を記録” menu may therefore enter HOLD on a developer Build and must not
be counted as a Sandbox qualification.
