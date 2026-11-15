# Third-party notices / 第三者ライセンスと帰属

Keep this file and `licenses/` with the distributed app. The single-extraction release includes the unchanged build10 Orchard.app and these supplemental notices together.
Keep the complete license supplement set with Orchard.app; the app bundle alone does not contain this entire supplemental set.

| Component | Version / identity | Terms and retained material |
| --- | --- | --- |
| Orchard original integration and R1-derived code | 0.4 build10 | [MIT](LICENSE); R1 copyright ©2026 shin4141 retained in [R1 notice](licenses/R1-MIT-LICENSE.txt) |
| CPython | 3.14.3, two private runtime copies | [PSF and historical license texts](licenses/Python-3.14.3-LICENSE.txt); [upstream incorporated-software appendix](licenses/Python-3.14.3-license-appendix.rst) |
| HACL* hash implementations | CPython v3.14.3 vendored sources | [MIT file-header and KaRaMeL notices](licenses/HACL-KaRaMeL-NOTICES.txt); [upstream Apache 2.0 text](licenses/Apache-2.0-HACL-LICENSE.txt) |
| KaRaMeL support headers | CPython v3.14.3 vendored headers | INRIA/Microsoft notice retained; Apache 2.0 and MIT notices above |
| Homebrew packaging changes | Installed CPython 3.14.3 bottle recipe | [BSD-2-Clause notice](licenses/Homebrew-BSD-2-Clause.txt); upstream sysconfig/macholib packaging adjustments |
| SQLite | 3.53.3 | [Public-domain dedication](https://www.sqlite.org/copyright.html); [bundled upstream README](licenses/SQLite-README.txt) |
| Expat-related Python code | CPython v3.14.3 source notice | [MIT COPYING](licenses/Expat-COPYING.txt); the actual native module links the OS libexpat |
| Other CPython-incorporated code | As described by the pinned 3.14.3 appendix | Mersenne Twister, SipHash, dtoa/strtod, mimalloc, asyncio and other applicable notices retained there |
| macOS frameworks/libraries | Provided by the user's OS | Dynamically linked system components, not copied into the kit |
| MalwareBazaar data | 100,000-value bounded subset | Separate conditional consent and mandatory [attribution](DATA_SOURCES.md), not MIT |

The full upstream Python appendix also describes components that are not shipped here. Its presence is not a claim that all those libraries are bundled.
No third-party pip/site-packages installation is included. The native `_ssl`, `_hashlib`, `_lzma`, `_decimal` and `_zstd` extensions and external OpenSSL libraries are absent.
The `readline` extension links macOS libedit, not a redistributed GNU Readline library.
Other native dependencies resolve to macOS libraries or the bundled Python/SQLite; no Homebrew install path is required at runtime.

## Installation image / 導入画像

The installation guide uses two cropped, metadata-free views of one maintainer-provided macOS screenshot. Its original warning and button pixels are retained. macOS system UI and Apple marks remain Apple's; the image does not imply Apple endorsement or notarization.

## Packaging changes / 包装時の変更

The single-extraction ZIP repackages existing build10 app bytes, file modes and symlinks without changing signed code, the database or signatures. No re-signing is performed for this distribution change.

The CPython runtime and selected standard-library/native modules were copied from the installed 3.14.3 distribution into a private framework.
Package paths/install IDs were adjusted, a subset was selected, and fresh ad-hoc signatures were applied during the earlier build.
The Homebrew CPython build includes its upstream packaging adjustments. Standard-library build metadata retains vendor prefixes; these are not private product workspace paths or required dynamic library locations.
Orchard's C launcher selects an isolated UTF-8 Python configuration and disables environment/site/current-directory imports.
This display-only repair leaves runtime libraries, Sentinel, detection rules, the worker, manifests and database unchanged. Build8's age-advisory policy is retained. Only the GUI host presentation/version changes, with a fresh embedded ad-hoc host seal.
Some unused CPython test extension modules remain in the frozen bundle; removal is a future packaging-hardening item.

Python/SQLite等のライセンスと実データの利用条件は別です。runtimeは候補内に同梱され、利用者のPython環境を採用しません。
変更概要と原文noticeを維持し、ライセンス追補は外側キットへ同梱します。配布時もこの組合せを保ってください。

Primary sources: [CPython 3.14.3 license](https://github.com/python/cpython/blob/v3.14.3/LICENSE),
[3.14.3 appendix](https://github.com/python/cpython/blob/v3.14.3/Doc/license.rst),
[HACL* vendoring identity](https://github.com/python/cpython/blob/v3.14.3/Modules/_hacl/refresh.sh),
[HACL* license at that identity](https://github.com/hacl-star/hacl-star/blob/8ba599b2f6c9701b3dc961db895b0856a2210f76/LICENSE),
[KaRaMeL header](https://github.com/python/cpython/blob/v3.14.3/Modules/_hacl/include/krml/internal/target.h),
[SQLite](https://www.sqlite.org/copyright.html).
