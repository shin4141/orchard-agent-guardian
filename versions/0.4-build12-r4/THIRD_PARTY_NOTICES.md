# Third-party notices / 第三者ライセンスと帰属

Keep this file, the accompanying MIT license and the `licenses/` directory with `Orchard Final Verified.app`. The complete license supplement is in the same release-kit folder as the app.

| Component | Version / identity | Terms and retained material |
| --- | --- | --- |
| Orchard original integration and R1-derived code | 0.4 build12 | [MIT](LICENSE); R1 copyright ©2026 shin4141 retained in [R1 notice](licenses/R1-MIT-LICENSE.txt) |
| CPython | 3.14.3, two private runtime copies | [PSF and historical license texts](licenses/Python-3.14.3-LICENSE.txt); [upstream incorporated-software appendix](licenses/Python-3.14.3-license-appendix.rst) |
| HACL* hash implementations | CPython v3.14.3 vendored sources | [MIT file-header and KaRaMeL notices](licenses/HACL-KaRaMeL-NOTICES.txt); [upstream Apache 2.0 text](licenses/Apache-2.0-HACL-LICENSE.txt) |
| KaRaMeL support headers | CPython v3.14.3 vendored headers | INRIA/Microsoft notice retained; Apache 2.0 and MIT notices above |
| Homebrew packaging changes | Installed CPython 3.14.3 bottle recipe | [BSD-2-Clause notice](licenses/Homebrew-BSD-2-Clause.txt); upstream sysconfig/macholib packaging adjustments |
| SQLite | 3.53.3 | [Public-domain dedication](https://www.sqlite.org/copyright.html); [bundled upstream README](licenses/SQLite-README.txt) |
| Expat-related Python code | CPython v3.14.3 source notice | [MIT COPYING](licenses/Expat-COPYING.txt); the actual native module links the OS libexpat |
| Other CPython-incorporated code | As described by the pinned 3.14.3 appendix | Mersenne Twister, SipHash, dtoa/strtod, mimalloc, asyncio and other applicable notices retained there |
| macOS frameworks/libraries | Provided by the user's OS | Dynamically linked system components, not copied into the kit |
| MalwareBazaar data | 300,000-value bounded subset | Separate conditional consent and mandatory [attribution](DATA_SOURCES.md), not MIT |

The full upstream Python appendix also describes components that are not shipped here. Its presence is not a claim that all those libraries are bundled.
No third-party pip/site-packages installation is included. The native `_ssl`, `_hashlib`, `_lzma`, `_decimal` and `_zstd` extensions and external OpenSSL libraries are absent.
The `readline` extension links macOS libedit, not a redistributed GNU Readline library.
Other native dependencies resolve to macOS libraries or the bundled Python/SQLite; no Homebrew install path is required at runtime.

## Runtime packaging / ランタイム同梱

The CPython runtime and selected standard-library/native modules were copied from the installed 3.14.3 distribution into a private framework.
Package paths and install IDs were adjusted and a runtime subset was selected. This r4 app uses Developer ID signatures and a stapled Apple notarization ticket.
The Homebrew CPython build includes its upstream packaging adjustments. Standard-library build metadata retains vendor prefixes; these are not private product workspace paths or required dynamic library locations.
Orchard's C launcher selects an isolated UTF-8 Python configuration and disables environment/site/current-directory imports.
The registration bridge validates and references existing state; it does not alter Sentinel detection/approval rules. The runtime manifest admits this exact additional bridge, and worker resource seals/version metadata are updated without changing worker machine-code instructions or database. Build8's age-advisory policy remains.
Some unused CPython test extension modules remain in the frozen bundle; removal is a future packaging-hardening item.

Python/SQLite等のライセンスと実データの利用条件は別です。runtimeはアプリ内に同梱され、利用者のPython環境を採用しません。
変更概要と原文noticeを維持し、ライセンス追補は外側キットへ同梱します。配布時もこの組合せを保ってください。

Primary sources: [CPython 3.14.3 license](https://github.com/python/cpython/blob/v3.14.3/LICENSE),
[3.14.3 appendix](https://github.com/python/cpython/blob/v3.14.3/Doc/license.rst),
[HACL* vendoring identity](https://github.com/python/cpython/blob/v3.14.3/Modules/_hacl/refresh.sh),
[HACL* license at that identity](https://github.com/hacl-star/hacl-star/blob/8ba599b2f6c9701b3dc961db895b0856a2210f76/LICENSE),
[KaRaMeL header](https://github.com/python/cpython/blob/v3.14.3/Modules/_hacl/include/krml/internal/target.h),
[SQLite](https://www.sqlite.org/copyright.html).
