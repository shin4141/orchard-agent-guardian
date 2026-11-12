# Third-party notices

This source packet contains no Homebrew runtime binaries. Its Build script
copies runtime files from the developer's local Homebrew installations and
places the corresponding license texts in the generated app under
`Contents/Resources/OrchardZipWorker/LICENSES/`.

| Component copied into a local Build | License source |
| --- | --- |
| Python 3.14 runtime and standard library | [Python Software Foundation](https://www.python.org/about/legal/) license from the installed formula |
| OpenSSL 3 `libcrypto` | [OpenSSL](https://openssl-library.org/source/license/) Apache-2.0 license from the installed formula |
| XZ `liblzma` | [XZ Utils](https://github.com/tukaani-project/xz/blob/master/COPYING) and 0BSD texts from the installed formula |
| Zstandard `libzstd` | [Zstandard](https://github.com/facebook/zstd) license text from the installed formula |

The included ZIP inspector is the pinned Orchard A1 source. Its original MIT
notice is preserved at
`validation/orchard_r1_a1_zip_engine_20261108_01/LICENSE`.

These notices describe the source packet and local Build inputs. A later
distribution of **binaries** needs a separate review of the exact runtime
versions and their required notices.
