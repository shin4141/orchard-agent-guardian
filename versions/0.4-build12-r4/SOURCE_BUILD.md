# Orchard 0.4 r4 source and build information

Orchard 0.4 r4 is build12 for Apple Silicon and macOS 26 or later. The accompanying [source manifest](SOURCE_MANIFEST.json) records the nine Swift files used for the host, the eleven Orchard Python modules shipped in the host and worker, the shared C launcher source, and bundle configuration. Each source entry has a SHA-256 checksum.

## Swift host

The build used the macOS 26.5 SDK on Apple Silicon. Use the macOS Command Line Tools and the Swift compiler from the selected developer directory. The host compiles for `arm64-apple-macos26.0`. The inputs are ordered as shown below.

```sh
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)" xcrun swiftc \
  -Xlinker -no_adhoc_codesign -parse-as-library -O -target arm64-apple-macos26.0 \
  src/swift/OrchardMain.swift \
  src/swift/ResidencyService.swift \
  src/swift/SentinelRuntime.swift \
  src/swift/OrchardZip.swift \
  src/swift/R1WorkerProcessPort.swift \
  src/swift/ReviewModel.swift \
  src/swift/ThreatSummary.swift \
  src/swift/RegistrationContinuity.swift \
  src/swift/LocalReportStore.swift \
  -o Orchard
```

The output is the host executable at `Contents/MacOS/Orchard`.

## Python and C launchers

- Runtime components are CPython 3.14.3 and SQLite 3.53.3. The shipped app keeps a selected standard-library ZIP and native extension modules under each app-local Python framework.
- Build `src/c/PythonLauncher.c` with the CPython 3.14 headers and link it to the corresponding bundled Python framework binary. The launcher build uses `clang -O2 -target arm64-apple-macos26.0` and `-Wl,-rpath,@executable_path/../Frameworks/Python.framework/Versions/3.14`. Install the host copy as `Contents/MacOS/OrchardPython` and the worker copy as `Contents/Helpers/OrchardInspection.app/Contents/MacOS/OrchardZipWorker`.
- The launcher reads `Resources/python314.zip` and `Resources/lib-dynload` beneath the framework version directory. The source manifest supplies the bundle destinations for the Orchard Python files and the worker policy.
- Use the supplied property lists for the host and the worker and the worker App Sandbox entitlement. Package integrity manifests describe the app's selected runtime files, nested worker and database hashes.
- The data inside the distributed app are a collection of 300,000 SHA-256 values made available under separate terms. A local build must use data the builder is authorized to use. See [data scope and attribution](DATA_SOURCES.md).
- The notarized download has the maintainer's Developer ID signature and Apple ticket. The shipped integrity records are tied to that distribution. This source set documents corresponding implementation and build inputs. Reproducing the maintainer's signature and ticket depends on the maintainer's distribution process.

[CPython 3.14.3 source](https://github.com/python/cpython/tree/v3.14.3) · [SQLite 3.53.3 source](https://www.sqlite.org/src/info/version-3.53.3) · [Software license](LICENSE) · [Third-party licenses](THIRD_PARTY_NOTICES.md)

## 日本語

この版のSwift 9ファイル、同梱Python実装11ファイル、Cランチャー、AppとWorkerの設定を掲載しています。Swiftのコンパイル順と配置は上記とソース一覧に記載しています。CPython 3.14.3、SQLite 3.53.3、macOS SDKを使用します。データは別条件でアプリに収録されています。

[導入案内](README.ja.md) · [ソース一覧](SOURCE_MANIFEST.json) · [データ利用条件と帰属](DATA_SOURCES.md)
