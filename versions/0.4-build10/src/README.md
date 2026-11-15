# build10 implementation source snapshot

This folder contains the seven Swift compilation inputs, C Python launcher, and ten Python sources shipped in the frozen app.
[SOURCE_MANIFEST.json](SOURCE_MANIFEST.json) records their exact file hashes. Generated Swift inputs match the accepted build's source identities.
The `sandbox_probe.py` file is an existing bundled diagnostic resource; the user guides do not invoke it.

Orchard source is MIT subject to [component notices](../THIRD_PARTY_NOTICES.md). The data is separately restricted and is not included in this source tree.
CPython 3.14.3 source and SQLite 3.53.3 are upstream dependencies, not copied in full here.

This is a readable implementation snapshot, **not a turnkey or reproducible-build kit**.
The private packaging history, private permission correspondence, real database, credentials and acceptance evidence are excluded.
A source rebuild needs compiler/runtime inputs, permitted replacement data or synthetic fixtures, regenerated integrity manifests/pins and fresh signing/acceptance.
The old artifact's GUI/installation PASS does not transfer to a rebuilt app. No command here starts a native test or obtains data.

実装sourceの確認・改変用snapshotです。既存の私有build手順や実データを公開したものではなく、再現buildのPASSは主張しません。
自動build補助は次回の課題として分離しています。

Build10 changes only host product labels and removes public simulation buttons. The packaged Python sources, age-advisory lookup, SHA data, detection rules, warning renderer and Sentinel behavior remain unchanged from build9. Verification modes remain in source. Build10 passed limited changed-UI acceptance with two inert ZIPs. This does not establish new Sentinel, installation or OS menu-bar acceptance.
