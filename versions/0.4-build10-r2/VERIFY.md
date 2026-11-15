# Verify the distribution / 配布物を確かめる

Download `Orchard-0.4-build10-release-r2.zip` and `SHA256SUMS` from the same trusted [project Release](https://github.com/shin4141/orchard-zip-inspector/releases).
One extraction produces `Orchard/` with exactly two items: `Orchard.app` and `はじめに・説明書/`. The guides folder contains every document, example, license notice and source snapshot. No second application ZIP is included.

For optional command-line verification, in the folder containing the two downloaded files:

```sh
shasum -a 256 -c SHA256SUMS
```

Expect `Orchard-0.4-build10-release-r2.zip: OK`. A checksum detects changed bytes; it does not authenticate the publisher or prove safety. Stop if it differs.

After extraction, optional static checks from inside `Orchard` (the folder containing the app) are:

```sh
shasum -a 256 -c "はじめに・説明書/SHA256SUMS.files"
codesign --verify --deep --strict Orchard.app
```

The manifest lives in the guides folder, but its paths are relative to the parent `Orchard` folder. Do not run that command from the guides folder. It is a distribution-file integrity list, not the MalwareBazaar hash dataset.

`SHA256SUMS.files` covers the regular app files and bundled documents/examples. It excludes itself and does not follow symlinks as separate entries. Packaging checks separately compare all six app symlink targets and all file modes with the pinned build10 source.
Signature verification here checks the existing ad-hoc seal; it does not establish Developer ID, notarization, runtime Sandbox enforcement or safety. These commands do not launch Orchard.

配布ZIPのchecksumを確認して1回展開すると、`Orchard` 内にアプリと説明書フォルダの2項目が並びます。内部checksumの任意確認は説明書フォルダの1つ上で行います。初心者向けの操作は [初回導入](INSTALL.ja.md) を参照してください。checksumや署名の一致は安全判定ではありません。ライセンス資料を一緒に保持してください。
ソース用Gitに実DBや実SHA一覧を置きません。
