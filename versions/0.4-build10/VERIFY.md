# Verify the distribution / 配布物を確かめる

Download `Orchard-0.4-build10-release.zip` and `SHA256SUMS` from the same trusted [project Release](https://github.com/shin4141/orchard-zip-inspector/releases).
One extraction produces `Orchard-build10/Orchard.app` beside the guides and license materials. No second application ZIP is included.

For optional command-line verification, in the folder containing the two downloaded files:

```sh
shasum -a 256 -c SHA256SUMS
```

Expect `Orchard-0.4-build10-release.zip: OK`. A checksum detects changed bytes; it does not authenticate the publisher or prove safety. Stop if it differs.

After extraction, optional static checks inside `Orchard-build10` are:

```sh
shasum -a 256 -c SHA256SUMS.files
codesign --verify --deep --strict Orchard.app
```

`SHA256SUMS.files` covers the regular app files and bundled documents/examples. It excludes itself and does not follow symlinks as separate entries. Packaging checks separately compare all six app symlink targets and all file modes with the pinned build10 source.
Signature verification here checks the existing ad-hoc seal; it does not establish Developer ID, notarization, runtime Sandbox enforcement or safety. These commands do not launch Orchard.

配布ZIPのchecksumを確認して1回展開すると、アプリと資料を利用できます。初心者向けの操作は [初回導入](INSTALL.ja.md) を参照してください。checksumや署名の一致は安全判定ではありません。ライセンス資料を一緒に保持してください。
ソース用Gitに実DBや実SHA一覧を置きません。
