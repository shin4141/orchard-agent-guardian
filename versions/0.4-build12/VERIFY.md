# Verify / 配布物の照合

Download the release kit `Orchard-0.4-build12-release.zip` and its external `SHA256SUMS`. That external file contains exactly one entry for the kit ZIP. Put those two files in the same folder; an app-only archive is not required. In that folder, run:

```sh
shasum -a 256 -c SHA256SUMS
```

Expected: `Orchard-0.4-build12-release.zip: OK`. Stop on mismatch. A checksum establishes identity, not safety or publisher authentication.

配布ページからキットZIPと外部 `SHA256SUMS` を同じフォルダへ保存します。外部checksumはキットZIPの1行だけで、内部用アプリZIPは不要です。そのフォルダで上のコマンドを実行し、`OK` を確認してください。一致は安全保証ではありません。

Expand once: `Orchard/` contains exactly `Orchard.app` and `はじめに・説明書/`. The latter holds licenses, source, images and inert examples. No nested application ZIP is needed. `SHA256SUMS.files` checks extracted guide/source files; `src/SOURCE_MANIFEST.json` identifies implementation inputs. The `SHA256SUMS` inside the guides is an internal app-archive reference, not the external release checksum used above.

説明書内の `SHA256SUMS` は内部用アプリZIPの参照値です。上の照合には、配布ページからキットZIPと一緒に取得した外部ファイルを使います。

Deep/strict ad-hoc signature verification is a packaging check, not Developer ID, Apple notarization or native acceptance. See [status](RELEASE_NOTES.md).
