# Orchard 🍎 0.4 r4 — 導入案内

Apple SiliconとmacOS 26以降に対応しています。Orchard 0.4 build12 r4はApple Developer IDで署名され、Apple公証チケットがアプリに添付されています。

1. [GitHub Release](https://github.com/shin4141/orchard-zip-inspector/releases/tag/v0.4.0-r4)のAssetsから `Orchard-0.4.0-r4-macos-arm64.zip` を取得します。同じ場所の `SHA256SUMS` でZIPのSHA-256を照合できます。
2. ZIPを展開し、`Orchard-0.4-r4` フォルダを開きます。アプリと案内、ライセンス、帰属資料は同じフォルダにあります。
3. フォルダ内の `Orchard Final Verified.app` を開きます。必要なPythonランタイムはアプリに同梱されています。

照合する場合は、ダウンロードしたZIPと `SHA256SUMS` を同じフォルダに置き、`shasum -a 256 -c SHA256SUMS` を実行します。Safariで自動展開された場合は、照合用のZIPがダウンロード先に残っているか確認してください。

OrchardはZIP内の疑わしい指示をローカルで静的に調べ、`AGENTS.md` や `CLAUDE.md` などの変更を通知します。結果画面で本文未検査や構造異常を確認できます。未検出やSHAの未一致は安全保証ではありません。MDの変更は人が原文を比較して承認または保留できます。監視によるAIの読取り・実行の自動停止や、ファイルの自動復元はありません。

[英語の導入案内](README.en.md) · [ソフトウェアライセンス](LICENSE) · [第三者ライセンス](THIRD_PARTY_NOTICES.md) · [データの条件と帰属](DATA_SOURCES.md) · [問い合わせ](SUPPORT.md)

[ソースとビルド情報](SOURCE_BUILD.md)
