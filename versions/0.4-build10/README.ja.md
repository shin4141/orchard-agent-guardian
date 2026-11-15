# Orchard 🍎 0.4

Mac内のZIPを静的検査し、開発フォルダの指示ファイルの変更に気づくための無料・非商用OSSです。
疑わしい指示の規則検査と、保存済み100,000件のSHA-256との照合は別の機能です。
SHA一致・未一致は調査の先行手掛かりで、安全・危険や実行可否の確定判定ではありません。

**Release 1（build10）です。製品バージョンはOrchard 0.4です。**
Apple Silicon・macOS26以降向け。CPython3.14.3とSQLite3.53.3を同梱し、Python/Homebrewの別途導入は不要です。

## 使い始める

1. 配布元のReleaseから配布キットとSHA256SUMSを入手し、[配布物を検証](VERIFY.md)します。
2. [画像付き初回起動手順（警告と個別承認）](INSTALL.ja.md)に従い、ダウンロードしたZIPを1回展開し、同じ階層にある `Orchard.app` を開きます。
3. [操作ガイド](GUIDE.ja.md)の無害ZIPと使い捨てフォルダで確認します。

配布ZIPは `Orchard-0.4-build10-release.zip`。展開後は `Orchard.app`、README、INSTALL、ライセンス資料が並びます。追加のアプリZIP展開は不要です。配布物のSHA256は `SHA256SUMS` で確認できます。画面の製品バージョンは「Orchard 0.4」です。

## 結果の読み方

| 表示 | 意味 |
| --- | --- |
| 疑わしい指示を検出しました | SHA結果より上の24pt太字・赤・警告アイコン。対象規則に一致した文言がある。マルウェア確定ではない |
| 対象規則内で疑わしい指示は検出されませんでした | 対象規則内の未検出。安全保証ではない |
| 指示の検査を完了できませんでした | 未検出とは異なる未完了状態 |
| 対象DBの既知SHAに一致 | 限定倉庫内に一致する値がある。内容の意図・危険性を確定しない |
| 対象DB内に一致なし | 読み取れた範囲で一致がない。安全・開封・実行の許可ではない |
| HOLD | DB破損、検査不能、許諾撤回、更新失敗、時刻異常等。経過時間だけでは照合を止めない |

元データの取得日時・出典・限定収録範囲を表示します。保存済み10万件との一致・未一致は25時間超でも照合します。
最新10万件でも全件収録でもありません。Recent保持1,048件＋限定Full98,952件で、元Fullの検証済み1,173,367 data rowsとは別の数です。
自動更新はOFFです。新しい脅威や広範な検出を保証しません。[出典と条件](DATA_SOURCES.md)。

## ローカル開発フォルダを見守る

GitHubを使っていない開発者も、Mac内の開発フォルダを登録できます。GitHubアカウントやGit repositoryは不要です。
対応する指示MDがまだなくても登録でき、監視中に対象MDが新しく作成された場合は追加として検知します。
対象はAGENTS.md、AGENTS.override.md、CLAUDE.md、CLAUDE.local.md、GEMINI.mdです。除外ディレクトリ・深さ・件数等の制限があります。

現行版の監視登録は**1フォルダ**です。登録直後は停止中で、監視開始は手動です。停止中・アプリ終了中を含む常時監視は保証しません。
「🍎 見守り」は監視が正常かつ未確認0件の状態です。変更時は日本語説明・原文・差分を確認し、明示承認して基準へ反映できます。
未確認の証拠は停止だけで消えません。ログイン項目登録は無効です。
すべてのAI書込みを防止したり、AIのRead → Agent → Writeを追跡する機能はありません。

署名はad-hoc、公証なしです。Appleが開発者や安全性を確認したことを意味しません。
build10はmacOS26.6.2で変更UI・検出用ZIP・無害ZIPの限定受入を確認済みです。Sentinel等の全面再試験は行っていません。旧版のPASSを新build全体のPASSへ転記しません。
配布者本人は、旧二重ZIPのブラウザ取得現物で個別承認・起動・検査結果表示を確認しました。展開操作の方法は未記録で、Finderを使ったとは扱いません。旧取得物のSHA一致と新しい単層キットの静的照合は別記録です。単層キットのMac受入、別Mac・新規user・実行時worker Sandbox・新しいOSメニューバー証拠へはPASSを転記しません。

[English](README.md) · [限界](LIMITS.md) · [Privacy](PRIVACY.md) · [Security](SECURITY.md) · [ライセンス](THIRD_PARTY_NOTICES.md) · [Release Notes](RELEASE_NOTES.md) · [停止・削除](UNINSTALL.md) · [問い合わせ・削除要請](SUPPORT.md) · [次回拡張](BACKLOG.md)

コードのMITライセンスとデータの利用許諾は別です。データはabuse.ch/Spamhausの条件付き許諾で、無料・非商用OSSのOrchardに限定subsetとして同梱します。
帰属、削除要請・許諾撤回対応を維持し、データ単体再配布・AI学習/カスタマイズ利用は認められません。[LICENSE_SCOPE.md](LICENSE_SCOPE.md)。

Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe.
