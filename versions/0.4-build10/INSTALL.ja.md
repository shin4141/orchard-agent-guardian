# はじめてのインストール

Orchard 0.4（build10）はApple Silicon・macOS26以降向けです。署名はad-hocで、Appleの公証はありません。個別承認は安全保証ではありません。

## ダウンロードして、1回だけ展開する

1. 配布元のGitHub Releaseで `Orchard-0.4-build10-release.zip` と `SHA256SUMS` をダウンロードします。ファイル名と [checksum](VERIFY.md)・配布元を確認します。
2. ダウンロードしたZIPを1回展開します。Macの通常の操作なら、ZIPをダブルクリックします。
3. 展開された `Orchard-build10` フォルダを開きます。ここに **Orchard.app** があり、もう一つのアプリZIPを探したり展開したりする必要はありません。

```text
Orchard-build10/
  Orchard.app
  README.ja.md / README.md
  INSTALL.ja.md / INSTALL.md
  LICENSE / THIRD_PARTY_NOTICES.md
  licenses/
  examples/
```

README・INSTALL・ライセンス資料はアプリと同じ階層にあります。ライセンス資料も一緒に保持してください。PythonやHomebrewの別途導入は不要です。

## Orchardを開く

1. **Orchard.app** をダブルクリックします。旧版と同時に起動・監視しないでください。
2. Appleが開発者やマルウェア非含有を確認できない旨の警告が出た場合は、配布元と同一性を確認した上で、システム設定 → プライバシーとセキュリティへ進みます。
3. Orchardのブロック表示にある **「このまま開く」** を選びます。

![設定内のOrchardブロック表示と、このまま開くボタン](images/first-launch-blocked.ja.png)

4. 続く確認ダイアログでも **「このまま開く」** というラベルを確認して選びます。OSが本人認証を求めた場合は本人がOS画面で対応し、パスワードを問い合わせへ送りません。

![Orchardの警告とアプリ個別承認の確認ダイアログ](images/first-launch-open-anyway.ja.png)

上の2図は、提供された同じ日本語macOS画面のブロック表示と確認ダイアログを分けて切り抜いたものです。原本の画素を保持し、周辺情報と画像メタデータを除いています。クリック完了や起動後の結果を写した画像ではありません。OSや言語で文言は変わる場合があります。[Apple公式手順](https://support.apple.com/en-us/102445)。

Gatekeeper全体の無効化やquarantine属性の削除は不要です。「破損している」「コンピュータに損害を与える」、既知の危険、管理ポリシー等の別警告では停止し、[問い合わせ](SUPPORT.md)へ進みます。

## 最初の検査

起動後、「ZIPを選んで照合」から同じフォルダ内の `examples/benign-notes.zip` を選び、「このZIPを照合」を押します。参照倉庫と結果を読み、詳しくは [操作ガイド](GUIDE.ja.md)へ進みます。SHA未一致や規則未検出は安全保証ではありません。

既存の本人確認は、旧二重ZIPからブラウザ取得した現物での個別承認・起動・結果表示についての記録です。展開に使った操作方法は記録されておらず、Finderを使ったとは扱いません。この単層キットの実機受入とは別です。構造・ファイル一致・署名の静的確認を、別Macやworkerの実行時Sandbox試験へ転記しません。
