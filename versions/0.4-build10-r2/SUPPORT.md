# Support and data requests / 問い合わせ・削除・撤回

General contact: [existing Orchard Issues](https://github.com/shin4141/orchard-zip-inspector/issues).
Report version/build, OS, result or warning category, and a short reproduction using harmless content.
For a confidential issue, post only a request for a private contact channel; wait before sharing details.
There is no newly registered external support service or guaranteed response time.

実SHA、DB、認証情報、監視原文・差分、検体、個人情報を公開Issueへ貼らないでください。
提供元の削除・許諾撤回通知は、既存の書面連絡経路を使用してください。秘密のticketリンクを公開しません。
一般利用者からの誤検知連絡は機密なしの連絡依頼で受け、必要な非公開経路を整えてから詳細を扱います。

## Maintainer procedure / 運用担当の手順

1. Record receipt time and a non-sensitive request reference. Confirm the requester and scope through the existing authenticated correspondence. Keep raw requested hashes and private notices out of public logs and Git.
2. Promptly hold affected distribution and use. Match the request against the managed-copy inventory: current/older app bundles and source ZIPs, older nested kits and single-extraction distributions, local warehouse generations, backups and any future published assets.
3. For entry removal, apply the existing monotonic suppression mechanism privately and prevent reintroduction. For consent withdrawal, retire all affected data use. Do not obtain new data or refresh timestamps as a workaround.
4. The frozen app pins its database. Editing its embedded DB is not a supported removal update. Stop/retire the affected build; any replacement needs a separately approved build, integrity check and acceptance.
5. If assets were later published, take them down and issue a non-sensitive withdrawal notice through the authorized release process. Tell recipients to stop using and remove affected copies. This offline build cannot remotely revoke or erase downloaded copies.
6. Verify local retirement and downstream actions, retain aggregate evidence of scope/completion, and reply through the established channel when authorized. An unresolved request keeps distribution on hold.

B/Cが受領記録、抑止・退役、既知コピーの追跡、非秘密証拠、確認を担当します。
この手順書の作成により、今すぐ既存データを削除したり、通知を送信したりしたものではありません。
無料・非商用OSS、subsetのみ、帰属、AI学習不使用の条件を維持し、商用化前には別途提供元と協議します。
ソフトウェアのMITライセンスとデータの条件付き許諾は分けて扱います。
