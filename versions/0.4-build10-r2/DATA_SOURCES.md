# Data sources / データの出典

Source: [abuse.ch MalwareBazaar](https://bazaar.abuse.ch/) official authenticated API/Export, in collaboration with Spamhaus Technology.
No malware samples are bundled or needed to use this version.

| Count / 件数 | Meaning / 意味 |
| --- | --- |
| 1,173,367 | Data rows validated in the temporary Full SHA-256 input; not its proven unique count / 一時Fullの検証行数。全件unique数は未確認 |
| 1,048 | Existing Recent unique values retained / 既存Recentから保持 |
| 98,952 | Additional unique selections from the bounded Full input / Fullから重複なく限定選定 |
| 100,000 | Unique values actually stored in this version / 実収録unique件数 |

The selection retains Recent and deterministically selects the remaining bounded subset. File order is not treated as age or recency.
This is neither the newest 100,000 entries nor a complete corpus; no broad detection coverage is guaranteed.
Full temporary data was deleted after validation. The full dataset and its standalone database are not distributed.

## Snapshot and freshness / 時刻と鮮度

| Field | UTC |
| --- | --- |
| Retained Recent source generation | 2026-11-14 03:24:27 |
| Retained Recent retrieval | 2026-11-14 03:38:48 |
| Full input source generation | 2026-11-14 22:27:04 |
| Full input retrieval | 2026-11-14 23:53:54 |

The reader retains the Recent source/retrieval dates and shows Full timestamps separately.
Build10 retains build8's removal of build7's age-only negative HOLD. After 25 hours, elapsed age is informational and matches/nonmatches against the stored snapshot remain available.
Database corruption, incomplete inspection, permission withdrawal, update failure and invalid clock conditions still prevent an affected result.
Automatic updates and continued acquisition are OFF. There is no update button that refreshes this database.

build8での25時間だけを理由とする未一致HOLDの撤廃をbuild10も維持します。取得時刻・DB・収録範囲は変更していません。
経過時間を表示したまま保存snapshotとの照合を行い、データが新しくなったとは扱いません。更新予定表示も実際の取得完了ではありません。
元のデータ受入metadataに残る90000秒は日時の参考値で、build10の照合を止める期限ではありません。

## Permission / 利用条件

The Orchard-specific written consent covers a subset bundled **as part of Orchard**, while the project remains free, open source and without commercial revenue.
Only SHA-256 values are stored here; no sample metadata is added. The consent does not specify 100,000 as a numerical license cap.
It requires attribution, no standalone dataset redistribution, no AI training/model customization, prompt entry removal on request, and compliance with written withdrawal.
Commercial use requires prior contact and separate terms. Once-a-day authenticated official updates are the stated guidance; scheduling is not enabled.

無料・非商用OSSのOrchard同梱subsetに限る条件付き許諾です。コードのMITライセンスをデータへ適用しません。
データ単体の抽出・公開・再配布、AI学習やモデルのカスタマイズには使えません。
削除・撤回通知時は影響する候補・古いコピーも退役します。[対応手順](SUPPORT.md)。
このoffline buildは提供元の通知を自動で受信せず、既に利用者が保存したコピーを遠隔削除できません。

Malware hash data courtesy of abuse.ch MalwareBazaar (https://bazaar.abuse.ch), provided in collaboration with Spamhaus Technology. Used with permission. No match does not mean a file is safe.
