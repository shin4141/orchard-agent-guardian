# Data sources / データの範囲 — Orchard 0.4 r4 (build12)

| Aggregate | Meaning / 意味 |
|---|---|
| 100,000 | Previous stored unique values, all retained / 旧版全件保持 |
| 200,000 | Actually added unique values / 実追加unique |
| 300,000 | Actual stored unique values / 実収録unique |
| 1,172 | Latest Recent unique values / 最新Recent |
| 116 | Latest Recent overlap with old DB / 旧DB重複 |
| 1,056 | Added from latest Recent / Recent新規 |
| 198,944 | Added from Full after old/Recent deduplication / Full新規 |
| 1,173,888 | Validated Full data rows, not proven total unique / Full検証行数 |

Old 100,000 values are retained. Eight were not observed in this Full; absence alone is not an explicit deletion request. Of the 1,172 Recent values, 1,169 were also observed in this Full. Inputs have different generation times. No chronological meaning is assigned to source ordering or bottom-k selection. This is not the latest 300,000, a complete corpus, or a guarantee of broad detection. Individual first-seen range and total Full unique count are unconfirmed.

旧10万件の8件は今回Fullに見当たりませんが保持しました。不在だけを撤回や削除要請とは扱いません。最新Recentのうち3件は今回Fullに見当たりません。生成時刻の異なるsnapshotであり、新旧順は推定しません。

| Component | Source generation UTC | Retrieval UTC |
|---|---|---|
| Oldest retained component | 2026-11-14T03:24:27Z | 2026-11-14T03:38:48Z |
| New Full | 2026-11-15T23:33:04Z | 2026-11-16T00:04:40Z |
| Latest Recent | 2026-11-15T23:55:07Z | 2026-11-16T00:04:31Z |

Latest Recent declares 2026-11-13T23:55:07Z through 2026-11-15T23:55:07Z (48 hours), not the range of all stored values. Retained source times are not rewritten as fresh. Elapsed age is advisory; matching remains available. Update failure, invalid clock, integrity and withdrawal checks remain. Automatic updates/scheduling are OFF; daily manual source review is the intended frequency. The app has no acquisition entry point.

Only authenticated official SHA-only Export was used: one Full GET, no Full HEAD/redirect/retry; one Recent HEAD plus one Recent GET. No samples, scraping or extra acquisition. Full CRC, entire ZIP structure, total expanded bytes, SHA single-column lines, provenance, UTC and footer count checks passed. The temporary Full ZIP was deleted; no Full DB/text is retained.

Malware hash data courtesy of **abuse.ch MalwareBazaar**, in collaboration with **Spamhaus Technology**. Used with permission. A nonmatch does not establish file safety. [Official source](https://bazaar.abuse.ch/export/). Orchard-specific consent applies only while Orchard is free, open source and without commercial revenue: a limited subset bundled as part of Orchard, no standalone dataset redistribution, no AI training/customization, no samples. 300,000 is a product target, not a numeric license cap. MIT does not license these data.

削除要請・書面による許諾撤回には速やかに対応し、抑止台帳を適用します。[support/removal](SUPPORT.md) / [security](SECURITY.md)。
