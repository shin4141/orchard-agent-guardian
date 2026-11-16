# Rollback / 旧版へ戻す

Stop monitoring in build12 and quit it normally before opening old r2. Never run two monitors against the same state. Keep the unchanged r2 archive (SHA256 `4b43813dbcc85b1ea7ad1a376a748400c9d79ce3f3ee2e8bfb6f0f4bbd702770`).

For an adopted r2 registration, build12 references the same state directory and preserves the original r2 registration JSON. Sentinel's state format and detector are unchanged. Adoption itself preserves baseline, pending and history bytes; later explicit monitoring/review operations can update those records normally. Returning to r2 uses its existing pointer and current retained state. It does not undo explicit approvals or restore project files.

Fresh build12 or build11-only registrations are not automatically visible to r2. Keep build12 and its state if rollback needs that registration. Do not invent a registration, delete pending evidence, or merge state files to force compatibility. Disposable r2-equivalent adoption passed; a live switch or reverse launch of the older r2 was not tested. See [status](RELEASE_NOTES.md).

旧r2の実倉庫・ZIP・登録は本作業で上書きしません。戻す前に監視を止めて終了し、元のアプリを使います。旧保存先はbuild12から参照され得るため削除しないでください。
