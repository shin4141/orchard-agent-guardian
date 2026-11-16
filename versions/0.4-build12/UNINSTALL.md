# Stop and remove / 停止・削除

Stop monitoring in Orchard and quit it normally. Move the unwanted app/kit to Trash. Do not remove your development project. The bundled SHA subset is removed with the app; do not extract or redistribute it as a dataset.

The version-independent registration pointer is `~/Library/Application Support/Orchard/registration.json`. Its `state_dir` may still refer to an older `Private100KCandidate7` or confirmed `Private300KCandidate11` directory. Removing an old application does not make that state disposable.

If you intentionally want to erase all monitoring records: stop and quit every Orchard using that registration, preserve any baseline/pending/history evidence you need, identify the actual selected state directory, then remove only that registration and state. This discards unreviewed changes and approval history. If unsure, retain the files and contact [support](SUPPORT.md). Do not delete an older namespace wholesale while another version still references it. No login item or automatic update is enabled by build12.

監視停止・正常終了後、不要なアプリだけを削除できます。登録データを消す場合は、未確認変更と承認履歴が失われることを確認し、実際の参照先だけを対象にします。プロジェクトは削除しません。[データの削除要請・撤回](SUPPORT.md)。
