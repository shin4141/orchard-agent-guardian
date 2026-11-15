# Rollback / 元の版へ戻す

Preserve pending monitoring evidence before changing versions. Stop only the intended Orchard app through its GUI and avoid simultaneous monitoring from multiple versions.
Use a previously approved distribution only when it is actually available from the trusted release source, with its checksum and license documents. Do not substitute an unknown archive.

This Release 1 package does not include a public previous-version download or automatic downgrade. Internal build9 is retained by the maintainer for rollback validation; it is not offered as a public download here.
The UI change does not migrate the database or monitoring registration. Deleting shared state is not required to return to a retained approved version.

版を変える前に未確認の証拠を保持し、対象アプリだけを正常終了します。公開済みの信頼できる旧版がある場合は、そのchecksumとライセンス文書を確認して使用してください。
旧版が公開されていない場合は、未知の配布物を探さず [問い合わせ](SUPPORT.md)へ進んでください。
[停止・削除](UNINSTALL.md)。
