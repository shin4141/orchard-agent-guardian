import Darwin
import Foundation
import SQLite3

enum OrchardLocalReportFault: Error {
    case identity, database, binding, day
}

struct OrchardLocalReportReceipt: Encodable {
    let recordID: String
    let detectionID: UUID
    let inspectionReceiptSHA256: String
    let payload: ReportPayloadBC
    let inspectedAt: Int64
    let approvedAt: Int64
    let receivedAt: Int64
    let duplicate: Bool
    let state = "UNVERIFIED"
}

struct OrchardLocalReportStore {
    let directory: URL

    static var userLocal: Self {
        let library = FileManager.default.homeDirectoryForCurrentUser
        return Self(directory: library.appendingPathComponent("Library/Application Support/Orchard Local Reports", isDirectory: true))
    }

    // The B8 payload stays unchanged. The real ledger has its own namespace,
    // omits the fixture reporter ID, and never qualifies a SHA as known danger.
    private static let applicationID: Int32 = 0x4F524C31
    private static let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    private enum Value {
        case text(String)
        case integer(Int64)
    }

    private func identity(_ url: URL) throws -> stat? {
        var info = stat()
        if lstat(url.path, &info) == 0 { return info }
        guard errno == ENOENT else { throw OrchardLocalReportFault.identity }
        return nil
    }

    private func privatePath(create: Bool) throws -> (URL, stat)? {
        let folder = directory.standardizedFileURL
        guard folder.isFileURL, folder.resolvingSymlinksInPath() == folder else {
            throw OrchardLocalReportFault.identity
        }
        if try identity(folder) == nil {
            guard create else { return nil }
            guard mkdir(folder.path, 0o700) == 0 || errno == EEXIST else { throw OrchardLocalReportFault.identity }
        }
        guard let folderInfo = try identity(folder), folderInfo.st_mode & S_IFMT == S_IFDIR,
              folderInfo.st_uid == geteuid(), folderInfo.st_mode & 0o777 == 0o700 else {
            throw OrchardLocalReportFault.identity
        }
        let url = folder.appendingPathComponent("unverified.sqlite")
        if try identity(url) == nil {
            guard create else { return nil }
            let fd = open(url.path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if fd >= 0 { close(fd) }
            else if errno != EEXIST { throw OrchardLocalReportFault.identity }
        }
        guard let info = try identity(url), info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_nlink == 1, info.st_mode & 0o777 == 0o600 else {
            throw OrchardLocalReportFault.identity
        }
        return (url, info)
    }

    private func withDatabase<T>(write: Bool, _ action: (OpaquePointer) throws -> T) throws -> T? {
        guard let (url, before) = try privatePath(create: write) else { return nil }
        var connection: OpaquePointer?
        let flags = (write ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY) | SQLITE_OPEN_NOFOLLOW | SQLITE_OPEN_FULLMUTEX
        let status = sqlite3_open_v2(url.path, &connection, flags, nil)
        defer { if let connection { sqlite3_close(connection) } }
        guard status == SQLITE_OK, let db = connection,
              let after = try identity(url), before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              sqlite3_busy_timeout(db, 250) == SQLITE_OK else { throw OrchardLocalReportFault.database }
        try exec(db, "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;")
        if write { try exec(db, "PRAGMA synchronous=FULL; BEGIN IMMEDIATE;") }
        else { try exec(db, "PRAGMA query_only=ON; BEGIN;") }
        var committed = false
        defer { if !committed { try? exec(db, "ROLLBACK;") } }
        try checkSchema(db, mayCreate: write)
        let result = try action(db)
        guard let final = try identity(url), before.st_dev == final.st_dev, before.st_ino == final.st_ino else {
            throw OrchardLocalReportFault.identity
        }
        try exec(db, "COMMIT;")
        committed = true
        return result
    }

    private func exec(_ db: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw OrchardLocalReportFault.database }
    }

    private func statement<T>(_ db: OpaquePointer, _ sql: String, _ values: [Value] = [],
                              _ read: (OpaquePointer) throws -> T) throws -> T {
        var raw: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &raw, nil) == SQLITE_OK, let stmt = raw else {
            if let raw { sqlite3_finalize(raw) }
            throw OrchardLocalReportFault.database
        }
        defer { sqlite3_finalize(stmt) }
        for (offset, value) in values.enumerated() {
            let index = Int32(offset + 1)
            let status: Int32
            switch value {
            case .text(let text): status = sqlite3_bind_text(stmt, index, text, -1, Self.transient)
            case .integer(let number): status = sqlite3_bind_int64(stmt, index, number)
            }
            guard status == SQLITE_OK else { throw OrchardLocalReportFault.database }
        }
        return try read(stmt)
    }

    private func scalar(_ db: OpaquePointer, _ sql: String, _ values: [Value] = []) throws -> Int64 {
        try statement(db, sql, values) { stmt in
            guard sqlite3_step(stmt) == SQLITE_ROW else { throw OrchardLocalReportFault.database }
            let value = sqlite3_column_int64(stmt, 0)
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw OrchardLocalReportFault.database }
            return value
        }
    }

    private func insert(_ db: OpaquePointer, _ sql: String, _ values: [Value]) throws {
        try statement(db, sql, values) { stmt in
            guard sqlite3_step(stmt) == SQLITE_DONE else { throw OrchardLocalReportFault.database }
        }
    }

    private func checkSchema(_ db: OpaquePointer, mayCreate: Bool) throws {
        let id = try scalar(db, "PRAGMA application_id")
        let version = try scalar(db, "PRAGMA user_version")
        let objectCount = "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"
        if id == 0, version == 0, mayCreate, try scalar(db, objectCount) == 0 {
            try exec(db, """
            CREATE TABLE reports (
              id TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL, received_at INTEGER NOT NULL,
              state TEXT NOT NULL CHECK(state = 'UNVERIFIED')
            ) WITHOUT ROWID;
            CREATE TABLE approved_detections (
              detection_id TEXT PRIMARY KEY NOT NULL, report_id TEXT NOT NULL REFERENCES reports(id),
              receipt_sha256 TEXT NOT NULL, inspected_at INTEGER NOT NULL, approved_at INTEGER NOT NULL,
              duplicate INTEGER NOT NULL CHECK(duplicate IN (0, 1))
            ) WITHOUT ROWID;
            PRAGMA application_id = \(Self.applicationID);
            PRAGMA user_version = 1;
            """)
        } else {
            guard id == Self.applicationID, version == 1, try scalar(db, objectCount) == 2,
                  try scalar(db, """
                    SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('reports','approved_detections')
                    """) == 2 else { throw OrchardLocalReportFault.database }
        }
    }

    private func payloadBytes(_ payload: ReportPayloadBC) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(payload)
    }

    private func storedReport(_ db: OpaquePointer, id: String, payload: Data) throws -> Int64? {
        try statement(db, "SELECT payload, received_at, state FROM reports WHERE id=?1", [.text(id)]) { query in
            let step = sqlite3_step(query)
            if step == SQLITE_DONE { return nil }
            guard step == SQLITE_ROW, let raw = sqlite3_column_text(query, 0),
                  Data(String(cString: raw).utf8) == payload,
                  let state = sqlite3_column_text(query, 2), String(cString: state) == "UNVERIFIED" else {
                throw OrchardLocalReportFault.binding
            }
            let received = sqlite3_column_int64(query, 1)
            guard sqlite3_step(query) == SQLITE_DONE else { throw OrchardLocalReportFault.database }
            return received
        }
    }

    private func storedDetection(_ db: OpaquePointer, approval: OrchardLocalReportApproval,
                                 reportID: String, payload: Data) throws -> OrchardLocalReportReceipt? {
        let detectionID = approval.detectionID.uuidString.lowercased()
        return try statement(db, """
            SELECT report_id, receipt_sha256, inspected_at, approved_at, duplicate
            FROM approved_detections WHERE detection_id=?1
            """, [.text(detectionID)]) { query in
            let step = sqlite3_step(query)
            if step == SQLITE_DONE { return nil }
            guard step == SQLITE_ROW,
                  let id = sqlite3_column_text(query, 0), String(cString: id) == reportID,
                  let receipt = sqlite3_column_text(query, 1), String(cString: receipt) == approval.inspectionReceiptSHA256,
                  sqlite3_column_int64(query, 2) == approval.inspectedAt,
                  sqlite3_column_int64(query, 3) == approval.approvedAt else { throw OrchardLocalReportFault.binding }
            let duplicate = sqlite3_column_int(query, 4)
            guard (0...1).contains(duplicate), sqlite3_step(query) == SQLITE_DONE,
                  let received = try storedReport(db, id: reportID, payload: payload) else {
                throw OrchardLocalReportFault.binding
            }
            return OrchardLocalReportReceipt(recordID: reportID, detectionID: approval.detectionID,
                inspectionReceiptSHA256: approval.inspectionReceiptSHA256, payload: approval.payload,
                inspectedAt: approval.inspectedAt, approvedAt: approval.approvedAt,
                receivedAt: received, duplicate: duplicate == 1)
        }
    }

    func accept(_ approval: OrchardLocalReportApproval) throws -> OrchardLocalReportReceipt {
        let bytes = try payloadBytes(approval.payload)
        let id = "report:" + hash54(bytes)
        guard let result = try withDatabase(write: true, { db in
            if let existing = try storedDetection(db, approval: approval, reportID: id, payload: bytes) {
                return existing
            }
            let previous = try storedReport(db, id: id, payload: bytes)
            if previous == nil {
                try insert(db, "INSERT INTO reports VALUES (?1,?2,?3,'UNVERIFIED')",
                           [.text(id), .text(String(decoding: bytes, as: UTF8.self)), .integer(approval.approvedAt)])
            }
            try insert(db, "INSERT INTO approved_detections VALUES (?1,?2,?3,?4,?5,?6)",
                [.text(approval.detectionID.uuidString.lowercased()), .text(id), .text(approval.inspectionReceiptSHA256),
                 .integer(approval.inspectedAt), .integer(approval.approvedAt), .integer(previous == nil ? 0 : 1)])
            guard let receipt = try storedDetection(db, approval: approval, reportID: id, payload: bytes) else {
                throw OrchardLocalReportFault.binding
            }
            return receipt
        }) else { throw OrchardLocalReportFault.database }
        return result
    }

    func reconcile(_ approval: OrchardLocalReportApproval) throws -> OrchardLocalReportReceipt? {
        let bytes = try payloadBytes(approval.payload)
        let id = "report:" + hash54(bytes)
        return try withDatabase(write: false) { db in
            try storedDetection(db, approval: approval, reportID: id, payload: bytes)
        } ?? nil
    }

    func dailyReadme(_ day: String) throws -> String {
        let clock = DateFormatter()
        clock.locale = Locale(identifier: "en_US_POSIX")
        var calendar = Calendar(identifier: .gregorian)
        guard let zone = TimeZone(identifier: "Asia/Tokyo") else { throw OrchardLocalReportFault.day }
        calendar.timeZone = zone
        clock.calendar = calendar
        clock.timeZone = zone
        clock.dateFormat = "yyyy-MM-dd"
        clock.isLenient = false
        guard let start = clock.date(from: day), clock.string(from: start) == day,
              let end = calendar.date(byAdding: .day, value: 1, to: start) else { throw OrchardLocalReportFault.day }
        let range: [Value] = [.integer(Int64(start.timeIntervalSince1970)), .integer(Int64(end.timeIntervalSince1970))]
        let counts = try withDatabase(write: false) { db in
            (try scalar(db, "SELECT count(*) FROM approved_detections WHERE inspected_at>=?1 AND inspected_at<?2", range),
             try scalar(db, "SELECT count(*) FROM reports WHERE received_at>=?1 AND received_at<?2 AND state='UNVERIFIED'", range))
        }
        let detected = counts.map { String($0.0) } ?? "—"
        let reported = counts.map { String($0.1) } ?? "—"
        return """
            ### Orchard ローカル通報の日次集計

            | 日付（JST） | 検出 | 通報 | 検証済み | 誤検知 | 再警告 |
            |---|---:|---:|---:|---:|---:|
            | \(day) | \(detected) | \(reported) | — | — | — |

            検出は明示承認に伴って記録した検査の件数です。通報は新規の未検証受付の件数で、重複は加算しません。
            「—」は受付台帳で集計できない項目です。独立審査・再警告の実績はこの台帳に含めません。
            """
    }
}
