// Read-only three-garden projection. Synthetic result fixtures never enter actual gardens.
import Foundation

enum GardenClassB: String, Codable, CaseIterable {
    case avoidOpen = "AVOID_OPEN", unknown = "UNKNOWN", noKnownBlocker = "NO_KNOWN_BLOCKER"
    var name: String {
        switch self { case .avoidOpen: return "毒林檎園"; case .unknown: return "アンノウン"; case .noKnownBlocker: return "林檎園" }
    }
}
struct GardenBucketB: Encodable {
    var code: GardenClassB
    var name: String
    var actualResultJobIDs: [UUID]
    var fixtureResultJobIDs: [UUID]
}
struct GardensViewB: Encodable {
    var buckets: [GardenBucketB]
    var unclassifiedJobIDs: [UUID]
    var evidenceScope: String
    var fixtureRows: [QualifiedGardenFixtureB]
    var rejectedBindings: [String]
    let actualInspectionConnected = false
}
func actualGardensViewB(_ jobs: [RecordJobB]) -> GardensViewB {
    GardensViewB(buckets: GardenClassB.allCases.map {
        GardenBucketB(code: $0, name: $0.name, actualResultJobIDs: [], fixtureResultJobIDs: [])
    }, unclassifiedJobIDs: jobs.map(\.jobID), evidenceScope: "A_C_DISCONNECTED_NO_ACTUAL_RESULT", fixtureRows: [], rejectedBindings: [])
}

enum GardenFixtureCompletionB: String, Codable { case qualifiedResultFixture, waiting, interrupted, counterFinished }
struct GardenBindingIdentityB: Codable, Equatable {
    var jobID: UUID
    var ownerID: UUID
    var storeID: UUID
    var jobRevision: Int
    var artifactSHA256: String
    var artifactIdentityDigest: String
    var queueJobSnapshotDigest: String
    var inspectionSessionID: UUID
}
struct GardenResultFixtureB: Codable {
    var binding: GardenBindingIdentityB
    var code: GardenClassB
    var completion: GardenFixtureCompletionB
    var provenance: String
    var sourceSHA256: String
    var coverage: [String]
    var reasons: [String]
    var limitations: [String]
}
struct ExpectedGardenFixtureB {
    var binding: GardenBindingIdentityB
    var pinnedEnvelopeSHA256: String
    var provenance: String
    var sourceSHA256: String
    var coverage: [String]
    var reasons: [String]
    var limitations: [String]
}
struct QualifiedGardenFixtureB: Encodable {
    let result: GardenResultFixtureB
    let evidenceScope = "SYNTHETIC_C_RESULT_FIXTURE_NOT_ACTUAL_INSPECTION"
    let actualResult = false
}
enum GardenFaultB: String, Error { case binding, provenance, coverage, completion, changedArtifact }

// expected is an independently pinned fixture producer record, never a claim from raw input.
func qualifyGardenFixtureB(_ result: GardenResultFixtureB, expected: ExpectedGardenFixtureB,
                           presentJob: RecordJobB, verifyPresentArtifact: () throws -> Void) throws -> QualifiedGardenFixtureB {
    guard result.completion == .qualifiedResultFixture else { throw GardenFaultB.completion }
    guard let a = presentJob.artifact, result.binding == expected.binding,
          result.binding.jobID == presentJob.jobID, result.binding.ownerID == presentJob.ownerID,
          result.binding.storeID == presentJob.storeID, result.binding.jobRevision == presentJob.revision,
          result.binding.artifactSHA256 == a.sha256,
          result.binding.artifactIdentityDigest == hash54(try canonicalJobB(a)),
          result.binding.queueJobSnapshotDigest == hash54(try canonicalJobB(presentJob)) else { throw GardenFaultB.binding }
    guard result.provenance == expected.provenance, !result.provenance.isEmpty,
          result.sourceSHA256 == expected.sourceSHA256, result.sourceSHA256.count == 64,
          result.sourceSHA256.allSatisfy({ $0.isHexDigit && !$0.isUppercase }) else { throw GardenFaultB.provenance }
    for field in [result.coverage, result.reasons, result.limitations] {
        guard !field.isEmpty, field.count <= 16, field.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 }) else { throw GardenFaultB.coverage }
    }
    guard result.coverage == expected.coverage, result.reasons == expected.reasons,
          result.limitations == expected.limitations,
          hash54(try canonicalJobB(result)) == expected.pinnedEnvelopeSHA256 else { throw GardenFaultB.coverage }
    do { try verifyPresentArtifact() } catch { throw GardenFaultB.changedArtifact }
    return QualifiedGardenFixtureB(result: result)
}
func renderFixtureGardensB(_ results: [GardenResultFixtureB], expected: [UUID: ExpectedGardenFixtureB],
                           presentJobs: [RecordJobB], verify: (RecordJobB) throws -> Void) -> GardensViewB {
    var qualified = [QualifiedGardenFixtureB](), rejected = [String](), seen = Set<UUID>()
    for result in results {
        do {
            guard seen.insert(result.binding.jobID).inserted,
                  let pin = expected[result.binding.jobID],
                  let job = presentJobs.first(where: { $0.jobID == result.binding.jobID }) else { throw GardenFaultB.binding }
            qualified.append(try qualifyGardenFixtureB(result, expected: pin, presentJob: job) { try verify(job) })
        } catch { rejected.append(String(describing: error)) }
    }
    return GardensViewB(buckets: GardenClassB.allCases.map { code in
        GardenBucketB(code: code, name: code.name, actualResultJobIDs: [],
            fixtureResultJobIDs: qualified.filter { $0.result.code == code }.map { $0.result.binding.jobID })
    }, unclassifiedJobIDs: [], evidenceScope: "SYNTHETIC_C_RESULT_FIXTURE_ONLY_NO_ACTUAL_CLASSIFICATION",
       fixtureRows: qualified, rejectedBindings: rejected)
}

struct GardenReadOnlyScreenB: Encodable {
    var headings: [String]
    var lines: [String]
    var view: GardensViewB
    init(_ view: GardensViewB) {
        self.view = view; headings = view.buckets.map(\.name)
        lines = [view.fixtureRows.isEmpty ? "A/C未接続・実検査結果はありません" : "合成C結果fixture・実検査結果ではありません"]
        for row in view.fixtureRows {
            lines.append(row.result.code.name)
            lines.append("理由: " + row.result.reasons.joined(separator: " / "))
            lines.append("確認範囲: " + row.result.coverage.joined(separator: " / "))
            lines.append("限界: " + row.result.limitations.joined(separator: " / "))
            lines.append("出所: " + row.result.provenance)
        }
        if !view.unclassifiedJobIDs.isEmpty { lines.append("未分類ジョブ: \(view.unclassifiedJobIDs.count)") }
    }
}
