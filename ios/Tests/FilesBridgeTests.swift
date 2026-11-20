import XCTest
@testable import Cairn

final class FilesBridgeTests: XCTestCase {
    private var dir: URL {
        let t = FileManager.default.temporaryDirectory.appendingPathComponent("fb-\(UUID().uuidString)", isDirectory: true)
        return t
    }

    func testSanitizeRejectsTraversal() {
        XCTAssertNil(FilesBridge.sanitize(""))
        XCTAssertNil(FilesBridge.sanitize("../secret"))
        XCTAssertNil(FilesBridge.sanitize("a..b/../c"))
        XCTAssertNil(FilesBridge.sanitize("a/b.zip"))
        XCTAssertNil(FilesBridge.sanitize(".hidden"))
        XCTAssertEqual(FilesBridge.sanitize("normal.zip"), "normal.zip")
        XCTAssertEqual(FilesBridge.sanitize("UUID-export ORIGINAL_IPA_CONTENTS.zip"), "UUID-export ORIGINAL_IPA_CONTENTS.zip")
    }

    func testListExportsReturnsFilesSortedByName() throws {
        let d = dir
        try FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: d.appendingPathComponent("b.zip").path, contents: Data("222".utf8))
        FileManager.default.createFile(atPath: d.appendingPathComponent("a.txt").path, contents: Data("1".utf8))
        defer { try? FileManager.default.removeItem(at: d) }

        let files = FilesBridge.listExports(in: d)
        XCTAssertEqual(files.count, 2)
        XCTAssertEqual(files.first?["name"] as? String, "a.txt")
        XCTAssertEqual(files.last?["name"] as? String, "b.zip")
        XCTAssertEqual(files.last?["size"] as? Int, 3)
        XCTAssertTrue((files.last?["modified"] as? Double ?? 0) > 0)
    }

    func testListExportsIgnoresDirectories() throws {
        let d = dir
        try FileManager.default.createDirectory(at: d.appendingPathComponent("sub", isDirectory: true), withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: d) }
        XCTAssertEqual(FilesBridge.listExports(in: d).count, 0)
    }

    func testExportSessionPersistsInExportsByDefault() throws {
        // Default destination must be Documents/Exports (Files-app visible), not tmp.
        let session = ExportSession(name: "persist.zip", expectedSize: 2)
        try session.begin()
        try session.append(data: Data("ok".utf8))
        let url = try session.finish()
        defer { try? FileManager.default.removeItem(at: url) }
        XCTAssertEqual(url.deletingLastPathComponent().lastPathComponent, "Exports")
        XCTAssertTrue(url.deletingLastPathComponent().path.contains("Documents"))
        XCTAssertEqual(try Data(contentsOf: url), Data("ok".utf8))
    }
}
