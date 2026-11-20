import XCTest
@testable import Cairn

final class SaveBridgeTests: XCTestCase {

    private func makeTempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cairn-tests-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testAppendDataAndFinishProducesIdenticalBytes() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "test.zip", expectedSize: 11, tmpDir: dir)
        try session.begin()
        try session.append(data: Data("hello ".utf8))
        try session.append(data: Data("world".utf8))
        let url = try session.finish()
        let bytes = try Data(contentsOf: url)
        XCTAssertEqual(bytes, Data("hello world".utf8))
        XCTAssertEqual(session.received, 11)
        XCTAssertEqual(session.fileURL, url)
        try? FileManager.default.removeItem(at: dir)
    }

    func testAppendBase64() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "b64.zip", expectedSize: 5, tmpDir: dir)
        try session.begin()
        try session.append(base64: "aGVsbG8=") // "hello"
        let url = try session.finish()
        XCTAssertEqual(try Data(contentsOf: url), Data("hello".utf8))
        try? FileManager.default.removeItem(at: dir)
    }

    func testBase64WithWhitespaceDecodes() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "b64b.zip", expectedSize: 5, tmpDir: dir)
        try session.begin()
        try session.append(base64: "aGVs\nbG8=") // line-wrapped base64
        let url = try session.finish()
        XCTAssertEqual(try Data(contentsOf: url), Data("hello".utf8))
        try? FileManager.default.removeItem(at: dir)
    }

    func testSizeMismatchThrowsAndCleansUp() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "bad.zip", expectedSize: 100, tmpDir: dir)
        try session.begin()
        try session.append(data: Data("short".utf8))
        XCTAssertThrowsError(try session.finish())
        XCTAssertNil(session.fileURL)
        // no stray files left in the temp dir
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertTrue(leftovers.isEmpty)
        try? FileManager.default.removeItem(at: dir)
    }

    func testAbortDeletesTempFile() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "abort.zip", expectedSize: 0, tmpDir: dir)
        try session.begin()
        guard let url = session.fileURL else {
            return XCTFail("fileURL should exist after begin")
        }
        try session.append(data: Data("partial".utf8))
        session.abort()
        XCTAssertNil(session.fileURL)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        try? FileManager.default.removeItem(at: dir)
    }

    func testChunkBeforeBeginThrows() {
        let session = ExportSession(name: "x.zip", expectedSize: 0)
        XCTAssertThrowsError(try session.append(data: Data([1, 2, 3])))
    }

    func testFinishBeforeBeginThrows() {
        let session = ExportSession(name: "y.zip", expectedSize: 0)
        XCTAssertThrowsError(try session.finish())
    }

    func testZeroSizeExportFinishesCleanly() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "empty.zip", expectedSize: 0, tmpDir: dir)
        try session.begin()
        let url = try session.finish()
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual((attrs[.size] as? NSNumber)?.int64Value, 0)
        try? FileManager.default.removeItem(at: dir)
    }

    func testSanitizedNamesCannotEscape() throws {
        let dir = makeTempDir()
        let session = ExportSession(name: "../../evil/name.zip", expectedSize: 0, tmpDir: dir)
        try session.begin()
        guard let url = session.fileURL else { return XCTFail("no file URL") }
        XCTAssertTrue(url.path.hasPrefix(dir.path), "temp file must stay inside the export dir")
        XCTAssertFalse(url.path.contains(".."))
        try session.abort()
        try? FileManager.default.removeItem(at: dir)
    }
}
