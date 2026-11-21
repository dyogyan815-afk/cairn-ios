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

    // MARK: - Message-protocol regression tests (the on-device failures)
    //
    // v1.2.1 shipped JS that posted chunks WITHOUT the "name" field; the native
    // side then looked them up under the "export.zip" default, every transfer
    // failed ("No active session for export.zip") and no chunk was ever ACKed
    // ("the app did not confirm chunk 0"). These tests drive SaveBridge.handle
    // with exactly the messages the injected JS sends.

    func testMessageFlowChunksWithoutNameFallBackToSingleSession() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        bridge.handle(["kind": "begin", "name": "ORIGINAL_IPA_CONTENTS.zip", "size": 11])
        XCTAssertEqual(bridge.sessionCount(), 1)
        // Chunks with NO name — the exact bug that failed on device.
        bridge.handle(["kind": "chunk", "index": 0, "data": Data("hello ".utf8).base64EncodedString()])
        bridge.handle(["kind": "chunk", "index": 1, "data": Data("world".utf8).base64EncodedString()])
        XCTAssertEqual(bridge.sessionCount(), 1, "chunks must not kill the session")
        bridge.handle(["kind": "finish", "name": "ORIGINAL_IPA_CONTENTS.zip"])
        XCTAssertEqual(bridge.sessionCount(), 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertEqual(files.count, 1, "exactly one export file expected, got \(files)")
        let data = try Data(contentsOf: dir.appendingPathComponent(files[0]))
        XCTAssertEqual(data, Data("hello world".utf8))
        try? FileManager.default.removeItem(at: dir)
    }

    func testMessageFlowChunksWithExplicitName() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        bridge.handle(["kind": "begin", "name": "a.zip", "size": 5])
        bridge.handle(["kind": "chunk", "name": "a.zip", "index": 0, "data": Data("hello".utf8).base64EncodedString()])
        bridge.handle(["kind": "finish", "name": "a.zip"])
        XCTAssertEqual(bridge.sessionCount(), 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertEqual(files.count, 1)
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent(files[0])), Data("hello".utf8))
        try? FileManager.default.removeItem(at: dir)
    }

    func testMessageFlowChunkWithoutNameAndNoSessionIsRejected() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        // No begin: a nameless chunk has nothing to fall back to.
        bridge.handle(["kind": "chunk", "index": 0, "data": Data("x".utf8).base64EncodedString()])
        XCTAssertEqual(bridge.sessionCount(), 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertTrue(files.isEmpty, "nothing may be written without a session")
        try? FileManager.default.removeItem(at: dir)
    }

    func testMessageFlowBeginReplacesStaleSessionOfSameName() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        bridge.handle(["kind": "begin", "name": "retry.zip", "size": 3])
        bridge.handle(["kind": "chunk", "name": "retry.zip", "index": 0, "data": Data("OLDOLDOLD".utf8).base64EncodedString()])
        // User retries the same export: the stale attempt must be dropped.
        bridge.handle(["kind": "begin", "name": "retry.zip", "size": 3])
        XCTAssertEqual(bridge.sessionCount(), 1, "the retry must replace, not pile up")
        bridge.handle(["kind": "chunk", "name": "retry.zip", "index": 0, "data": Data("new".utf8).base64EncodedString()])
        bridge.handle(["kind": "finish", "name": "retry.zip"])
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertEqual(files.count, 1, "the aborted attempt must leave no temp file behind, got \(files)")
        XCTAssertEqual(try Data(contentsOf: dir.appendingPathComponent(files[0])), Data("new".utf8))
        try? FileManager.default.removeItem(at: dir)
    }

    func testMessageFlowFinishWithWrongSizeCleansUp() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        bridge.handle(["kind": "begin", "name": "short.zip", "size": 100])
        bridge.handle(["kind": "chunk", "name": "short.zip", "index": 0, "data": Data("5byte".utf8).base64EncodedString()])
        bridge.handle(["kind": "finish", "name": "short.zip"])
        XCTAssertEqual(bridge.sessionCount(), 0, "failed finish must remove the session")
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertTrue(files.isEmpty, "failed finish must delete the partial file")
        try? FileManager.default.removeItem(at: dir)
    }

    func testMessageFlowAbortRemovesSessionAndFile() throws {
        let dir = makeTempDir()
        let bridge = SaveBridge(sessionDir: dir)
        bridge.handle(["kind": "begin", "name": "gone.zip", "size": 10])
        bridge.handle(["kind": "chunk", "name": "gone.zip", "index": 0, "data": Data("partial".utf8).base64EncodedString()])
        bridge.handle(["kind": "abort", "name": "gone.zip"])
        XCTAssertEqual(bridge.sessionCount(), 0)
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        XCTAssertTrue(files.isEmpty)
        try? FileManager.default.removeItem(at: dir)
    }
}
