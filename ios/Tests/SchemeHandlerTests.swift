import XCTest
@testable import Cairn

final class SchemeHandlerTests: XCTestCase {

    // MARK: MIME types

    func testMimeTypes() {
        XCTAssertEqual(SchemeHandler.mime(for: "js"), "text/javascript")
        XCTAssertEqual(SchemeHandler.mime(for: "mjs"), "text/javascript")
        XCTAssertEqual(SchemeHandler.mime(for: "css"), "text/css")
        XCTAssertEqual(SchemeHandler.mime(for: "html"), "text/html")
        XCTAssertEqual(SchemeHandler.mime(for: "svg"), "image/svg+xml")
        XCTAssertEqual(SchemeHandler.mime(for: "json"), "application/json")
        XCTAssertEqual(SchemeHandler.mime(for: "woff2"), "font/woff2")
        XCTAssertEqual(SchemeHandler.mime(for: "unknownext"), "application/octet-stream")
    }

    func testMimeIsCaseInsensitive() {
        XCTAssertEqual(SchemeHandler.mime(for: "JS"), "text/javascript")
        XCTAssertEqual(SchemeHandler.mime(for: "SVG"), "image/svg+xml")
    }

    // MARK: Path normalization

    func testNormalizeAppPath() {
        XCTAssertEqual(SchemeHandler.normalizeAppPath("/js/ui/app.js"), "js/ui/app.js")
        XCTAssertEqual(SchemeHandler.normalizeAppPath("js/ui/app.js"), "js/ui/app.js")
        XCTAssertEqual(SchemeHandler.normalizeAppPath(""), "index.html")
        XCTAssertEqual(SchemeHandler.normalizeAppPath("/"), "index.html")
        XCTAssertEqual(SchemeHandler.normalizeAppPath("/a//b///c"), "a/b/c")
        XCTAssertEqual(SchemeHandler.normalizeAppPath("/index.html"), "index.html")
    }

    // MARK: Path traversal rejection

    func testUnsafePathsRejected() {
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("a/../../b"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("../secret"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("a/.."))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("a\\b"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("%2e%2e/x"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("a/%2E%2e/b"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("/absolute"))
        XCTAssertTrue(SchemeHandler.isUnsafeAppPath("./local"))
    }

    func testSafePathsAccepted() {
        XCTAssertFalse(SchemeHandler.isUnsafeAppPath("index.html"))
        XCTAssertFalse(SchemeHandler.isUnsafeAppPath("js/core/ipa.js"))
        XCTAssertFalse(SchemeHandler.isUnsafeAppPath("css/app.css"))
        XCTAssertFalse(SchemeHandler.isUnsafeAppPath("assets/logo.v2.final.svg"))
    }

    // MARK: HTTP Range parsing

    private let size: Int64 = 1000

    func testRangeNilForMissingHeader() {
        XCTAssertNil(SchemeHandler.parseRange(nil, fileSize: size))
        XCTAssertNil(SchemeHandler.parseRange("", fileSize: size))
    }

    func testRangeFullClosed() {
        XCTAssertEqual(SchemeHandler.parseRange("bytes=0-99", fileSize: size)?.start, 0)
        XCTAssertEqual(SchemeHandler.parseRange("bytes=0-99", fileSize: size)?.end, 99)
        XCTAssertEqual(SchemeHandler.parseRange("bytes=100-999", fileSize: size)?.end, 999)
    }

    func testRangeClampedToEnd() {
        let r = SchemeHandler.parseRange("bytes=100-5000", fileSize: size)
        XCTAssertEqual(r?.start, 100)
        XCTAssertEqual(r?.end, 999)
    }

    func testRangeOpenEnded() {
        let r = SchemeHandler.parseRange("bytes=500-", fileSize: size)
        XCTAssertEqual(r?.start, 500)
        XCTAssertEqual(r?.end, 999)
    }

    func testRangeSuffix() {
        let r = SchemeHandler.parseRange("bytes=-100", fileSize: size)
        XCTAssertEqual(r?.start, 900)
        XCTAssertEqual(r?.end, 999)
    }

    func testRangeSuffixLargerThanFile() {
        let r = SchemeHandler.parseRange("bytes=-5000", fileSize: size)
        XCTAssertEqual(r?.start, 0)
        XCTAssertEqual(r?.end, 999)
    }

    func testRangeMalformed() {
        XCTAssertNil(SchemeHandler.parseRange("bytes=abc", fileSize: size))
        XCTAssertNil(SchemeHandler.parseRange("bytes=5-2", fileSize: size))
        XCTAssertNil(SchemeHandler.parseRange("bytes=1000-", fileSize: size))
        XCTAssertNil(SchemeHandler.parseRange("bytes=-", fileSize: size))
        XCTAssertNil(SchemeHandler.parseRange("items=0-1", fileSize: size))
    }

    func testRangeFirstOfMultipleUsed() {
        let r = SchemeHandler.parseRange("bytes=0-9,500-599", fileSize: size)
        XCTAssertEqual(r?.start, 0)
        XCTAssertEqual(r?.end, 9)
    }

    func testRangeCaseInsensitivePrefix() {
        XCTAssertEqual(SchemeHandler.parseRange("BYTES=0-1", fileSize: size)?.start, 0)
    }
}
