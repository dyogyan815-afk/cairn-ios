import XCTest
@testable import Cairn

/// Contract tests for FetchBridge: the exact behaviour the injected
/// window.__cairnFetch (BridgeJS) relies on. The network layer is injected,
/// so no test touches the real network.
final class FetchBridgeTests: XCTestCase {

    private typealias Loader = FetchBridge.Loader

    private struct Captured {
        var js: String
        var detail: [String: Any]
    }

    /// Installs a responderOverride that parses the dispatched CustomEvent
    /// JSON into a dictionary (the same JSON the page receives).
    private func makeBridge(loader: @escaping Loader) -> (FetchBridge, () -> Captured?) {
        let bridge = FetchBridge(loader: loader)
        var last: Captured?
        bridge.responderOverride = { js in
            guard let range = js.range(of: "detail:") else { last = nil; return }
            var json = String(js[range.upperBound...])
            // detail:{...}))  → strip the closing "}))" of dispatchEvent(...)
            if json.hasSuffix("}))") { json = String(json.dropLast(3)) }
            let data = json.data(using: .utf8)!
            let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
            last = Captured(js: js, detail: obj)
        }
        return (bridge, { last })
    }

    func testRefusesNonHttpSchemes() {
        let (bridge, capture) = makeBridge { _, _, completion in
            XCTFail("loader must never be called for a non-http scheme")
            completion(.failure(NSError(domain: "test", code: 1)))
        }
        bridge.handle(["kind": "fetch", "req": 1, "url": "file:///etc/passwd"])
        let c = capture()
        XCTAssertEqual(c?.detail["ok"] as? Bool, false)
        let err = (c?.detail["error"] as? String) ?? ""
        XCTAssertTrue(err.contains("http"), "must explain the http(s)-only rule, got: \(err)")
    }

    func testRefusesCairnScheme() {
        let (bridge, capture) = makeBridge { _, _, completion in
            XCTFail("loader must never be called for the cairn scheme")
            completion(.failure(NSError(domain: "test", code: 1)))
        }
        bridge.handle(["kind": "fetch", "req": 2, "url": "cairn://app/index.html"])
        XCTAssertEqual(capture()?.detail["ok"] as? Bool, false)
    }

    func testInvalidURLReportsError() {
        let (bridge, capture) = makeBridge { _, _, _ in XCTFail("no call for an invalid URL") }
        bridge.handle(["kind": "fetch", "req": 3, "url": "not a url"])
        let c = capture()
        XCTAssertEqual(c?.detail["ok"] as? Bool, false)
        XCTAssertNotNil(c?.detail["error"])
        XCTAssertEqual(c?.detail["req"] as? Int, 3, "response must echo the request id")
    }

    func testSuccessDeliversBase64Payload() throws {
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 1, 2, 3, 4])
        let (bridge, capture) = makeBridge { request, maxBytes, completion in
            XCTAssertEqual(request.url?.absoluteString, "https://example.com/a.png")
            XCTAssertEqual(maxBytes, 1 << 20)
            let response = HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!
            completion(.success((png, response)))
        }
        bridge.handle(["kind": "fetch", "req": 7, "url": "https://example.com/a.png", "maxBytes": 1 << 20])
        let c = capture()
        XCTAssertEqual(c?.detail["ok"] as? Bool, true)
        XCTAssertEqual(c?.detail["req"] as? Int, 7)
        let data = Data(base64Encoded: (c?.detail["data"] as? String) ?? "")
        XCTAssertEqual(data, png, "payload must arrive as faithful base64")
        XCTAssertEqual(c?.detail["status"] as? Int, 200)
        XCTAssertEqual(c?.detail["finalUrl"] as? String, "https://example.com/a.png")
    }

    func testHTTPErrorIsReportedNotDelivered() {
        let (bridge, capture) = makeBridge { request, _, completion in
            let response = HTTPURLResponse(url: request.url!, statusCode: 404, httpVersion: nil, headerFields: nil)!
            completion(.success((Data("nope".utf8), response)))
        }
        bridge.handle(["kind": "fetch", "req": 4, "url": "https://example.com/missing.png"])
        let c = capture()
        XCTAssertEqual(c?.detail["ok"] as? Bool, false)
        let err = (c?.detail["error"] as? String) ?? ""
        XCTAssertTrue(err.contains("404"), "must surface the real HTTP status, got: \(err)")
        XCTAssertEqual(c?.detail["status"] as? Int, 404)
    }

    func testLoaderFailureSurfacesTheReason() {
        let (bridge, capture) = makeBridge { _, _, completion in
            completion(.failure(NSError(domain: NSURLErrorDomain, code: NSURLErrorTimedOut,
                                        userInfo: [NSLocalizedDescriptionKey: "request timed out"])))
        }
        bridge.handle(["kind": "fetch", "req": 5, "url": "https://example.com/slow.png"])
        let c = capture()
        XCTAssertEqual(c?.detail["ok"] as? Bool, false)
        XCTAssertEqual(c?.detail["error"] as? String, "request timed out")
    }
}
