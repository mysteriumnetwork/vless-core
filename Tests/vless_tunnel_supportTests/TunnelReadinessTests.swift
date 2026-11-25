import XCTest
import XRay

@testable import vless_tunnel_support

/// The waiting around the probe, with a probe the test controls.
final class TunnelReadinessTests: XCTestCase {

    private struct Refused: LocalizedError {
        var errorDescription: String? { "the server refused us" }
    }

    func testAProbeThatPassesIsReady() {
        let outcome = TunnelReadiness.check(isCancelled: { false }) {}

        XCTAssertEqual(outcome, .ready)
    }

    /// The reason is the only thing that says why a connect failed, so it has
    /// to survive the trip.
    func testAProbeThatFailsSaysWhy() {
        let outcome = TunnelReadiness.check(isCancelled: { false }) { throw Refused() }

        XCTAssertEqual(outcome, .failed("the server refused us"))
    }

    /// A stop that arrived before the start reached the probe.
    func testNothingIsProbedOnceAStopHasBeenAskedFor() {
        let probed = expectation(description: "probe ran")
        probed.isInverted = true

        let outcome = TunnelReadiness.check(isCancelled: { true }) { probed.fulfill() }

        XCTAssertEqual(outcome, .cancelled)
        wait(for: [probed], timeout: 0.2)
    }

    /// The point of running the probe on a thread of its own: it blocks for
    /// seconds and cannot be interrupted, and a disconnect must not wait.
    func testAStopDoesNotWaitForTheProbeToFinish() {
        let stop = StopSignal()
        let release = DispatchSemaphore(value: 0)
        let entered = DispatchSemaphore(value: 0)
        let finished = expectation(description: "probe returned")

        DispatchQueue.global().async {
            entered.wait()
            stop.raise()
        }

        let began = Date()
        let outcome = TunnelReadiness.check(isCancelled: { stop.isRaised }) {
            entered.signal()
            release.wait()
            finished.fulfill()
        }

        XCTAssertEqual(outcome, .cancelled)
        XCTAssertLessThan(Date().timeIntervalSince(began), 1, "waited on a probe that was called off")

        // Let the abandoned probe go, and see that it ends without incident.
        release.signal()
        wait(for: [finished], timeout: 2)
    }

    /// The wait is polled, and a probe that has finished must not be held up
    /// until the next poll comes round.
    func testAFinishedProbeIsNotKeptWaiting() {
        let began = Date()
        let outcome = TunnelReadiness.check(pollInterval: 5, isCancelled: { false }) {}

        XCTAssertEqual(outcome, .ready)
        XCTAssertLessThan(Date().timeIntervalSince(began), 1)
    }

    func testAStopSignalIsLoweredForTheNextStart() {
        let stop = StopSignal()
        XCTAssertFalse(stop.isRaised)

        stop.raise()
        XCTAssertTrue(stop.isRaised)

        stop.reset()
        XCTAssertFalse(stop.isRaised)
    }
}

/// The probe itself, against the real core. No tunnel and no network: the
/// server these configs name is on this machine, and is not there.
final class ExitProbeTests: XCTestCase {

    override func tearDown() {
        XRayStop()
        super.tearDown()
    }

    /// The config the Dart layer emits, pointed at [address]:[port].
    ///
    /// The routing rule is the part that matters here. It is scoped to the
    /// SOCKS inbound, so Xray's own lookups miss it and go out through the
    /// proxy. Unscoped, they would be answered by a direct query from this
    /// machine, and a probe would pass with no server behind it at all.
    private func config(address: String, port: Int) throws -> Data {
        let dart = """
        {
          "log": {"loglevel": "warning", "access": "none"},
          "dns": {"servers": ["1.1.1.1", "1.0.0.1"], "queryStrategy": "UseIPv4"},
          "inbounds": [{
            "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": 0,
            "settings": {"auth": "password", "accounts": [], "udp": true}
          }],
          "outbounds": [
            {
              "tag": "proxy", "protocol": "vless",
              "settings": {"vnext": [{
                "address": "\(address)", "port": \(port),
                "users": [{"id": "f7422437-7044-4599-8165-5f7ae7311fc4", "encryption": "none"}]
              }]},
              "streamSettings": {
                "network": "ws", "security": "tls",
                "tlsSettings": {"serverName": "exit.invalid", "alpn": ["http/1.1"]},
                "wsSettings": {"path": "/vless", "host": "exit.invalid"}
              }
            },
            {"tag": "dns-out", "protocol": "dns", "settings": {"nonIPQuery": "reject"}}
          ],
          "routing": {"rules": [{
            "type": "field", "inboundTag": ["socks-in"], "port": 53, "outboundTag": "dns-out"
          }]}
        }
        """
        return try TunnelXrayConfigPreparer.prepare(Data(dart.utf8)).config
    }

    private func start(address: String, port: Int) throws {
        var error: NSError?
        XRayStart(try config(address: address, port: port), &error)
        if let error { throw error }
    }

    /// What a server that is down looks like from here, and the whole reason
    /// for the probe: Xray starts on this config without complaint.
    func testAServerThatIsNotThereFailsTheProbe() throws {
        // Nothing listens on the discard port.
        try start(address: "127.0.0.1", port: 9)

        let outcome = TunnelReadiness.check(isCancelled: { false }) {
            try ExitProbe.run(timeoutMs: 3000)
        }

        guard case let .failed(reason) = outcome else {
            return XCTFail("a tunnel with no server behind it was reported as \(outcome)")
        }
        XCTAssertFalse(reason.isEmpty)
    }

    func testTheProbeFailsWhenNothingIsRunning() {
        let outcome = TunnelReadiness.check(isCancelled: { false }) {
            try ExitProbe.run(timeoutMs: 1000)
        }

        XCTAssertEqual(outcome, .failed("xray is not running"))
    }

    /// A stop while the real probe is still waiting on a server that never
    /// answers. The probe is left to run out on its own.
    func testAStopCutsARealProbeShort() throws {
        // TEST-NET-1: reserved, so the dial goes nowhere and nothing refuses it.
        try start(address: "192.0.2.1", port: 443)

        let stop = StopSignal()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { stop.raise() }

        let began = Date()
        let outcome = TunnelReadiness.check(isCancelled: { stop.isRaised }) {
            try ExitProbe.run(timeoutMs: 4000)
        }

        XCTAssertEqual(outcome, .cancelled)
        XCTAssertLessThan(Date().timeIntervalSince(began), 2, "the stop waited on the probe")
    }
}
