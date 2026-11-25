import Foundation
import XRay

/// Whether a tunnel that has come up may be reported as connected.
///
/// Up is not the same as working. Xray dials its server only when there is
/// something to carry, so a tunnel whose server is down, or refuses the
/// credentials, starts exactly like a healthy one and then drops everything.
/// The probe is what tells them apart, and this runs it without letting it
/// hold up a stop.
public enum TunnelReadiness {

    public enum Outcome: Equatable {
        case ready
        /// The probe ran and failed. Carries its own account of why.
        case failed(String)
        /// A stop arrived first. The probe may still be running; nothing waits
        /// for it.
        case cancelled
    }

    /// Runs `probe` on a thread of its own and waits for it, giving up as soon
    /// as `isCancelled` turns true.
    ///
    /// A thread rather than a call, because the probe blocks for as long as its
    /// own timeout and cannot be interrupted, and a disconnect during a connect
    /// must not wait that out.
    public static func check(
        pollInterval: TimeInterval = 0.05,
        isCancelled: @escaping () -> Bool,
        probe: @escaping () throws -> Void
    ) -> Outcome {
        if isCancelled() { return .cancelled }

        let result = ProbeResult()
        let finished = DispatchSemaphore(value: 0)
        Thread {
            do {
                try probe()
                result.set(.ready)
            } catch {
                result.set(.failed((error as NSError).localizedDescription))
            }
            finished.signal()
        }.start()

        while finished.wait(timeout: .now() + pollInterval) == .timedOut {
            if isCancelled() { return .cancelled }
        }
        return result.get()
    }

    /// Written once by the probe's thread, read once by the waiter.
    private final class ProbeResult: @unchecked Sendable {
        private let lock = NSLock()
        private var outcome = Outcome.failed("the probe never finished")

        func set(_ value: Outcome) {
            lock.lock()
            outcome = value
            lock.unlock()
        }

        func get() -> Outcome {
            lock.lock()
            defer { lock.unlock() }
            return outcome
        }
    }
}

/// The probe itself: one name resolved through the running Xray instance, which
/// sends the query over the proxy outbound. It fails when the server cannot be
/// reached, closes the connection, or does not answer in time.
enum ExitProbe {
    /// The same name and limit as Android and Windows, so a server that fails
    /// one fails all.
    static let domain = "cloudflare.com"
    static let timeoutMs = 8000

    static func run(domain: String = domain, timeoutMs: Int = timeoutMs) throws {
        var error: NSError?
        XRayProbe(domain, timeoutMs, &error)
        if let error { throw error }
    }
}

/// Raised the moment a stop is asked for, ahead of the teardown it queues.
///
/// The teardown waits its turn behind a start that is still running, so by
/// itself it cannot tell that start to give up. This can, from any thread.
public final class StopSignal: @unchecked Sendable {
    private let lock = NSLock()
    private var raised = false

    public init() {}

    public func raise() {
        lock.lock()
        raised = true
        lock.unlock()
    }

    /// Call when a new start begins.
    public func reset() {
        lock.lock()
        raised = false
        lock.unlock()
    }

    public var isRaised: Bool {
        lock.lock()
        defer { lock.unlock() }
        return raised
    }
}
