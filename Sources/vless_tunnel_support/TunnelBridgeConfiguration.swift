import Foundation

/// Builds the configuration for the tun2socks bridge that moves packets between
/// the system tunnel interface and Xray's loopback SOCKS inbound.
public enum TunnelBridgeConfiguration {

    /// What the bridge spends on each session, and how many it keeps.
    ///
    /// The extension's memory is close to linear in open sessions: every one
    /// holds a coroutine stack in the bridge, with its transfer buffer on that
    /// stack, and a TLS connection of its own in Xray. Past ``maxSessionCount``
    /// the bridge ends its oldest session to admit the new one, which is the
    /// only thing here that bounds the total. Restarting Xray does not: it
    /// leaves the connections it was carrying open.
    public struct Limits: Equatable, Sendable {
        /// What a session's stack needs besides its buffer.
        private static let stackOverhead = 20480

        public let tcpBufferSize: Int
        public let maxSessionCount: Int

        /// Derived, never set: the buffer is allocated on this stack.
        public var taskStackSize: Int { Self.stackOverhead + tcpBufferSize }

        /// For iOS, which ends a packet tunnel at roughly 50 MB.
        ///
        /// The buffer is the bridge's own recommendation for an extension: it
        /// takes a session from about 185 KB to 125 KB, with no loss of
        /// throughput at the 35 Mbit/s the test exit could carry.
        ///
        /// The cap is what was measured, on macOS: 44 MB with every session a
        /// live TLS connection and 47 MB while 300 connections arrived in six
        /// seconds, against 84 MB for the same load before. At 96 the bridge
        /// began resetting connections that were still being set up. Not yet
        /// measured on a device.
        public static let constrained = Limits(tcpBufferSize: 4096, maxSessionCount: 128)

        /// Where nothing ends the process for its size.
        public static let roomy = Limits(tcpBufferSize: 65536, maxSessionCount: 512)

        public static var platform: Limits {
            #if os(iOS)
            return .constrained
            #else
            return .roomy
            #endif
        }
    }

    /// Non-obvious settings, and why:
    ///
    /// - `pipeline: false` — with pipelining the bridge sends CONNECT before
    ///   username/password authentication has completed, and the inbound
    ///   rejects it.
    /// - `udp: 'udp'` — carries UDP over a SOCKS UDP ASSOCIATE rather than
    ///   tunnelling it inside the TCP stream, which DNS needs.
    /// - `task-stack-size`, `tcp-buffer-size`, `max-session-count` — see
    ///   ``Limits``.
    public static func yaml(
        socksPort: Int,
        credentials: ProxyCredentials,
        mtu: Int,
        logPath: String,
        limits: Limits = .platform
    ) -> String {
        """
        tunnel:
          mtu: \(mtu)
        socks5:
          address: 127.0.0.1
          port: \(socksPort)
          udp: 'udp'
          pipeline: false
          username: \(quoted(credentials.username))
          password: \(quoted(credentials.password))
        misc:
          task-stack-size: \(limits.taskStackSize)
          tcp-buffer-size: \(limits.tcpBufferSize)
          max-session-count: \(limits.maxSessionCount)
          connect-timeout: 5000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
          log-file: \(quoted(logPath))
          log-level: error
          limit-nofile: 65535
        """
    }

    /// Single-quoted YAML scalar; a literal quote is doubled.
    private static func quoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "''") + "'"
    }
}
