import Crypto
import Foundation
import Logging
import NIOCore
import NIOEmbedded
import Testing
@_spi(ShadowsocksTesting) import NIOShadowsocks
import NIOShadowsocksTestUtils

/// Packet-format and session tests for the Shadowsocks 2022 UDP client.
///
/// Every packet is checked against `ShadowsocksTestServer`, which implements the server half from
/// the specification independently, so the four UDP-specific details that differ from TCP are pinned
/// by something other than our own encoder.
///
/// Method-dependent cases loop over `allCases` rather than using `@Test(arguments:)` — Xcode's
/// `-only-testing` cannot select individual parameterized cases.
struct ShadowsocksUDPClientHandlerTests {
    private static let logger = Logger(label: "shadowsocks.udp.tests")
    private static let allocator = ByteBufferAllocator()

    private static func psks(_ method: ShadowsocksMethod, count: Int = 2) -> [[UInt8]] {
        (0..<count).map { index in
            (0..<method.keySize).map { UInt8((index * 0x20 + $0 + 1) % 256) }
        }
    }

    private static func makeHandler(method: ShadowsocksMethod = .aes128gcm,
                                    pskCount: Int = 2,
                                    host: String = "example.com",
                                    port: Int = 53,
                                    now: @Sendable @escaping () -> NIODeadline = { NIODeadline.now() }) throws
        -> (ShadowsocksUDPClientHandler, ShadowsocksTestServer) {
        let chain = psks(method, count: pskCount)
        let config = try ShadowsocksConfiguration(method: method, psks: chain)
        let handler = ShadowsocksUDPClientHandler(config: config,
                                                targetHost: host,
                                                targetPort: port,
                                                logger: logger,
                                                now: now)
        return (handler, ShadowsocksTestServer(method: method, psks: chain))
    }

    /// The client session ID the handler minted, recovered via a packet it produced.
    private static func clientSessionID(of handler: ShadowsocksUDPClientHandler,
                                        server: ShadowsocksTestServer) throws -> [UInt8] {
        let probe = try handler.encode(payload: [0x00], allocator: allocator)
        return try server.decodeUDP(probe).sessionID
    }

    // MARK: - Round trip

    @Test("a datagram round-trips through an independent server codec")
    func roundTrip() throws {
        let targets: [(String, Int)] = [
            ("example.com", 53),
            ("192.0.2.10", 5353),
            ("2001:db8::1", 443),
        ]

        for method in ShadowsocksMethod.allCases {
            for (host, port) in targets {
                let (handler, server) = try Self.makeHandler(method: method, host: host, port: port)
                let payload = Array("dns query bytes".utf8)

                let packet = try handler.encode(payload: payload, allocator: Self.allocator)
                let decoded = try server.decodeUDP(packet)

                #expect(decoded.payload == payload, "payload for \(host) via \(method.rawValue)")
                #expect(decoded.port == UInt16(port), "port for \(host) via \(method.rawValue)")
                // The codec renders IP literals via SocketAddress, so the expectation must too —
                // notably IPv6 zero-compression.
                let expectedHost = (try? SocketAddress(ipAddress: host, port: port))?.ipAddress ?? host
                #expect(decoded.host == expectedHost, "host for \(host) via \(method.rawValue)")
                #expect(decoded.resolvedUserIndex == 1, "the server must resolve the uPSK")

                // And back the other way.
                let response = Array("dns answer bytes".utf8)
                let serverPacket = try server.encodeUDP(payload: response,
                                                        clientSessionID: decoded.sessionID,
                                                        serverSessionID: [UInt8](repeating: 0x7A, count: 8),
                                                        packetID: 0)
                let emitted = try handler.decode(packet: serverPacket, allocator: Self.allocator)
                #expect([UInt8](emitted.readableBytesView) == response,
                        "response for \(host) via \(method.rawValue)")
            }
        }
    }

    @Test("identity header count follows the PSK chain length")
    func identityHeaderCount() throws {
        for (pskCount, expectedIndex) in [(1, 0), (2, 1), (3, 2)] {
            let (handler, server) = try Self.makeHandler(pskCount: pskCount)
            let decoded = try server.decodeUDP(try handler.encode(payload: [1, 2, 3],
                                                                 allocator: Self.allocator))
            #expect(decoded.resolvedUserIndex == expectedIndex,
                    "\(pskCount) PSKs must resolve to index \(expectedIndex)")
        }
    }

    // MARK: - The four UDP-specific details

    /// Using the packet ID alone as the nonce produces packets a server silently drops, which is the
    /// worst possible failure mode — everything looks fine and nothing works.
    @Test("the AEAD nonce is separateHeader[4..<16], not the packet ID alone")
    func nonceIsSeparateHeaderTail() throws {
        let method = ShadowsocksMethod.aes128gcm
        let (handler, _) = try Self.makeHandler(method: method)
        let packet = try handler.encode(payload: Array("probe".utf8), allocator: Self.allocator)

        // Layout: encrypted separate header (16) ‖ one identity header (16) ‖ sealed body.
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        let bytes = [UInt8](packet.readableBytesView)
        let separateHeader = try AESBlock.decrypt(block: Array(bytes[0..<16]), key: config.psks[0])
        let sealed = Array(bytes[32...])

        let subkey = config.sessionSubkey(salt: Array(separateHeader.prefix(8)))
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: separateHeader[4..<16]),
                                        ciphertext: Data(sealed.prefix(sealed.count - 16)),
                                        tag: Data(sealed.suffix(16)))
        #expect(throws: Never.self) { try AES.GCM.open(box, using: subkey) }

        // The plausible-but-wrong construction: four zero bytes followed by the packet ID.
        let wrongNonceBytes = [UInt8](repeating: 0, count: 4) + separateHeader[8..<16]
        let wrongBox = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: wrongNonceBytes),
                                             ciphertext: Data(sealed.prefix(sealed.count - 16)),
                                             tag: Data(sealed.suffix(16)))
        #expect(throws: (any Error).self) { try AES.GCM.open(wrongBox, using: subkey) }
    }

    /// The test server parses padding before the address, so a TCP-shaped body would fail there.
    @Test("padding precedes the address in the UDP header")
    func paddingPrecedesAddress() throws {
        let (handler, server) = try Self.makeHandler()
        let decoded = try server.decodeUDP(try handler.encode(payload: [9, 9],
                                                             allocator: Self.allocator))
        #expect(decoded.paddingLength == 0, "UDP packets are sent unpadded to stay under the MTU")
        #expect(decoded.host == "example.com", "the address must parse after the padding field")
        #expect(decoded.payload == [9, 9])
    }

    /// UDP identity headers key on the raw iPSK and XOR the plaintext with the separate header. Using
    /// the TCP construction (a salt-derived subkey, no XOR) must not accidentally agree.
    @Test("UDP identity headers use the raw iPSK XORed with the separate header")
    func identityHeaderConstruction() throws {
        let method = ShadowsocksMethod.aes128gcm
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        let (handler, _) = try Self.makeHandler(method: method)
        let packet = try handler.encode(payload: [1], allocator: Self.allocator)

        let bytes = [UInt8](packet.readableBytesView)
        let separateHeader = try AESBlock.decrypt(block: Array(bytes[0..<16]), key: config.psks[0])
        let identityHeader = Array(bytes[16..<32])

        let expected = try AESBlock.encrypt(
            block: zip(config.pskHashes[1], separateHeader).map { $0 ^ $1 },
            key: config.psks[0]
        )
        #expect(identityHeader == expected)

        // The TCP construction, for contrast.
        let tcpStyle = try config.tcpIdentityHeaders(salt: Array(separateHeader.prefix(method.saltSize)))
        #expect(identityHeader != tcpStyle)
    }

    @Test("the separate header is keyed by iPSK0 outbound and the uPSK inbound")
    func separateHeaderKeysPerDirection() throws {
        let method = ShadowsocksMethod.aes128gcm
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        let (handler, server) = try Self.makeHandler(method: method)

        let packet = try handler.encode(payload: [1], allocator: Self.allocator)
        let encrypted = Array([UInt8](packet.readableBytesView)[0..<16])

        // Decrypting under iPSK0 yields a header whose session ID matches what the server observed;
        // decrypting under the uPSK yields something else entirely.
        let underIPSK = try AESBlock.decrypt(block: encrypted, key: config.psks[0])
        let underUPSK = try AESBlock.decrypt(block: encrypted, key: config.sessionKey)
        let observed = try server.decodeUDP(try handler.encode(payload: [1], allocator: Self.allocator))

        #expect(Array(underIPSK.prefix(8)) == observed.sessionID)
        #expect(Array(underUPSK.prefix(8)) != observed.sessionID)
    }

    // MARK: - Session and replay

    @Test("the packet ID increments by one and the session ID stays fixed")
    func packetIDIncrementsAndSessionIsStable() throws {
        let (handler, server) = try Self.makeHandler()
        var sessionIDs = Set<String>()
        var packetIDs = [UInt64]()

        for _ in 0..<5 {
            let decoded = try server.decodeUDP(try handler.encode(payload: [0],
                                                                  allocator: Self.allocator))
            sessionIDs.insert(decoded.sessionID.hexString)
            packetIDs.append(decoded.packetID)
        }

        #expect(sessionIDs.count == 1, "one handler is one session")
        #expect(packetIDs == [0, 1, 2, 3, 4])
    }

    @Test("two handlers use different session IDs")
    func sessionIDsAreRandomPerHandler() throws {
        let (first, firstServer) = try Self.makeHandler()
        let (second, secondServer) = try Self.makeHandler()
        let a = try firstServer.decodeUDP(try first.encode(payload: [0], allocator: Self.allocator))
        let b = try secondServer.decodeUDP(try second.encode(payload: [0], allocator: Self.allocator))
        #expect(a.sessionID != b.sessionID)
        #expect(a.sessionID != [UInt8](repeating: 0, count: 8))
    }

    @Test("a replayed server packet ID is rejected")
    func replayedPacketIsRejected() throws {
        let (handler, server) = try Self.makeHandler()
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)
        let serverSessionID = [UInt8](repeating: 0x7A, count: 8)

        let first = try server.encodeUDP(payload: Array("one".utf8),
                                         clientSessionID: clientSessionID,
                                         serverSessionID: serverSessionID,
                                         packetID: 0)
        #expect(throws: Never.self) { try handler.decode(packet: first, allocator: Self.allocator) }

        // The identical datagram again must not be relayed a second time.
        #expect(throws: ShadowsocksError.replayedPacket(id: 0)) {
            try handler.decode(packet: first, allocator: Self.allocator)
        }
    }

    @Test("out-of-order server packets inside the window are accepted")
    func outOfOrderPacketsAccepted() throws {
        let (handler, server) = try Self.makeHandler()
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)
        let serverSessionID = [UInt8](repeating: 0x7A, count: 8)

        for packetID in [0, 1, 4, 2, 3] as [UInt64] {
            let packet = try server.encodeUDP(payload: [UInt8(packetID)],
                                              clientSessionID: clientSessionID,
                                              serverSessionID: serverSessionID,
                                              packetID: packetID)
            #expect(throws: Never.self, "packet \(packetID) is out of order but not a duplicate") {
                try handler.decode(packet: packet, allocator: Self.allocator)
            }
        }
    }

    /// SIP022 §3.2.4: a new server session must not displace a live one, or an off-path attacker
    /// could reset the replay window at will.
    @Test("a new server session is rejected while the current one is live, and accepted after")
    func serverSessionGracePeriod() throws {
        let clock = MutableDeadlineClock()
        let (handler, server) = try Self.makeHandler(now: { clock.now })
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)

        let firstSession = [UInt8](repeating: 0x11, count: 8)
        let secondSession = [UInt8](repeating: 0x22, count: 8)

        let establish = try server.encodeUDP(payload: [1],
                                             clientSessionID: clientSessionID,
                                             serverSessionID: firstSession,
                                             packetID: 0)
        #expect(throws: Never.self) { try handler.decode(packet: establish, allocator: Self.allocator) }

        // Still inside the grace period.
        clock.advance(by: .seconds(30))
        let tooSoon = try server.encodeUDP(payload: [2],
                                           clientSessionID: clientSessionID,
                                           serverSessionID: secondSession,
                                           packetID: 0)
        #expect(throws: ShadowsocksError.sessionMismatch) {
            try handler.decode(packet: tooSoon, allocator: Self.allocator)
        }

        // Past it.
        clock.advance(by: .seconds(31))
        let nowAllowed = try server.encodeUDP(payload: [3],
                                              clientSessionID: clientSessionID,
                                              serverSessionID: secondSession,
                                              packetID: 1)
        #expect(throws: Never.self) {
            try handler.decode(packet: nowAllowed, allocator: Self.allocator)
        }

        // The displaced session becomes the "old" slot and still works, with its own window.
        let fromOldSession = try server.encodeUDP(payload: [4],
                                                  clientSessionID: clientSessionID,
                                                  serverSessionID: firstSession,
                                                  packetID: 7)
        #expect(throws: Never.self) {
            try handler.decode(packet: fromOldSession, allocator: Self.allocator)
        }
    }

    @Test("a response for a different client session is rejected")
    func mismatchedClientSessionRejected() throws {
        let (handler, server) = try Self.makeHandler()
        let packet = try server.encodeUDP(payload: [1],
                                          clientSessionID: [UInt8](repeating: 0xEE, count: 8),
                                          serverSessionID: [UInt8](repeating: 0x7A, count: 8),
                                          packetID: 0)
        #expect(throws: ShadowsocksError.sessionMismatch) {
            try handler.decode(packet: packet, allocator: Self.allocator)
        }
    }

    // MARK: - Rejections

    @Test("a response with the client header type is rejected")
    func wrongHeaderTypeRejected() throws {
        let (handler, server) = try Self.makeHandler()
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)
        let packet = try server.encodeUDP(payload: [1],
                                          clientSessionID: clientSessionID,
                                          serverSessionID: [UInt8](repeating: 0x7A, count: 8),
                                          packetID: 0,
                                          type: 0)
        #expect(throws: ShadowsocksError.headerTypeMismatch(expected: 1, actual: 0)) {
            try handler.decode(packet: packet, allocator: Self.allocator)
        }
    }

    @Test("a response timestamp outside the replay window is rejected")
    func skewedTimestampRejected() throws {
        let (handler, server) = try Self.makeHandler()
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)
        let packet = try server.encodeUDP(payload: [1],
                                          clientSessionID: clientSessionID,
                                          serverSessionID: [UInt8](repeating: 0x7A, count: 8),
                                          packetID: 0,
                                          timestamp: ShadowsocksConfiguration.currentTimestamp() + 31)
        #expect(throws: (any Error).self) {
            try handler.decode(packet: packet, allocator: Self.allocator)
        }
    }

    @Test("malformed datagrams are rejected without crashing")
    func malformedDatagramsRejected() throws {
        let (handler, server) = try Self.makeHandler()
        let clientSessionID = try Self.clientSessionID(of: handler, server: server)

        // Shorter than the separate header plus a tag.
        var short = Self.allocator.buffer(capacity: 8)
        short.writeBytes([UInt8](repeating: 0, count: 8))
        #expect(throws: ShadowsocksError.truncatedHeader) {
            try handler.decode(packet: short, allocator: Self.allocator)
        }

        // Right length, garbage contents.
        var garbage = Self.allocator.buffer(capacity: 64)
        garbage.writeBytes((0..<64).map { UInt8($0) })
        #expect(throws: (any Error).self) {
            try handler.decode(packet: garbage, allocator: Self.allocator)
        }

        // A valid packet with one ciphertext byte flipped.
        let valid = try server.encodeUDP(payload: Array("payload".utf8),
                                         clientSessionID: clientSessionID,
                                         serverSessionID: [UInt8](repeating: 0x7A, count: 8),
                                         packetID: 0)
        var corruptedBytes = [UInt8](valid.readableBytesView)
        corruptedBytes[20] ^= 0xFF
        var corrupted = Self.allocator.buffer(capacity: corruptedBytes.count)
        corrupted.writeBytes(corruptedBytes)
        #expect(throws: ShadowsocksError.authenticationFailed) {
            try handler.decode(packet: corrupted, allocator: Self.allocator)
        }
    }

    /// UDP is unreliable and an off-path attacker can inject packets, so a bad datagram must be
    /// dropped rather than tearing down a session that is otherwise healthy.
    @Test("a bad datagram is dropped without closing the channel or erroring")
    func badDatagramIsDroppedNotFatal() throws {
        let method = ShadowsocksMethod.aes128gcm
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "203.0.113.1", port: 8388)).wait()
        let handler = ShadowsocksUDPClientHandler(config: config,
                                                targetHost: "example.com",
                                                targetPort: 53,
                                                logger: Self.logger)
        try channel.pipeline.syncOperations.addHandler(handler)

        var garbage = channel.allocator.buffer(capacity: 64)
        garbage.writeBytes((0..<64).map { UInt8($0) })
        // Must not throw: the handler swallows the packet rather than firing an error.
        try channel.writeInbound(garbage)
        loop.run()

        #expect(try channel.readInbound(as: ByteBuffer.self) == nil, "nothing may be relayed")
        #expect(channel.isActive, "one bad datagram must not kill the session")
    }

    @Test("an outbound write produces exactly one datagram")
    func writeProducesOneDatagram() throws {
        let method = ShadowsocksMethod.aes128gcm
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        var server = ShadowsocksTestServer(method: method, psks: Self.psks(method))
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "203.0.113.1", port: 8388)).wait()
        try channel.pipeline.syncOperations.addHandler(
            ShadowsocksUDPClientHandler(config: config,
                                      targetHost: "example.com",
                                      targetPort: 53,
                                      logger: Self.logger)
        )

        let payload = Array("one datagram".utf8)
        var out = channel.allocator.buffer(capacity: payload.count)
        out.writeBytes(payload)
        try channel.writeOutbound(out)

        let datagram = try #require(try channel.readOutbound(as: ByteBuffer.self))
        #expect(try channel.readOutbound(as: ByteBuffer.self) == nil, "one write, one datagram")
        #expect(try server.decodeUDP(datagram).payload == payload)
        _ = server
    }
}

/// A hand-advanced monotonic clock, so the 60s server-session grace period can be tested without
/// sleeping. Distinct from the existing `Helpers/MutableClock`, which is `Date`-based — the grace
/// period deliberately uses `NIODeadline` so a wall-clock jump cannot widen or shrink it.
private final class MutableDeadlineClock: @unchecked Sendable {
    private let lock = NSLock()
    private var offset = TimeAmount.zero
    private let base = NIODeadline.now()

    var now: NIODeadline {
        lock.withLock { base + offset }
    }

    func advance(by amount: TimeAmount) {
        lock.withLock { offset = offset + amount }
    }
}
