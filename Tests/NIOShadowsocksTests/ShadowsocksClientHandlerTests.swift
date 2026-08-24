import Crypto
import Foundation
import Logging
import NIOCore
import NIOEmbedded
import Testing
@_spi(ShadowsocksTesting) import NIOShadowsocks
import NIOShadowsocksTestUtils

/// Framing and state-machine tests for the Shadowsocks 2022 TCP client.
///
/// Every response is produced by `ShadowsocksTestServer`, which implements the server half from
/// the specification independently, so these tests check interoperability rather than self-consistency.
///
/// Method-dependent cases loop over `ShadowsocksMethod.allCases` instead of using
/// `@Test(arguments:)` — Xcode's `-only-testing` cannot select individual parameterized cases, so an
/// `arguments:` test silently reports "not run" under this repo's tooling.
struct ShadowsocksClientHandlerTests {
    // MARK: - Fixtures

    private static let logger = Logger(label: "shadowsocks.tests")

    private static func psks(_ method: ShadowsocksMethod, count: Int = 2) -> [[UInt8]] {
        (0..<count).map { index in
            (0..<method.keySize).map { UInt8((index * 0x20 + $0 + 1) % 256) }
        }
    }

    /// Collects the outcome of `establishedFuture`, which is delivered via a callback.
    private final class ResultBox: @unchecked Sendable {
        var result: Result<Void, any Error>?
        var completionCount = 0

        var succeeded: Bool {
            if case .success = result { return true }
            return false
        }

        var error: (any Error)? {
            if case .failure(let error) = result { return error }
            return nil
        }
    }

    private struct Harness {
        let loop: EmbeddedEventLoop
        let channel: EmbeddedChannel
        let handler: ShadowsocksClientHandler
        var server: ShadowsocksTestServer
        let established: ResultBox
    }

    /// Builds a harness the way production does: connect first, then add the handler, so the
    /// preamble goes out from `handlerAdded` (`PlainTCPProxyUpgrader` hands back a connected channel).
    private static func makeHarness(method: ShadowsocksMethod = .aes128gcm,
                                    pskCount: Int = 2,
                                    serverPSKs: [[UInt8]]? = nil,
                                    host: String = "example.com",
                                    port: Int = 443) throws -> Harness {
        let chain = psks(method, count: pskCount)
        let config = try ShadowsocksConfiguration(method: method, psks: chain)

        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)
        try channel.connect(to: SocketAddress(ipAddress: "203.0.113.1", port: 8388)).wait()

        let handler = ShadowsocksClientHandler(config: config,
                                                targetHost: host,
                                                targetPort: port,
                                                logger: logger)
        try channel.pipeline.syncOperations.addHandler(handler)

        let box = ResultBox()
        handler.establishedFuture?.whenComplete { result in
            box.completionCount += 1
            box.result = result
        }
        loop.run()

        return Harness(loop: loop,
                       channel: channel,
                       handler: handler,
                       server: ShadowsocksTestServer(method: method, psks: serverPSKs ?? chain),
                       established: box)
    }

    private static func readAllOutbound(_ channel: EmbeddedChannel) throws -> ByteBuffer {
        var combined = ByteBufferAllocator().buffer(capacity: 0)
        while var next = try channel.readOutbound(as: ByteBuffer.self) {
            combined.writeBuffer(&next)
        }
        return combined
    }

    private static func flippingByte(at index: Int, in buffer: ByteBuffer) -> ByteBuffer {
        var bytes = [UInt8](buffer.readableBytesView)
        bytes[index] ^= 0xFF
        var out = ByteBufferAllocator().buffer(capacity: bytes.count)
        out.writeBytes(bytes)
        return out
    }

    /// Drives a valid handshake and returns the harness positioned after establishment.
    private static func established(method: ShadowsocksMethod = .aes128gcm,
                                   firstPayload: [UInt8] = Array("hello".utf8)) throws -> Harness {
        var harness = try makeHarness(method: method)
        var request = try readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)
        let response = try harness.server.encodeResponseHeader(payload: firstPayload)
        try harness.channel.writeInbound(response)
        harness.loop.run()
        return harness
    }

    // MARK: - Request shape

    @Test("the request preamble has exactly the specified length")
    func preambleLength() throws {
        for method in ShadowsocksMethod.allCases {
            var harness = try Self.makeHarness(method: method)
            let request = try Self.readAllOutbound(harness.channel)
            var decodable = request.slicedCopy()
            let decoded = try harness.server.decodeRequest(&decodable)

            let variableLength = ShadowsocksConfiguration
                .addressBytes(host: "example.com", port: 443).count + 2 + decoded.paddingLength
            let expected = method.saltSize
                + ShadowsocksMethod.blockSize                                  // one identity header
                + ShadowsocksMethod.requestFixedHeaderSize + ShadowsocksMethod.tagSize
                + variableLength + ShadowsocksMethod.tagSize

            #expect(request.readableBytes == expected, "preamble length for \(method.rawValue)")
        }
    }

    /// SIP022 §3.1.3 requires salt and both header chunks in a single write.
    @Test("the preamble is emitted as a single write")
    func preambleIsOneWrite() throws {
        let harness = try Self.makeHarness()
        let first = try harness.channel.readOutbound(as: ByteBuffer.self)
        let second = try harness.channel.readOutbound(as: ByteBuffer.self)
        #expect(first != nil)
        #expect(second == nil, "the preamble must not be split across writes")
    }

    @Test("each connection uses a fresh random salt")
    func saltIsRandomPerConnection() throws {
        let first = try Self.makeHarness()
        let second = try Self.makeHarness()
        let saltSize = ShadowsocksMethod.aes128gcm.keySize

        let firstSalt = Array(try Self.readAllOutbound(first.channel).readableBytesView.prefix(saltSize))
        let secondSalt = Array(try Self.readAllOutbound(second.channel).readableBytesView.prefix(saltSize))

        #expect(firstSalt != secondSalt)
        #expect(firstSalt != [UInt8](repeating: 0, count: saltSize), "salt must not be all zeros")
    }

    @Test("the identity header count matches the PSK chain length")
    func identityHeaderCount() throws {
        for (pskCount, expectedHeaders) in [(1, 0), (2, 1), (3, 2)] {
            var harness = try Self.makeHarness(pskCount: pskCount)
            var request = try Self.readAllOutbound(harness.channel)
            let decoded = try harness.server.decodeRequest(&request)
            #expect(decoded.identityHeaderCount == expectedHeaders,
                    "\(pskCount) PSKs must produce \(expectedHeaders) identity headers")
            #expect(decoded.resolvedUserIndex == pskCount - 1,
                    "the server must resolve to the uPSK")
        }
    }

    @Test("the server decodes the target address for domains, IPv4 and IPv6")
    func targetAddressEncoding() throws {
        let cases: [(String, Int)] = [
            ("example.com", 443),
            ("192.0.2.10", 8080),
            ("2001:db8::1", 993),
        ]

        for method in ShadowsocksMethod.allCases {
            for (host, port) in cases {
                var harness = try Self.makeHarness(method: method, host: host, port: port)
                var request = try Self.readAllOutbound(harness.channel)
                let decoded = try harness.server.decodeRequest(&request)
                #expect(decoded.port == UInt16(port), "port for \(host) via \(method.rawValue)")
                // The codec renders IP literals via SocketAddress, so the expectation must too —
                // notably IPv6 zero-compression.
                let expectedHost = (try? SocketAddress(ipAddress: host, port: port))?.ipAddress ?? host
                #expect(decoded.host == expectedHost, "host for \(host) via \(method.rawValue)")
            }
        }
    }

    @Test("request padding stays within the specified bound")
    func requestPaddingWithinBounds() throws {
        for _ in 0..<20 {
            var harness = try Self.makeHarness()
            var request = try Self.readAllOutbound(harness.channel)
            let decoded = try harness.server.decodeRequest(&request)
            #expect(decoded.paddingLength <= ShadowsocksConfiguration.maxPaddingLength)
            #expect(decoded.host == "example.com", "padding must not corrupt the address")
        }
    }

    @Test("the preamble is also sent when the handler is added before connect")
    func preambleSentOnChannelActive() throws {
        let method = ShadowsocksMethod.aes128gcm
        let config = try ShadowsocksConfiguration(method: method, psks: Self.psks(method))
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(loop: loop)

        let handler = ShadowsocksClientHandler(config: config,
                                                targetHost: "example.com",
                                                targetPort: 443,
                                                logger: Self.logger)
        try channel.pipeline.syncOperations.addHandler(handler)
        #expect(try channel.readOutbound(as: ByteBuffer.self) == nil,
                "nothing may be written before the channel is active")

        try channel.connect(to: SocketAddress(ipAddress: "203.0.113.1", port: 8388)).wait()
        var server = ShadowsocksTestServer(method: method, psks: Self.psks(method))
        var request = try Self.readAllOutbound(channel)
        let decoded = try server.decodeRequest(&request)
        #expect(decoded.host == "example.com")
    }

    // MARK: - Response framing

    /// The test that actually catches accumulator bugs: partial-read code breaks on dribbled input,
    /// not on whole buffers.
    @Test("a response delivered one byte at a time is decoded intact")
    func responseByteAtATime() throws {
        for method in ShadowsocksMethod.allCases {
            var harness = try Self.makeHarness(method: method)
            var request = try Self.readAllOutbound(harness.channel)
            _ = try harness.server.decodeRequest(&request)

            let payload = Array("the quick brown fox jumps over the lazy dog".utf8)
            let response = try harness.server.encodeResponseHeader(payload: payload)
            let bytes = [UInt8](response.readableBytesView)

            var emitted = [UInt8]()
            for (offset, byte) in bytes.enumerated() {
                var single = ByteBufferAllocator().buffer(capacity: 1)
                single.writeBytes([byte])
                try harness.channel.writeInbound(single)
                harness.loop.run()

                while let out = try harness.channel.readInbound(as: ByteBuffer.self) {
                    emitted += [UInt8](out.readableBytesView)
                }

                if offset < bytes.count - 1 {
                    #expect(emitted.isEmpty, "nothing may be emitted before a chunk completes")
                }
            }

            #expect(emitted == payload, "byte-at-a-time payload for \(method.rawValue)")
            #expect(harness.established.succeeded)
        }
    }

    @Test("a response delivered as one buffer is decoded intact")
    func responseAsSingleBuffer() throws {
        for method in ShadowsocksMethod.allCases {
            var harness = try Self.makeHarness(method: method)
            var request = try Self.readAllOutbound(harness.channel)
            _ = try harness.server.decodeRequest(&request)

            let payload = Array("single buffer".utf8)
            try harness.channel.writeInbound(
                try harness.server.encodeResponseHeader(payload: payload)
            )
            harness.loop.run()

            let out = try harness.channel.readInbound(as: ByteBuffer.self)
            #expect(out.map { [UInt8]($0.readableBytesView) } == payload,
                    "single-buffer payload for \(method.rawValue)")
        }
    }

    @Test("a response split at adversarial boundaries is decoded intact")
    func responseSplitAtAdversarialBoundaries() throws {
        let method = ShadowsocksMethod.aes128gcm
        let payload = Array("boundary probe payload".utf8)

        // One byte short of the header, mid-tag, and mid-length-chunk.
        let headerEnd = method.saltSize + method.responseHeaderSize + ShadowsocksMethod.tagSize
        let splitPoints = [1, headerEnd - 1, headerEnd - 8, headerEnd, headerEnd + 3]

        for splitPoint in splitPoints {
            var harness = try Self.makeHarness(method: method)
            var request = try Self.readAllOutbound(harness.channel)
            _ = try harness.server.decodeRequest(&request)

            let bytes = [UInt8](try harness.server.encodeResponseHeader(payload: payload).readableBytesView)
            guard splitPoint < bytes.count else { continue }

            for slice in [Array(bytes[0..<splitPoint]), Array(bytes[splitPoint...])] {
                var buffer = ByteBufferAllocator().buffer(capacity: slice.count)
                buffer.writeBytes(slice)
                try harness.channel.writeInbound(buffer)
                harness.loop.run()
            }

            var emitted = [UInt8]()
            while let out = try harness.channel.readInbound(as: ByteBuffer.self) {
                emitted += [UInt8](out.readableBytesView)
            }
            #expect(emitted == payload, "split at \(splitPoint)")
        }
    }

    @Test("multiple response chunks reassemble in order")
    func multipleResponseChunksInOrder() throws {
        var harness = try Self.makeHarness()
        var request = try Self.readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)

        let chunks = [Array("first".utf8), Array("second".utf8), Array("third".utf8)]
        try harness.channel.writeInbound(try harness.server.encodeResponseHeader(payload: chunks[0]))
        for chunk in chunks.dropFirst() {
            try harness.channel.writeInbound(try harness.server.encodeResponseChunk(payload: chunk))
        }
        harness.loop.run()

        var emitted = [UInt8]()
        while let out = try harness.channel.readInbound(as: ByteBuffer.self) {
            emitted += [UInt8](out.readableBytesView)
        }
        #expect(emitted == chunks.flatMap { $0 })
    }

    // MARK: - Outbound chunking

    @Test("outbound writes use ascending nonces and decode server-side")
    func outboundNonceOrdering() throws {
        var harness = try Self.established()
        _ = try Self.readAllOutbound(harness.channel)

        let payloads = [Array("first write".utf8), Array("second write".utf8)]
        for payload in payloads {
            var buffer = ByteBufferAllocator().buffer(capacity: payload.count)
            buffer.writeBytes(payload)
            try harness.channel.writeOutbound(buffer)
        }

        var stream = try Self.readAllOutbound(harness.channel)
        // The server's request nonce counter continues from the two header chunks, so decoding both
        // payloads in order only works if the client advanced its counter in lockstep.
        for payload in payloads {
            #expect(try harness.server.decodePayloadChunk(&stream) == payload)
        }
        #expect(stream.readableBytes == 0)
    }

    @Test("writes larger than 0xFFFF are split into multiple chunks")
    func largeWritesSplit() throws {
        let cases: [(Int, Int)] = [
            (ShadowsocksClientHandler.maxChunkLength, 1),
            (ShadowsocksClientHandler.maxChunkLength + 1, 2),
            (100 * 1024, 2),
        ]

        for (size, expectedChunks) in cases {
            var harness = try Self.established()
            _ = try Self.readAllOutbound(harness.channel)

            let payload = (0..<size).map { UInt8($0 % 251) }
            var buffer = ByteBufferAllocator().buffer(capacity: size)
            buffer.writeBytes(payload)
            try harness.channel.writeOutbound(buffer)

            var stream = try Self.readAllOutbound(harness.channel)
            var decoded = [UInt8]()
            var chunkCount = 0
            while stream.readableBytes > 0 {
                decoded += try harness.server.decodePayloadChunk(&stream)
                chunkCount += 1
            }

            #expect(decoded == payload, "payload of \(size) bytes must survive chunking")
            #expect(chunkCount == expectedChunks, "\(size) bytes must produce \(expectedChunks) chunks")
        }
    }

    @Test("an empty write emits no chunk")
    func emptyWriteEmitsNothing() throws {
        let harness = try Self.established()
        _ = try Self.readAllOutbound(harness.channel)

        try harness.channel.writeOutbound(ByteBufferAllocator().buffer(capacity: 0))
        #expect(try harness.channel.readOutbound(as: ByteBuffer.self) == nil)
    }

    // MARK: - Establishment and rejections

    @Test("a valid response completes establishedFuture exactly once")
    func establishedFutureSucceedsOnce() throws {
        let harness = try Self.established()
        #expect(harness.established.succeeded)
        #expect(harness.established.completionCount == 1)
    }

    @Test("a response with the client header type is rejected")
    func rejectsWrongHeaderType() throws {
        var harness = try Self.makeHarness()
        var request = try Self.readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)

        let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3], type: 0)
        try? harness.channel.writeInbound(response)
        harness.loop.run()

        #expect(harness.established.error as? ShadowsocksError
            == .headerTypeMismatch(expected: 1, actual: 0))
    }

    @Test("a response timestamp outside the replay window is rejected")
    func rejectsSkewedTimestamp() throws {
        for skew in [Int64(31), Int64(-31)] {
            var harness = try Self.makeHarness()
            var request = try Self.readAllOutbound(harness.channel)
            _ = try harness.server.decodeRequest(&request)

            let now = ShadowsocksConfiguration.currentTimestamp()
            let timestamp = skew > 0 ? now + UInt64(skew) : now - UInt64(-skew)
            let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3],
                                                                   timestamp: timestamp)
            try? harness.channel.writeInbound(response)
            harness.loop.run()

            guard case .timestampOutOfWindow = harness.established.error as? ShadowsocksError else {
                Issue.record("expected a timestamp rejection for skew \(skew), got \(String(describing: harness.established.error))")
                continue
            }
        }
    }

    @Test("a response echoing the wrong request salt is rejected")
    func rejectsWrongRequestSalt() throws {
        var harness = try Self.makeHarness()
        var request = try Self.readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)

        let wrongSalt = [UInt8](repeating: 0x77, count: ShadowsocksMethod.aes128gcm.saltSize)
        let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3],
                                                               requestSalt: wrongSalt)
        try? harness.channel.writeInbound(response)
        harness.loop.run()

        #expect(harness.established.error as? ShadowsocksError == .requestSaltMismatch)
    }

    @Test("a corrupted response header fails authentication")
    func rejectsCorruptedResponseHeader() throws {
        var harness = try Self.makeHarness()
        var request = try Self.readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)

        let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3])
        // Flip a byte inside the sealed header, past the salt.
        let corrupted = Self.flippingByte(at: ShadowsocksMethod.aes128gcm.saltSize + 2,
                                          in: response)
        try? harness.channel.writeInbound(corrupted)
        harness.loop.run()

        #expect(harness.established.error as? ShadowsocksError == .authenticationFailed)
    }

    @Test("a corrupted payload chunk mid-stream fails authentication")
    func rejectsCorruptedPayloadChunk() throws {
        var harness = try Self.established()
        #expect(harness.established.succeeded)

        // Drain the payload the handshake already delivered, so the assertion below is about the
        // corrupted chunk only.
        while try harness.channel.readInbound(as: ByteBuffer.self) != nil {}

        // `writeInbound` rethrows whatever the pipeline caught (and clears it), so assert on the
        // write itself rather than on a later `throwIfErrorCaught`.
        let chunk = try harness.server.encodeResponseChunk(payload: Array("second".utf8))
        let corrupted = Self.flippingByte(at: 3, in: chunk)
        #expect(throws: ShadowsocksError.authenticationFailed) {
            try harness.channel.writeInbound(corrupted)
        }
        harness.loop.run()

        #expect(try harness.channel.readInbound(as: ByteBuffer.self) == nil,
                "a corrupted chunk must not emit plaintext")
    }

    @Test("a stream truncated before the response header fails establishedFuture")
    func truncatedStreamFailsEstablishment() throws {
        var harness = try Self.makeHarness()
        var request = try Self.readAllOutbound(harness.channel)
        _ = try harness.server.decodeRequest(&request)

        let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3])
        var partial = ByteBufferAllocator().buffer(capacity: 4)
        partial.writeBytes(Array([UInt8](response.readableBytesView).prefix(4)))
        try harness.channel.writeInbound(partial)
        harness.loop.run()
        #expect(harness.established.result == nil, "still waiting for the rest of the header")

        _ = try? harness.channel.finish()
        harness.loop.run()

        #expect(harness.established.error as? ShadowsocksError == .truncatedHeader,
                "EOF before the header must fail rather than hang")
    }

    /// The case that protects SASE status reporting: a wrong PSK must surface as an authentication
    /// failure, not as a generic transport error.
    @Test("a response from a server with a different PSK fails authentication")
    func rejectsWrongPSK() throws {
        let method = ShadowsocksMethod.aes128gcm
        let wrongPSKs = Self.psks(method).map { psk in psk.map { $0 ^ 0xFF } }

        var harness = try Self.makeHarness(method: method, serverPSKs: wrongPSKs)
        // The server cannot read our request either, but what matters here is the client's verdict.
        _ = try Self.readAllOutbound(harness.channel)
        harness.server.observedRequestSalt = [UInt8](repeating: 0, count: method.saltSize)
        let response = try harness.server.encodeResponseHeader(payload: [1, 2, 3])
        try? harness.channel.writeInbound(response)
        harness.loop.run()

        #expect(harness.established.error as? ShadowsocksError == .authenticationFailed)
    }

    // MARK: - Lifecycle

    @Test("input closure propagates for half-close support")
    func inputClosedPropagates() throws {
        let harness = try Self.established()

        final class EventRecorder: ChannelInboundHandler, @unchecked Sendable {
            typealias InboundIn = ByteBuffer
            var sawInputClosed = false

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                if case ChannelEvent.inputClosed = event { sawInputClosed = true }
                context.fireUserInboundEventTriggered(event)
            }
        }

        let recorder = EventRecorder()
        try harness.channel.pipeline.syncOperations.addHandler(recorder)
        harness.channel.pipeline.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
        harness.loop.run()

        #expect(recorder.sawInputClosed, "the codec must not swallow half-close events")
    }

    /// SIP022 has no in-band EOF, so a FIN is just a FIN — but a write arriving after output
    /// half-close must not trap.
    @Test("a write after output half-close does not trap")
    func writeAfterOutputHalfCloseDoesNotTrap() throws {
        let harness = try Self.established()
        _ = try Self.readAllOutbound(harness.channel)

        try? harness.channel.close(mode: .output).wait()
        harness.loop.run()

        var buffer = ByteBufferAllocator().buffer(capacity: 4)
        buffer.writeBytes(Array("late".utf8))
        // The write is expected to fail; the requirement is that it fails rather than crashes.
        let promise = harness.channel.eventLoop.makePromise(of: Void.self)
        harness.channel.write(buffer, promise: promise)
        harness.channel.flush()
        harness.loop.run()
        _ = try? promise.futureResult.wait()
    }
}

// MARK: - Test-only helpers

private extension ByteBuffer {
    /// A copy positioned at the same reader index, so a buffer can be decoded more than once.
    func slicedCopy() -> ByteBuffer {
        var copy = ByteBufferAllocator().buffer(capacity: readableBytes)
        copy.writeBytes(readableBytesView)
        return copy
    }
}
