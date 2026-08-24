import Foundation
import NIOCore
import NIOPosix
@_spi(ShadowsocksTesting) import NIOShadowsocks

/// A real, listening Shadowsocks 2022 server for integration tests.
///
/// Decodes the client's request preamble with `ShadowsocksTestServer` (the independent
/// server-side codec), records the target it asked for, then echoes every payload chunk back inside
/// the tunnel. That makes it possible to drive `PlainTCPProxyUpgrader` over a real socket and check
/// the whole path — routing, connector, codec, framing — rather than a mocked channel.
public final class ShadowsocksTestEchoServer: Sendable {
    /// What the client asked the server to connect to, once the preamble has been decoded.
    public struct ObservedRequest: Sendable, Equatable {
        public let host: String
        public let port: UInt16
        public let resolvedUserIndex: Int

        public init(host: String, port: UInt16, resolvedUserIndex: Int) {
            self.host = host
            self.port = port
            self.resolvedUserIndex = resolvedUserIndex
        }
    }

    /// What the server does with the plaintext it recovers from the tunnel.
    public enum Behaviour: Sendable {
        /// Echo every payload chunk straight back.
        case echo
        /// Accumulate until a complete HTTP request has arrived, then reply with this canned
        /// response. Lets a real `HTTPClient` drive a request through the tunnel.
        case cannedHTTPResponse(String)
    }

    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private let state: State

    /// Shared observation point. An actor would need awaits inside NIO callbacks, so this is a lock.
    public final class State: @unchecked Sendable {
        private let lock = NSLock()
        private var _requests: [ObservedRequest] = []
        private var _handshakeFailures = 0
        private var _tunnelledRequests: [String] = []

        public var requests: [ObservedRequest] {
            lock.withLock { _requests }
        }

        public var handshakeFailures: Int {
            lock.withLock { _handshakeFailures }
        }

        public func record(_ request: ObservedRequest) {
            lock.withLock { _requests.append(request) }
        }

        public func recordFailure() {
            lock.withLock { _handshakeFailures += 1 }
        }

        /// The plaintext the client sent through the tunnel, for `.cannedHTTPResponse`.
        public var tunnelledRequests: [String] {
            lock.withLock { _tunnelledRequests }
        }

        public func recordTunnelledRequest(_ request: String) {
            lock.withLock { _tunnelledRequests.append(request) }
        }
    }

    public var port: Int { channel.localAddress?.port ?? 0 }
    public var observedRequests: [ObservedRequest] { state.requests }
    public var handshakeFailures: Int { state.handshakeFailures }
    public var tunnelledRequests: [String] { state.tunnelledRequests }

    private init(group: MultiThreadedEventLoopGroup, channel: Channel, state: State) {
        self.group = group
        self.channel = channel
        self.state = state
    }

    public static func start(method: ShadowsocksMethod,
                      psks: [[UInt8]],
                      behaviour: Behaviour = .echo) async throws -> ShadowsocksTestEchoServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let state = State()
        let channel = try await ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        EchoHandler(method: method, psks: psks, state: state, behaviour: behaviour)
                    )
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        return ShadowsocksTestEchoServer(group: group, channel: channel, state: state)
    }

    public func shutdown() async {
        try? await channel.close()
        try? await group.shutdownGracefully()
    }

    // MARK: - Handler

    private final class EchoHandler: ChannelInboundHandler, @unchecked Sendable {
        typealias InboundIn = ByteBuffer
        typealias OutboundOut = ByteBuffer

        private var server: ShadowsocksTestServer
        private let state: State
        private let behaviour: Behaviour
        private var accumulator: ByteBuffer?
        private var decodedRequest = false
        private var sentResponseHeader = false
        /// Plaintext recovered from the tunnel, for `.cannedHTTPResponse`.
        private var tunnelledPlaintext = ""
        private var answered = false

        public init(method: ShadowsocksMethod, psks: [[UInt8]], state: State, behaviour: Behaviour) {
            self.server = ShadowsocksTestServer(method: method, psks: psks)
            self.state = state
            self.behaviour = behaviour
        }

        public func handlerAdded(context: ChannelHandlerContext) {
            accumulator = context.channel.allocator.buffer(capacity: 0)
        }

        public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
            var incoming = unwrapInboundIn(data)
            accumulator?.writeBuffer(&incoming)

            do {
                if !decodedRequest {
                    // The preamble arrives in one write from our client, so one attempt suffices;
                    // a short read simply leaves it for the next `channelRead`.
                    guard var buffer = accumulator else { return }
                    let request = try server.decodeRequest(&buffer)
                    accumulator = buffer
                    decodedRequest = true
                    state.record(ObservedRequest(host: request.host,
                                                 port: request.port,
                                                 resolvedUserIndex: request.resolvedUserIndex))
                }

                // Handle every complete payload chunk recovered from the tunnel.
                while var buffer = accumulator, buffer.readableBytes > 0 {
                    let payload = try server.decodePayloadChunk(&buffer)
                    accumulator = buffer
                    try handle(payload, context: context)
                }
            } catch let error as ShadowsocksTestServer.ServerError where error == .short {
                // Partial chunk — wait for more bytes. The accumulator still holds them because
                // `decodePayloadChunk` only advances on a complete chunk.
                return
            } catch {
                state.recordFailure()
                context.close(promise: nil)
            }
        }

        private func handle(_ payload: [UInt8], context: ChannelHandlerContext) throws {
            switch behaviour {
            case .echo:
                try send(payload, context: context)

            case .cannedHTTPResponse(let response):
                tunnelledPlaintext += String(decoding: payload, as: UTF8.self)
                // Wait for the end of the request head before answering, and answer only once.
                guard !answered, tunnelledPlaintext.contains("\r\n\r\n") else { return }
                answered = true
                state.recordTunnelledRequest(tunnelledPlaintext)
                try send(Array(response.utf8), context: context)
            }
        }

        private func send(_ payload: [UInt8], context: ChannelHandlerContext) throws {
            let out: ByteBuffer
            if sentResponseHeader {
                out = try server.encodeResponseChunk(payload: payload, allocator: context.channel.allocator)
            } else {
                sentResponseHeader = true
                out = try server.encodeResponseHeader(payload: payload, allocator: context.channel.allocator)
            }
            context.writeAndFlush(wrapOutboundOut(out), promise: nil)
        }
    }
}
