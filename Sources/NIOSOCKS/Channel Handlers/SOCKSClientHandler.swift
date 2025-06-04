//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// Connects to a SOCKS server to establish a proxied connection
/// to a host. This handler should be inserted at the beginning of a
/// channel's pipeline. Note that SOCKS only supports fully-qualified
/// domain names and IPv4 or IPv6 sockets, and not UNIX sockets.
///
/// Two connection modes are supported:
/// - CONNECT: For TCP connections (default). The handler should be added to a TCP channel.
/// - UDP ASSOCIATE: For UDP connections. The handler should be added to a UDP channel.
public final class SOCKSClientHandler: ChannelDuplexHandler {
    /// Accepts `ByteBuffer` as input where receiving.
    public typealias InboundIn = ByteBuffer
    /// Sends `ByteBuffer` to the next pipeline stage when receiving.
    public typealias InboundOut = ByteBuffer
    /// Accepts `ByteBuffer` as the type to send.
    public typealias OutboundIn = ByteBuffer
    /// Sends `ByteBuffer` to the next outbound stage.
    public typealias OutboundOut = ByteBuffer

    private let targetAddress: SOCKSAddress
    private let username: String?
    private let password: String?
    private let commandType: SOCKSCommand

    private var state: ClientStateMachine
    private var removalToken: ChannelHandlerContext.RemovalToken?
    private var inboundBuffer: ByteBuffer?

    private var bufferedWrites: MarkedCircularBuffer<(NIOAny, EventLoopPromise<Void>?)> = .init(initialCapacity: 8)
    
    /// Creates a new ``SOCKSClientHandler`` that connects to a server
    /// and instructs the server to connect to `targetAddress` with basic authentication.
    /// - parameter targetAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    /// - parameter username: The username to use for authentication.
    /// - parameter password: The password to use for authentication.
    /// - parameter command: The SOCKS command to use, either .connect (default) for TCP connections or .udpAssociate for UDP.
    public init(targetAddress: SOCKSAddress, username: String? = nil, password: String? = nil, command: SOCKSCommand = .connect) {

        switch targetAddress {
        case .address(.unixDomainSocket):
            preconditionFailure("UNIX domain sockets are not supported.")
        case .domain, .address(.v4), .address(.v6):
            break
        }

        self.state = ClientStateMachine()
        self.targetAddress = targetAddress
        self.username = username
        self.password = password
        self.commandType = command
    }

    public func channelActive(context: ChannelHandlerContext) {
        self.beginHandshake(context: context)
    }

    /// Add handler to pipeline and start handshake.
    /// - Parameter context: Calling context.
    public func handlerAdded(context: ChannelHandlerContext) {
        self.beginHandshake(context: context)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

        // if we've established the connection then forward on the data
        if self.state.proxyEstablished {
            context.fireChannelRead(data)
            return
        }

        var inboundBuffer = self.unwrapInboundIn(data)

        self.inboundBuffer.setOrWriteBuffer(&inboundBuffer)
        do {
            // Safe to bang, `setOrWrite` above means there will
            // always be a value.
            let action = try self.state.receiveBuffer(&self.inboundBuffer!)
            try self.handleAction(action, context: context)
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if self.state.proxyEstablished && self.bufferedWrites.count == 0 {
            context.write(data, promise: promise)
        } else {
            self.bufferedWrites.append((data, promise))
        }
    }

    private func writeBufferedData(context: ChannelHandlerContext) {
        guard self.state.proxyEstablished else {
            return
        }
        while self.bufferedWrites.hasMark {
            let (data, promise) = self.bufferedWrites.removeFirst()
            context.write(data, promise: promise)
        }
        context.flush()  // safe to flush otherwise we wouldn't have the mark

        while !self.bufferedWrites.isEmpty {
            let (data, promise) = self.bufferedWrites.removeFirst()
            context.write(data, promise: promise)
        }
    }

    public func flush(context: ChannelHandlerContext) {
        self.bufferedWrites.mark()
        self.writeBufferedData(context: context)
    }
}

@available(*, unavailable)
extension SOCKSClientHandler: Sendable {}

extension SOCKSClientHandler {

    private func beginHandshake(context: ChannelHandlerContext) {
        guard context.channel.isActive, self.state.shouldBeginHandshake else {
            return
        }
        do {
            try self.handleAction(self.state.connectionEstablished(), context: context)
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }

    private func handleAction(_ action: ClientAction, context: ChannelHandlerContext) throws {
        switch action {
        case .waitForMoreData:
            break  // do nothing, we've already buffered the data
        case .sendGreeting:
            try self.handleActionSendClientGreeting(context: context)
        case .sendAuthentication:
            try self.handleActionSendAuthentication(context: context)
        case .sendRequest:
            try self.handleActionSendRequest(context: context)
        case .proxyEstablished:
            self.handleProxyEstablished(context: context)
        }
    }

    private func handleActionSendClientGreeting(context: ChannelHandlerContext) throws {
        let methods: [AuthenticationMethod]
        
        if self.username != nil && self.password != nil {
            // Support both username/password and no authentication
            methods = [.usernamePassword, .noneRequired]
        } else {
            // No authentication only
            methods = [.noneRequired]
        }
        
        let greeting = ClientGreeting(methods: methods)
        let capacity = 2 + methods.count  // [version, #methods, methods...]
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientGreeting(greeting)
        try self.state.sendClientGreeting(greeting)
        context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
    }

    private func handleProxyEstablished(context: ChannelHandlerContext) {
        // Get the server response from the state machine
        guard let response = self.state.activeResponse else {
            // This should never happen as we're only in this method when the state is active
            preconditionFailure("SOCKS proxy established but no server response available")
        }
        
        // Create the event with the bound address and command type from the server response
        let event = SOCKSProxyEstablishedEvent(boundAddress: response.boundAddress, command: self.commandType)
        context.fireUserInboundEventTriggered(event)

        self.emptyInboundAndOutboundBuffer(context: context)

        if let removalToken = self.removalToken {
            context.leavePipeline(removalToken: removalToken)
        }
    }

    private func handleActionSendRequest(context: ChannelHandlerContext) throws {
        let request = SOCKSRequest(command: self.commandType, addressType: self.targetAddress)
        try self.state.sendClientRequest(request)

        // the client request is always 6 bytes + the address info
        // [protocol_version, command, reserved, address type, <address>, port (2bytes)]
        let capacity = 6 + self.targetAddress.size
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientRequest(request)
        context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
    }

    private func handleActionSendAuthentication(context: ChannelHandlerContext) throws {
        guard let username = self.username, let password = self.password else {
            throw SOCKSError.AuthenticationFailed()
        }
        
        // Format per RFC 1929:
        // +----+------+----------+------+----------+
        // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
        // +----+------+----------+------+----------+
        // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
        // +----+------+----------+------+----------+
        
        let usernameBytes = username.utf8
        let passwordBytes = password.utf8
        
        guard usernameBytes.count <= 255, passwordBytes.count <= 255 else {
            throw SOCKSError.AuthenticationFailed()
        }
        
        let capacity = 3 + usernameBytes.count + passwordBytes.count
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        
        // VER = 0x01 for username/password auth
        buffer.writeInteger(UInt8(0x01))
        // ULEN - username length
        buffer.writeInteger(UInt8(usernameBytes.count))
        // UNAME - username
        buffer.writeBytes(usernameBytes)
        // PLEN - password length
        buffer.writeInteger(UInt8(passwordBytes.count))
        // PASSWD - password
        buffer.writeBytes(passwordBytes)
        
        try self.state.sendUsernamePasswordAuth(username, password)
        context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
    }

    private func emptyInboundAndOutboundBuffer(context: ChannelHandlerContext) {
        if let inboundBuffer = self.inboundBuffer, inboundBuffer.readableBytes > 0 {
            // after the SOCKS handshake message we already received further bytes.
            // so let's send them down the pipe
            self.inboundBuffer = nil
            context.fireChannelRead(self.wrapInboundOut(inboundBuffer))
        }

        // If we have any buffered writes, we must send them before we are removed from the pipeline
        self.writeBufferedData(context: context)
    }
}

extension SOCKSClientHandler: RemovableChannelHandler {

    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        guard self.state.proxyEstablished else {
            self.removalToken = removalToken
            return
        }

        // We must clear the buffers here before we are removed, since the
        // handler removal may be triggered as a side effect of the
        // `SOCKSProxyEstablishedEvent`. In this case we may end up here,
        // before the buffer empty method in `handleProxyEstablished` is
        // invoked.
        self.emptyInboundAndOutboundBuffer(context: context)
        context.leavePipeline(removalToken: removalToken)
    }

}

/// A `Channel` user event that is sent when a SOCKS connection has been established
///
/// After this event has been received it is safe to remove the `SOCKSClientHandler` from the channel pipeline.
/// For UDP ASSOCIATE mode, the `boundAddress` field contains the address the client should use for sending
/// UDP datagrams through the proxy.
public struct SOCKSProxyEstablishedEvent: Sendable {
    /// The address that the SOCKS server is bound to and listening on
    /// This is particularly important for UDP ASSOCIATE mode where clients must
    /// send datagrams to this address.
    public let boundAddress: SOCKSAddress
    
    /// The command type that was used for this connection
    public let command: SOCKSCommand
    
    /// Creates a new SOCKS proxy established event
    public init(boundAddress: SOCKSAddress, command: SOCKSCommand) {
        self.boundAddress = boundAddress
        self.command = command
    }
}

extension SOCKSClientHandler {
    /// Creates a new ``SOCKSClientHandler`` that connects to a server
    /// and instructs the server to establish a TCP connection to `targetAddress`.
    /// - parameter targetAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    /// - parameter username: The username to use for authentication, if needed.
    /// - parameter password: The password to use for authentication, if needed.
    public static func tcpConnection(to targetAddress: SOCKSAddress, username: String? = nil, password: String? = nil) -> SOCKSClientHandler {
        return SOCKSClientHandler(targetAddress: targetAddress, username: username, password: password, command: .connect)
    }
    
    /// Creates a new ``SOCKSClientHandler`` that connects to a server
    /// and instructs the server to establish a UDP association for relaying datagrams.
    /// - parameter targetAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    /// - parameter username: The username to use for authentication, if needed.
    /// - parameter password: The password to use for authentication, if needed.
    public static func udpAssociation(to targetAddress: SOCKSAddress, username: String? = nil, password: String? = nil) -> SOCKSClientHandler {
        return SOCKSClientHandler(targetAddress: targetAddress, username: username, password: password, command: .udpAssociate)
    }
}

// MARK: UDP Association Handling Guide
/*
UDP association with SOCKS5 proxies is slightly more complex than TCP connections:

1. When using UDP ASSOCIATE, the client sends a UDP ASSOCIATE request to the SOCKS server
   over a TCP control connection.

2. The SOCKS server responds with:
   - A reply code (0x00 for success)
   - A bound address (IP and port) that the client should use to send UDP datagrams

3. This handler captures the bound address from the SOCKS server response and makes it available
   through the SOCKSProxyEstablishedEvent.

4. When sending UDP datagrams through the proxy, they must be wrapped in a special format:
   +----+------+------+----------+----------+----------+
   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
   +----+------+------+----------+----------+----------+
   | 2  |  1   |  1   | Variable |    2     | Variable |
   +----+------+------+----------+----------+----------+

5. The client must maintain the TCP control connection to the SOCKS server for as long as
   the UDP association is needed. If the TCP connection is closed, the UDP association is
   terminated by the SOCKS server.

For more details, see RFC 1928 section 7 "Procedure for UDP-based clients".
*/
