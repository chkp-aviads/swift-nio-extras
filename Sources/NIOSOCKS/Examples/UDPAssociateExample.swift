//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// MARK: - This file is for documentation purposes only and is not included in the build.

import NIOCore
import NIOPosix

/// Example of using UDP ASSOCIATE mode with SOCKS5 proxy
/// 
/// This example demonstrates how to:
/// 1. Establish a SOCKS5 proxy connection with UDP ASSOCIATE command
/// 2. Handle the UDP relay process
/// 3. Format and send UDP datagrams through a SOCKS5 proxy
///
/// For UDP ASSOCIATE to work correctly:
/// 1. The TCP control connection must remain open as long as UDP traffic is needed
/// 2. The bound address from the SOCKS server must be extracted from the SOCKSProxyEstablishedEvent
/// 3. UDP datagrams must be properly encapsulated according to the SOCKS5 specification
/// 
/// Note: This is a simplified example for illustration purposes.
/// In a real application, you would need to handle more edge cases.
final class UDPAssociateExample : Sendable {

    // Step 1: Create the control channel (TCP connection to SOCKS proxy)
    private func createControlChannel(to proxyAddress: SocketAddress) -> EventLoopFuture<Channel> {
        let bootstrap = ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                return channel.eventLoop.submit {
                    // The target address can be any address - for UDP ASSOCIATE it's often 0.0.0.0:0
                    // The proxy server will reply with the actual address to use
                    let socksHandler = SOCKSClientHandler.udpAssociation(
                        to: .address(try! SocketAddress(ipAddress: "0.0.0.0", port: 0))
                    )
                    
                    // We need to wait for the proxy to be established before proceeding
                    let proxyEstablishedPromise = channel.eventLoop.makePromise(of: SOCKSProxyEstablishedEvent.self)
                    try channel.pipeline.syncOperations.addHandler(socksHandler)
                    try channel.pipeline.syncOperations.addHandler(ProxyEstablishedHandler(promise: proxyEstablishedPromise))
                }
            }
        
        return bootstrap.connect(to: proxyAddress).flatMap { channel -> EventLoopFuture<Channel> in
            // Get the handler we added in channelInitializer that contains the promise
            let handler = try! channel.pipeline.syncOperations.handler(type: ProxyEstablishedHandler.self)
            
            // Wait for the proxy to be established
            return handler.promise.futureResult.map { _ in
                return channel
            }
        }
    }
    
    // Step 2: Create the UDP channel for sending/receiving datagrams
    private func createUDPChannel(proxyBoundAddress: SocketAddress) -> EventLoopFuture<Channel> {
        let bootstrap = DatagramBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                channel.pipeline.addHandler(SOCKSUDPEncapsulationHandler(proxyBoundAddress: proxyBoundAddress))
            }
        
        // Bind to any available local port
        return bootstrap.bind(host: "0.0.0.0", port: 0)
    }
    
    // Main function to demonstrate the UDP ASSOCIATE workflow
    func runExample() {
        let proxyAddress = try! SocketAddress(ipAddress: "127.0.0.1", port: 1080)
        let targetAddress = try! SocketAddress(ipAddress: "8.8.8.8", port: 53) // DNS server
        
        // First, create the control channel (TCP connection to the SOCKS proxy)
        createControlChannel(to: proxyAddress).flatMap { controlChannel -> EventLoopFuture<(Channel, Channel)> in
            // Keep the control channel active - if it's closed, the UDP association is terminated
            
            // Get the SOCKSProxyEstablishedEvent to know the bound address
            let handler = try! controlChannel.pipeline.syncOperations.handler(type: ProxyEstablishedHandler.self)
            let event = handler.event!
            
            // Extract the socket address from the SOCKSAddress in the event
            // For UDP ASSOCIATE, the SOCKS server returns a bound address that the client
            // must use to send UDP datagrams. This address is crucial for the UDP association to work.
            // RFC 1928 section 6: "In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
            // fields indicate the port number/address where the client must send UDP request messages
            // to be relayed."
            guard case .address(let socketAddress) = event.boundAddress else {
                return controlChannel.eventLoop.makeFailedFuture(
                    UDPAssociateError.invalidProxyResponse(message: "SOCKS server returned non-socket address for UDP ASSOCIATE")
                )
            }
            
            // Now create the UDP channel for sending/receiving datagrams
            return self.createUDPChannel(proxyBoundAddress: socketAddress).map { udpChannel in
                return (controlChannel, udpChannel)
            }
        }.whenComplete { result in
            switch result {
            case .success(let (controlChannel, udpChannel)):
                // Now we can send UDP datagrams through the proxy
                // The SOCKSUDPEncapsulationHandler will handle encapsulation
                
                // Example: Send a DNS query
                var buffer = ByteBuffer()
                buffer.writeString("DNS query data would go here")
                
                // Send the datagram to the target through the proxy
                // The SOCKSUDPEncapsulationHandler will handle the encapsulation
                udpChannel.writeAndFlush(AddressedEnvelope(remoteAddress: targetAddress, data: buffer), promise: nil)
                
                // In a real application, we would also set up a handler to receive responses
                
                // Keep the application running (in a real app you would manage this differently)
                sleep(10)
                
                // Clean up
                udpChannel.close(promise: nil)
                controlChannel.close(promise: nil)
                
            case .failure(let error):
                print("Error: \(error)")
            }
        }
    }
}

// Helper handler to receive and store the SOCKSProxyEstablishedEvent
private class ProxyEstablishedHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    
    let promise: EventLoopPromise<SOCKSProxyEstablishedEvent>
    var event: SOCKSProxyEstablishedEvent?
    
    init(promise: EventLoopPromise<SOCKSProxyEstablishedEvent>) {
        self.promise = promise
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? SOCKSProxyEstablishedEvent {
            self.event = event
            promise.succeed(event)
        }
        context.fireUserInboundEventTriggered(event)
    }
}

// Handler to encapsulate UDP datagrams in the SOCKS5 UDP format
private final class SOCKSUDPEncapsulationHandler: ChannelDuplexHandler, Sendable {
    typealias InboundIn = AddressedEnvelope<ByteBuffer>
    typealias InboundOut = AddressedEnvelope<ByteBuffer>
    typealias OutboundIn = AddressedEnvelope<ByteBuffer>
    typealias OutboundOut = AddressedEnvelope<ByteBuffer>
    
    private let proxyBoundAddress: SocketAddress
    
    init(proxyBoundAddress: SocketAddress) {
        self.proxyBoundAddress = proxyBoundAddress
    }
    
    // When sending data, encapsulate it in the SOCKS5 UDP format
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let envelope = self.unwrapOutboundIn(data)
        let originalData = envelope.data
        
        // Create a new buffer for the encapsulated datagram
        var buffer = context.channel.allocator.buffer(capacity: originalData.readableBytes + 10)
        
        // SOCKS5 UDP datagram format:
        // +----+------+------+----------+----------+----------+
        // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
        // +----+------+------+----------+----------+----------+
        // | 2  |  1   |  1   | Variable |    2     | Variable |
        // +----+------+------+----------+----------+----------+
        
        // RSV: 2 reserved bytes (must be 0)
        buffer.writeInteger(UInt16(0))
        
        // FRAG: Fragment number (0 for unfragmented datagrams)
        buffer.writeInteger(UInt8(0))
        
        // ATYP: Address type + DST.ADDR + DST.PORT
        let socketAddress = envelope.remoteAddress
        switch socketAddress {
        case .v4(let addr):
            // IPv4 address type (0x01)
            buffer.writeInteger(UInt8(1))
            // IPv4 address (4 bytes)
            _ = withUnsafeBytes(of: addr.address.sin_addr) { pointer in
                buffer.writeBytes(pointer)
            }
            // Port (2 bytes)
            buffer.writeInteger(UInt16(bigEndian: addr.address.sin_port))
            
        case .v6(let addr):
            // IPv6 address type (0x04)
            buffer.writeInteger(UInt8(4))
            // IPv6 address (16 bytes)
            _ = withUnsafeBytes(of: addr.address.sin6_addr) { pointer in
                buffer.writeBytes(pointer)
            }
            // Port (2 bytes)
            buffer.writeInteger(UInt16(bigEndian: addr.address.sin6_port))
            
        case .unixDomainSocket:
            fatalError("Unix domain sockets are not supported for SOCKS")
        }
        
        // DATA: Original datagram data
        buffer.writeBytes(originalData.readableBytesView)
        
        // Create a new envelope with the proxy's bound address and the encapsulated data
        // This address is extracted from the SOCKSProxyEstablishedEvent and passed during initialization
        let newEnvelope = AddressedEnvelope(remoteAddress: proxyBoundAddress, data: buffer)
        
        context.write(self.wrapOutboundOut(newEnvelope), promise: promise)
    }
    
    // When receiving data, extract the actual data from the SOCKS5 UDP format
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let envelope = self.unwrapInboundIn(data)
        var buffer = envelope.data
        
        // Skip RSV (2 bytes)
        _ = buffer.readInteger(as: UInt16.self)
        
        // Skip FRAG (1 byte)
        _ = buffer.readInteger(as: UInt8.self)
        
        // Read ATYP (1 byte)
        guard let atyp = buffer.readInteger(as: UInt8.self) else {
            return // Malformed packet
        }
        
        // Skip DST.ADDR (variable length based on ATYP)
        switch atyp {
        case 1: // IPv4
            _ = buffer.readSlice(length: 4) // Skip 4 bytes IPv4 address
        case 3: // Domain name
            if let length = buffer.readInteger(as: UInt8.self) {
                _ = buffer.readSlice(length: Int(length)) // Skip domain name
            } else {
                return // Malformed packet
            }
        case 4: // IPv6
            _ = buffer.readSlice(length: 16) // Skip 16 bytes IPv6 address
        default:
            return // Unknown address type
        }
        
        // Skip DST.PORT (2 bytes)
        _ = buffer.readInteger(as: UInt16.self)
        
        // The remaining buffer is the actual datagram data
        let originalData = buffer
        
        // Create a new envelope with the original data
        // In a real implementation, you would extract the destination from the SOCKS header
        let newEnvelope = AddressedEnvelope(remoteAddress: envelope.remoteAddress, data: originalData)
        
        context.fireChannelRead(self.wrapInboundOut(newEnvelope))
    }
}

// MARK: - Error types specific to UDP ASSOCIATE

/// Error types specific to UDP ASSOCIATE operation
public enum UDPAssociateError: Error, CustomStringConvertible {
    /// The proxy response was invalid for UDP ASSOCIATE operation
    case invalidProxyResponse(message: String)
    
    public var description: String {
        switch self {
        case .invalidProxyResponse(let message):
            return "Invalid proxy response: \(message)"
        }
    }
}
