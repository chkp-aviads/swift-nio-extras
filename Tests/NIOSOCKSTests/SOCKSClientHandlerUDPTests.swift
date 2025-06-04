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
import NIOEmbedded
import XCTest

@testable import NIOSOCKS

class SOCKSClientHandlerUDPTests: XCTestCase {

    var channel: EmbeddedChannel!
    var handler: SOCKSClientHandler!

    override func setUp() {
        XCTAssertNil(self.channel)
        self.handler = SOCKSClientHandler.udpAssociation(to: .address(try! .init(ipAddress: "192.168.1.1", port: 1080)))
        self.channel = EmbeddedChannel(handler: self.handler)
    }

    func connect() {
        try! self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 1080)).wait()
    }

    override func tearDown() {
        XCTAssertNotNil(self.channel)
        self.channel = nil
    }

    func assertOutputBuffer(_ bytes: [UInt8], line: UInt = #line) {
        if var buffer = try! self.channel.readOutbound(as: ByteBuffer.self) {
            XCTAssertEqual(buffer.readBytes(length: buffer.readableBytes), bytes, line: line)
        } else if bytes.count > 0 {
            XCTFail("Expected bytes but found none")
        }
    }

    func writeInbound(_ bytes: [UInt8], line: UInt = #line) {
        try! self.channel.writeInbound(ByteBuffer(bytes: bytes))
    }

    func assertInbound(_ bytes: [UInt8], line: UInt = #line) {
        var buffer = try! self.channel.readInbound(as: ByteBuffer.self)
        XCTAssertEqual(buffer!.readBytes(length: buffer!.readableBytes), bytes, line: line)
    }

    func testUDPAssociateHandshake() {
        let clientHandler = UDPMockSOCKSClientHandler()
        XCTAssertNoThrow(try self.channel.pipeline.syncOperations.addHandler(clientHandler))

        self.connect()

        // The client should start the handshake instantly (same as TCP)
        self.assertOutputBuffer([0x05, 0x01, 0x00])

        // Server selects an authentication method
        self.writeInbound([0x05, 0x00])

        // Client sends the UDP ASSOCIATE request (command 0x03 instead of 0x01)
        // Note: In UDP ASSOCIATE, the address is typically the client's address or 0.0.0.0
        self.assertOutputBuffer([0x05, 0x03, 0x00, 0x01, 192, 168, 1, 1, 0x04, 0x38])

        // Server replies with a success and provides its bound address
        // Using a different bound address (10.0.0.1:8080) to ensure it's captured correctly
        XCTAssertFalse(clientHandler.hadSOCKSEstablishedProxyUserEvent)
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90]) // 10.0.0.1:8080
        XCTAssertTrue(clientHandler.hadSOCKSEstablishedProxyUserEvent)
        
        // Verify the SOCKSProxyEstablishedEvent contains the correct bound address and command
        XCTAssertEqual(clientHandler.lastProxyEstablishedEvent?.command, .udpAssociate)
        if case .address(let socketAddress) = clientHandler.lastProxyEstablishedEvent?.boundAddress {
            XCTAssertEqual(socketAddress.ipAddress, "10.0.0.1")
            XCTAssertEqual(socketAddress.port, 8080)
        } else {
            XCTFail("Expected a socket address in the established event")
        }

        // For UDP, the TCP connection should be maintained while data flows through UDP
        // Any inbound data should now go straight through the TCP connection
        self.writeInbound([1, 2, 3, 4, 5])
        self.assertInbound([1, 2, 3, 4, 5])

        // Any outbound data should also go straight through
        XCTAssertNoThrow(try self.channel.writeOutbound(ByteBuffer(bytes: [1, 2, 3, 4, 5])))
        self.assertOutputBuffer([1, 2, 3, 4, 5])
    }
}

// Helper class to check if SOCKSProxyEstablishedEvent is fired
class UDPMockSOCKSClientHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer
    
    var hadSOCKSEstablishedProxyUserEvent = false
    var lastProxyEstablishedEvent: SOCKSProxyEstablishedEvent?
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? SOCKSProxyEstablishedEvent {
            self.hadSOCKSEstablishedProxyUserEvent = true
            self.lastProxyEstablishedEvent = event
        }
        context.fireUserInboundEventTriggered(event)
    }
}
