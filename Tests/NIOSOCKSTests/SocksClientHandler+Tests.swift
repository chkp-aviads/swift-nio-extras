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

class SocksClientHandlerTests: XCTestCase {

    var channel: EmbeddedChannel!
    var handler: SOCKSClientHandler!

    override func setUp() {
        XCTAssertNil(self.channel)
        self.handler = SOCKSClientHandler(targetAddress: .address(try! .init(ipAddress: "192.168.1.1", port: 80)))
        self.channel = EmbeddedChannel(handler: self.handler)
    }

    func connect() {
        try! self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
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

    func testTypicalWorkflow() {

        let clientHandler = MockSOCKSClientHandler()
        XCTAssertNoThrow(try self.channel.pipeline.syncOperations.addHandler(clientHandler))

        self.connect()

        // the client should start the handshake instantly
        self.assertOutputBuffer([0x05, 0x01, 0x00])

        // server selects an authentication method
        self.writeInbound([0x05, 0x00])

        // client sends the request
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        // server replies yay
        XCTAssertFalse(clientHandler.hadSOCKSEstablishedProxyUserEvent)
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        XCTAssertTrue(clientHandler.hadSOCKSEstablishedProxyUserEvent)

        // any inbound data should now go straight through
        self.writeInbound([1, 2, 3, 4, 5])
        self.assertInbound([1, 2, 3, 4, 5])

        // any outbound data should also go straight through
        XCTAssertNoThrow(try self.channel.writeOutbound(ByteBuffer(bytes: [1, 2, 3, 4, 5])))
        self.assertOutputBuffer([1, 2, 3, 4, 5])
    }

    // Tests that if we write alot of data at the start then
    // that data will be written after the client has completed
    // the socks handshake.
    func testThatBufferingWorks() {
        self.connect()

        let writePromise = self.channel.eventLoop.makePromise(of: Void.self)
        self.channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3, 4, 5]), promise: writePromise)
        self.assertOutputBuffer([0x05, 0x01, 0x00])
        self.writeInbound([0x05, 0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        XCTAssertNoThrow(try writePromise.futureResult.wait())
        self.assertOutputBuffer([1, 2, 3, 4, 5])
    }

    func testBufferingWithMark() {
        self.connect()

        let writePromise1 = self.channel.eventLoop.makePromise(of: Void.self)
        let writePromise2 = self.channel.eventLoop.makePromise(of: Void.self)
        self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise1)
        self.channel.flush()
        self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: writePromise2)

        self.assertOutputBuffer([0x05, 0x01, 0x00])
        self.writeInbound([0x05, 0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        XCTAssertNoThrow(try writePromise1.futureResult.wait())
        self.assertOutputBuffer([1, 2, 3])

        XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())
        XCTAssertNoThrow(try writePromise2.futureResult.wait())
        self.assertOutputBuffer([4, 5, 6])
        self.assertOutputBuffer([7, 8, 9])
    }

    func testTypicalWorkflowDripfeed() {
        self.connect()

        // the client should start the handshake instantly
        self.assertOutputBuffer([0x05, 0x01, 0x00])

        // server selects authentication method
        // once the dripfeed is complete we should get the client request
        self.writeInbound([0x05])
        self.assertOutputBuffer([])
        self.writeInbound([0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        // drip feed server response
        self.writeInbound([0x05, 0x00, 0x00, 0x01])
        self.assertOutputBuffer([])
        self.writeInbound([192, 168])
        self.assertOutputBuffer([])
        self.writeInbound([1, 1])
        self.assertOutputBuffer([])
        self.writeInbound([0x00, 0x50])

        // any inbound data should now go straight through
        self.writeInbound([1, 2, 3, 4, 5])
        self.assertInbound([1, 2, 3, 4, 5])
    }

    func testInvalidAuthenticationMethod() {
        self.connect()

        class ErrorHandler: ChannelInboundHandler {
            typealias InboundIn = ByteBuffer

            var promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func errorCaught(context: ChannelHandlerContext, error: Error) {
                promise.fail(error)
            }
        }

        self.assertOutputBuffer([0x05, 0x01, 0x00])

        // server requests an auth method we don't support
        let promise = self.channel.eventLoop.makePromise(of: Void.self)
        try! self.channel.pipeline.syncOperations.addHandler(ErrorHandler(promise: promise), position: .last)
        self.writeInbound([0x05, 0x01])
        XCTAssertThrowsError(try promise.futureResult.wait()) { e in
            XCTAssertTrue(e is SOCKSError.InvalidAuthenticationSelection)
        }
    }

    func testProxyConnectionFailed() {
        self.connect()

        class ErrorHandler: ChannelInboundHandler {
            typealias InboundIn = ByteBuffer

            var promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func errorCaught(context: ChannelHandlerContext, error: Error) {
                promise.fail(error)
            }
        }

        // start handshake, send request
        self.assertOutputBuffer([0x05, 0x01, 0x00])
        self.writeInbound([0x05, 0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        // server replies with an error
        let promise = self.channel.eventLoop.makePromise(of: Void.self)
        try! self.channel.pipeline.syncOperations.addHandler(ErrorHandler(promise: promise), position: .last)
        self.writeInbound([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        XCTAssertThrowsError(try promise.futureResult.wait()) { e in
            XCTAssertEqual(e as? SOCKSError.ConnectionFailed, .init(reply: .serverFailure))
        }
    }

    func testDelayedConnection() {
        // we shouldn't start the handshake until the client
        // has connected
        self.assertOutputBuffer([])

        self.connect()

        // now the handshake should have started
        self.assertOutputBuffer([0x05, 0x01, 0x00])
    }

    func testDelayedHandlerAdded() {

        // reset the channel that was set up automatically
        XCTAssertNoThrow(try self.channel.close().wait())
        self.channel = EmbeddedChannel()
        self.handler = SOCKSClientHandler(targetAddress: .domain("127.0.0.1", port: 1234))
        XCTAssertNoThrow(try self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait())
        XCTAssertTrue(self.channel.isActive)

        // there shouldn't be anything outbound
        self.assertOutputBuffer([])

        // add the handler, there should be outbound data immediately
        XCTAssertNoThrow(try self.channel.pipeline.syncOperations.addHandler(handler))
        self.assertOutputBuffer([0x05, 0x01, 0x00])
    }

    func testHandlerRemovalAfterEstablishEvent() {
        class SOCKSEventHandler: ChannelInboundHandler {
            typealias InboundIn = NIOAny

            var establishedPromise: EventLoopPromise<Void>

            init(establishedPromise: EventLoopPromise<Void>) {
                self.establishedPromise = establishedPromise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                switch event {
                case is SOCKSProxyEstablishedEvent:
                    self.establishedPromise.succeed(())
                default:
                    break
                }
                context.fireUserInboundEventTriggered(event)
            }
        }

        let establishPromise = self.channel.eventLoop.makePromise(of: Void.self)
        let removalPromise = self.channel.eventLoop.makePromise(of: Void.self)
        establishPromise.futureResult.assumeIsolated().whenSuccess { _ in
            self.channel.pipeline.syncOperations.removeHandler(self.handler).cascade(to: removalPromise)
        }

        XCTAssertNoThrow(
            try self.channel.pipeline.syncOperations.addHandler(SOCKSEventHandler(establishedPromise: establishPromise))
        )

        self.connect()

        // these writes should be buffered to be send out once the connection is established.
        self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
        self.channel.flush()
        self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

        self.assertOutputBuffer([0x05, 0x01, 0x00])
        self.writeInbound([0x05, 0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        self.assertOutputBuffer([1, 2, 3])

        XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())

        self.assertOutputBuffer([4, 5, 6])
        self.assertOutputBuffer([7, 8, 9])

        XCTAssertNoThrow(try removalPromise.futureResult.wait())
        XCTAssertThrowsError(try self.channel.pipeline.syncOperations.handler(type: SOCKSClientHandler.self)) {
            XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
        }
    }

    func testHandlerRemovalBeforeConnectionIsEstablished() {
        self.connect()

        // these writes should be buffered to be send out once the connection is established.
        self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
        self.channel.flush()
        self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

        self.assertOutputBuffer([0x05, 0x01, 0x00])
        self.writeInbound([0x05, 0x00])
        self.assertOutputBuffer([0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        // we try to remove the handler before the connection is established.
        let removalPromise = self.channel.eventLoop.makePromise(of: Void.self)
        self.channel.pipeline.syncOperations.removeHandler(self.handler, promise: removalPromise)

        // establishes the connection
        self.writeInbound([0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])

        // write six more bytes - those should be passed through right away
        self.writeInbound([1, 2, 3, 4, 5, 6])
        self.assertInbound([1, 2, 3, 4, 5, 6])

        self.assertOutputBuffer([1, 2, 3])

        XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())

        self.assertOutputBuffer([4, 5, 6])
        self.assertOutputBuffer([7, 8, 9])

        XCTAssertNoThrow(try removalPromise.futureResult.wait())
        XCTAssertThrowsError(try self.channel.pipeline.syncOperations.handler(type: SOCKSClientHandler.self)) {
            XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
        }
    }
    
    func testUsernamePasswordAuthentication() throws {
        let authHandler = SOCKSClientHandler(targetAddress: .address(try! .init(ipAddress: "192.168.1.1", port: 80)),
                                           username: "testuser", 
                                           password: "testpass")
        let authChannel = EmbeddedChannel(handler: authHandler)

        // Activate the channel to start the handshake
        try authChannel.connect(to: .init(ipAddress: "127.0.0.1", port: 1080)).wait()

        // The handler should send a greeting including usernamePassword method
        if let greeting = try authChannel.readOutbound(as: ByteBuffer.self) {
            XCTAssertEqual(greeting.readableBytes, 4) // 1 version + 1 method count + 2 methods
            XCTAssertEqual(greeting.getInteger(at: 0, as: UInt8.self), 5) // version
            XCTAssertEqual(greeting.getInteger(at: 1, as: UInt8.self), 2) // two methods
            XCTAssertEqual(greeting.getInteger(at: 2, as: UInt8.self), 2) // usernamePassword method
            XCTAssertEqual(greeting.getInteger(at: 3, as: UInt8.self), 0) // noneRequired method
        } else {
            XCTFail("No greeting sent")
        }

        // Server selects username/password auth
        var serverSelection = ByteBuffer()
        serverSelection.writeInteger(UInt8(5)) // version
        serverSelection.writeInteger(UInt8(2)) // username/password method
        try authChannel.writeInbound(serverSelection)

        // Client should send auth data
        if let authData = try authChannel.readOutbound(as: ByteBuffer.self) {
            XCTAssertEqual(authData.readableBytes, 1 + 1 + 8 + 1 + 8) // ver + ulen + username + plen + password
            XCTAssertEqual(authData.getInteger(at: 0, as: UInt8.self), 1) // auth version
            XCTAssertEqual(authData.getInteger(at: 1, as: UInt8.self), 8) // username length
            
            let username = authData.getString(at: 2, length: 8)
            XCTAssertEqual(username, "testuser")
            
            XCTAssertEqual(authData.getInteger(at: 10, as: UInt8.self), 8) // password length
            
            let password = authData.getString(at: 11, length: 8)
            XCTAssertEqual(password, "testpass")
        } else {
            XCTFail("No auth data sent")
        }

        // Server accepts authentication
        var serverAuthResponse = ByteBuffer()
        serverAuthResponse.writeInteger(UInt8(1)) // auth version
        serverAuthResponse.writeInteger(UInt8(0)) // status OK
        try authChannel.writeInbound(serverAuthResponse)

        // Client should send SOCKS request
        if let request = try authChannel.readOutbound(as: ByteBuffer.self) {
            XCTAssertEqual(request.readableBytes, 10) // ver + cmd + rsv + atyp + addr + port
            XCTAssertEqual(request.getInteger(at: 0, as: UInt8.self), 5) // version
            XCTAssertEqual(request.getInteger(at: 1, as: UInt8.self), 1) // connect command
            XCTAssertEqual(request.getInteger(at: 2, as: UInt8.self), 0) // reserved
            XCTAssertEqual(request.getInteger(at: 3, as: UInt8.self), 1) // IPv4 address type
        } else {
            XCTFail("No request sent")
        }

        // Server sends successful response
        var serverResponse = ByteBuffer()
        serverResponse.writeInteger(UInt8(5)) // version
        serverResponse.writeInteger(UInt8(0)) // success
        serverResponse.writeInteger(UInt8(0)) // reserved
        serverResponse.writeInteger(UInt8(1)) // IPv4 address type
        
        // IP address 192.168.1.1
        serverResponse.writeInteger(UInt8(192))
        serverResponse.writeInteger(UInt8(168))
        serverResponse.writeInteger(UInt8(1))
        serverResponse.writeInteger(UInt8(1))
        
        // Port 80
        serverResponse.writeInteger(UInt16(80).bigEndian)
        
        try authChannel.writeInbound(serverResponse)

        // Trigger an event
        var testBuffer = ByteBuffer()
        testBuffer.writeString("Hello")
        try authChannel.writeOutbound(testBuffer)
        
        if let writtenData = try authChannel.readOutbound(as: ByteBuffer.self) {
            XCTAssertEqual(writtenData.getString(at: 0, length: 5), "Hello")
        } else {
            XCTFail("No data sent")
        }
    }
}

class MockSOCKSClientHandler: ChannelInboundHandler {
    typealias InboundIn = NIOAny

    var hadSOCKSEstablishedProxyUserEvent: Bool = false

    init() {}

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is SOCKSProxyEstablishedEvent:
            self.hadSOCKSEstablishedProxyUserEvent = true
        default:
            break
        }
        context.fireUserInboundEventTriggered(event)
    }
}
