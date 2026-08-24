//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Logging
import NIOCore

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Wraps a connected channel so that everything above this handler sees plaintext and everything
/// below it sees a Shadowsocks 2022 stream.
///
/// Placed closest to the network, with the relay (`GlueHandler`) above it: inbound is decrypted
/// before the glue sees it, outbound is encrypted after the glue writes it.
public final class ShadowsocksClientHandler: ChannelDuplexHandler, RemovableChannelHandler, @unchecked Sendable {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// SIP022 length chunks are two bytes, so a payload chunk caps out at 0xFFFF — note this is the
    /// 2022 limit, not the 0x3FFF of the older AEAD ciphers.
    public static let maxChunkLength = Int(UInt16.max)

    private static let clientHeaderType: UInt8 = 0
    private static let serverHeaderType: UInt8 = 1

    private enum InboundState {
        /// Waiting for `salt ‖ AEAD(response header)`, which is consumed in one shot.
        case awaitingResponseHeader
        /// Waiting for a payload chunk of this plaintext length.
        case awaitingPayload(Int)
        /// Waiting for the next two-byte length chunk.
        case awaitingLength
        case failed
    }

    private let config: ShadowsocksConfiguration
    private let targetHost: String
    private let targetPort: UInt16
    private let logger: Logger

    // Outbound state.
    private var requestSalt = [UInt8]()
    private var requestSubkey: SymmetricKey?
    private var requestNonce = AEADNonceCounter()
    private var preambleSent = false

    // Inbound state.
    private var accumulator: ByteBuffer?
    private var responseSubkey: SymmetricKey?
    private var responseNonce = AEADNonceCounter()
    private var inboundState = InboundState.awaitingResponseHeader

    /// Succeeds once the server's response header authenticates, which is the only proof the PSK
    /// chain was accepted. Mirrors `SOCKSEventsHandler.socksEstablishedFuture`: created in
    /// `handlerAdded`, so it is `nil` until then.
    ///
    /// Without this the caller cannot tell a wrong PSK from an unreachable server, and SASE status
    /// reporting would show `.serviceUnreachable` for a credential problem.
    private var establishedPromise: EventLoopPromise<Void>?
    private var storedEstablishedFuture: EventLoopFuture<Void>?

    public var establishedFuture: EventLoopFuture<Void>? { storedEstablishedFuture }

    public init(config: ShadowsocksConfiguration, targetHost: String, targetPort: Int, logger: Logger) {
        self.config = config
        self.targetHost = targetHost
        self.targetPort = UInt16(targetPort)
        self.logger = logger
    }

    // MARK: - Channel lifecycle

    public func handlerAdded(context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: Void.self)
        establishedPromise = promise
        storedEstablishedFuture = promise.futureResult
        accumulator = context.channel.allocator.buffer(capacity: 0)

        // A caller that dials the server itself hands back an already-connected channel, so
        // adds handlers afterwards, so `channelActive` will never fire for us there.
        if context.channel.isActive {
            sendRequestPreamble(context: context)
        }
    }

    public func channelActive(context: ChannelHandlerContext) {
        sendRequestPreamble(context: context)
        context.fireChannelActive()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        // A stream that dies before the response header must fail the future rather than hang.
        failEstablished(with: ShadowsocksError.truncatedHeader)
        context.fireChannelInactive()
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        failEstablished(with: ShadowsocksError.truncatedHeader)
    }

    // MARK: - Outbound

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var payload = unwrapOutboundIn(data)
        guard payload.readableBytes > 0 else {
            promise?.succeed(())
            return
        }

        var out = context.channel.allocator.buffer(capacity: payload.readableBytes + 64)
        do {
            while payload.readableBytes > 0 {
                let chunkLength = min(payload.readableBytes, Self.maxChunkLength)
                guard let chunk = payload.readBytes(length: chunkLength) else { break }
                out.writeBytes(try seal(UInt16(chunkLength).shadowsocksBytes))
                out.writeBytes(try seal(chunk))
            }
        } catch {
            promise?.fail(error)
            fail(context: context, error: error)
            return
        }

        context.write(wrapOutboundOut(out), promise: promise)
    }

    /// `salt ‖ identity headers ‖ AEAD(fixed header) ‖ AEAD(variable header)`, emitted as a single
    /// write because SIP022 §3.1.3 requires it.
    private func sendRequestPreamble(context: ChannelHandlerContext) {
        guard !preambleSent else { return }
        preambleSent = true

        let method = config.method
        let salt = ShadowsocksConfiguration.randomBytes(count: method.saltSize)
        requestSalt = salt
        requestSubkey = config.sessionSubkey(salt: salt)

        // ponytail: always random padding, never folding the first payload in as initial payload.
        // The spec explicitly sanctions this ("a simple approach is to always send random length
        // padding"). It costs one extra segment plus ≤900 bytes per connection and removes the
        // timer and buffering state machine that server-first protocols (SMTP, SSH, MySQL) would
        // otherwise need to avoid deadlocking. Upgrade path: buffer the first write for ~200ms and
        // fold it in, if traffic fingerprinting becomes a concern.
        let padding = ShadowsocksConfiguration.randomPadding()
        var variableHeader = ShadowsocksConfiguration.addressBytes(host: targetHost, port: targetPort)
        variableHeader += UInt16(padding.count).shadowsocksBytes
        variableHeader += padding

        var fixedHeader = [Self.clientHeaderType]
        fixedHeader += ShadowsocksConfiguration.currentTimestamp().shadowsocksBytes
        fixedHeader += UInt16(variableHeader.count).shadowsocksBytes

        do {
            let sealedFixed = try seal(fixedHeader)
            let sealedVariable = try seal(variableHeader)

            var out = context.channel.allocator.buffer(
                capacity: salt.count + config.identityHeaderCount * ShadowsocksMethod.blockSize
                    + sealedFixed.count + sealedVariable.count
            )
            out.writeBytes(salt)
            out.writeBytes(try config.tcpIdentityHeaders(salt: salt))
            out.writeBytes(sealedFixed)
            out.writeBytes(sealedVariable)

            context.writeAndFlush(wrapOutboundOut(out), promise: nil)
        } catch {
            fail(context: context, error: error)
        }
    }

    private func seal(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let requestSubkey else { throw ShadowsocksError.truncatedHeader }
        let nonce = try requestNonce.next()
        let box = try AES.GCM.seal(plaintext, using: requestSubkey, nonce: nonce)
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }

    // MARK: - Inbound

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .failed = inboundState { return }

        var incoming = unwrapInboundIn(data)
        accumulator?.writeBuffer(&incoming)

        do {
            while try decodeInbound(context: context) {}
        } catch {
            fail(context: context, error: error)
            return
        }

        // Keeps the accumulator from growing without bound on a long-lived stream.
        accumulator?.discardReadBytes()
    }

    /// Decodes as much as is available. Returns `false` when more bytes are needed, so a peer
    /// dribbling one byte at a time can never desynchronize the stream: nothing is consumed until a
    /// whole chunk has arrived.
    private func decodeInbound(context: ChannelHandlerContext) throws -> Bool {
        guard var buffer = accumulator else { return false }
        defer { accumulator = buffer }

        let method = config.method
        let tagSize = ShadowsocksMethod.tagSize

        switch inboundState {
        case .failed:
            return false

        case .awaitingResponseHeader:
            let needed = method.saltSize + method.responseHeaderSize + tagSize
            guard buffer.readableBytes >= needed else { return false }

            guard let salt = buffer.readBytes(length: method.saltSize) else { return false }
            responseSubkey = config.sessionSubkey(salt: salt)
            responseNonce = AEADNonceCounter()

            guard let sealed = buffer.readBytes(length: method.responseHeaderSize + tagSize) else {
                return false
            }
            let header = try open(sealed)

            guard header[0] == Self.serverHeaderType else {
                throw ShadowsocksError.headerTypeMismatch(expected: Self.serverHeaderType,
                                                              actual: header[0])
            }

            let timestamp = header[1..<9].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
            try ShadowsocksConfiguration.validateTimestamp(timestamp)

            // The echoed request salt proves the response belongs to *this* request. Comparing it
            // with `==` is correct: it is a public value we sent in the clear ourselves, so there is
            // no secret to leak through timing. Anything secret is compared by the AEAD's own
            // constant-time verifier inside `open`.
            let echoedSalt = Array(header[9..<(9 + method.saltSize)])
            guard echoedSalt == requestSalt else {
                throw ShadowsocksError.requestSaltMismatch
            }

            // The response fixed header doubles as the first length chunk.
            let lengthOffset = 9 + method.saltSize
            let length = Int(header[lengthOffset]) << 8 | Int(header[lengthOffset + 1])
            inboundState = .awaitingPayload(length)

            establishedPromise?.succeed(())
            establishedPromise = nil
            return true

        case .awaitingLength:
            let needed = 2 + tagSize
            guard buffer.readableBytes >= needed else { return false }
            guard let sealed = buffer.readBytes(length: needed) else { return false }
            let plaintext = try open(sealed)
            inboundState = .awaitingPayload(Int(plaintext[0]) << 8 | Int(plaintext[1]))
            return true

        case .awaitingPayload(let length):
            let needed = length + tagSize
            guard buffer.readableBytes >= needed else { return false }
            guard let sealed = buffer.readBytes(length: needed) else { return false }
            let plaintext = try open(sealed)
            inboundState = .awaitingLength

            guard !plaintext.isEmpty else { return true }
            var out = context.channel.allocator.buffer(capacity: plaintext.count)
            out.writeBytes(plaintext)
            context.fireChannelRead(wrapInboundOut(out))
            return true
        }
    }

    private func open(_ bytes: [UInt8]) throws -> [UInt8] {
        guard let responseSubkey else { throw ShadowsocksError.truncatedHeader }
        let nonce = try responseNonce.next()
        let tagSize = ShadowsocksMethod.tagSize

        do {
            let box = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: Data(bytes.prefix(bytes.count - tagSize)),
                tag: Data(bytes.suffix(tagSize))
            )
            return [UInt8](try AES.GCM.open(box, using: responseSubkey))
        } catch {
            // Every AEAD failure funnels into one error so the connect path can report
            // `.badCredentials` rather than a generic transport failure.
            throw ShadowsocksError.authenticationFailed
        }
    }

    // MARK: - Failure

    private func fail(context: ChannelHandlerContext, error: any Error) {
        inboundState = .failed
        logger.error("Shadowsocks 2022 stream failed: \(error)")
        failEstablished(with: error)
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }

    private func failEstablished(with error: any Error) {
        establishedPromise?.fail(error)
        establishedPromise = nil
    }
}
