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

/// Wraps a connected datagram channel so everything above sees bare plaintext payloads and the wire
/// carries Shadowsocks 2022 UDP packets.
///
/// One instance is one SIP022 UDP session. Datagram channels are conventionally scoped to a single
/// client 5-tuple and a single remote, so with one handler per `(client, target)` channel the session
/// state needs no map and no actor — it is naturally per-instance.
///
/// UDP differs from the TCP codec in four ways that are all easy to get wrong and all fail silently
/// (the server simply drops the packet):
///
/// 1. The AEAD nonce is `separateHeader[4..<16]` — the last 4 bytes of the session ID plus the whole
///    packet ID — not the packet ID alone.
/// 2. Padding precedes the address, the opposite of the TCP variable-length header.
/// 3. Identity headers are keyed by the *raw* iPSK, not a salt-derived subkey, and their plaintext is
///    XORed with the separate header so it varies per packet.
/// 4. The separate header is ECB-encrypted under `iPSK0` client→server but under the uPSK
///    server→client, and responses carry no identity headers at all.
public final class ShadowsocksUDPClientHandler: ChannelDuplexHandler, @unchecked Sendable {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// `session id (8) ‖ packet id (8)` — one AES block, for both methods.
    public static let separateHeaderSize = 16
    public static let sessionIDSize = 8

    /// SIP022 §3.2.4: a new server session is only trusted once the current one has been quiet this
    /// long, which is what stops an off-path attacker from displacing a live session.
    public static let serverSessionGracePeriod = TimeAmount.seconds(60)

    private static let clientHeaderType: UInt8 = 0
    private static let serverHeaderType: UInt8 = 1

    private let config: ShadowsocksConfiguration
    private let targetHost: String
    private let targetPort: UInt16
    private let logger: Logger

    // Outbound session state: fixed for the life of the handler.
    private let clientSessionID: [UInt8]
    private var clientPacketID: UInt64 = 0

    // Inbound: one current and one old server session.
    //
    // ponytail: two slots, not a map. This is the spec's own sanctioned alternative to tracking every
    // session — "keep track of one old server session and one current server session, and reject
    // newer server sessions when the last packet received from the old session is less than 1 minute
    // old". Upgrade path: an LRU keyed by session ID if a server ever rotates sessions rapidly.
    private var currentServerSessionID: [UInt8]?
    private var currentReplayWindow = ReplayWindow()
    private var currentLastSeen: NIODeadline?
    private var oldServerSessionID: [UInt8]?
    private var oldReplayWindow = ReplayWindow()

    /// Injectable so tests can drive the session grace period without sleeping.
    private let now: @Sendable () -> NIODeadline

    public init(config: ShadowsocksConfiguration,
         targetHost: String,
         targetPort: Int,
         logger: Logger,
         now: @Sendable @escaping () -> NIODeadline = { NIODeadline.now() }) {
        self.config = config
        self.targetHost = targetHost
        self.targetPort = UInt16(targetPort)
        self.logger = logger
        self.now = now
        self.clientSessionID = ShadowsocksConfiguration.randomBytes(count: Self.sessionIDSize)
    }

    // MARK: - Outbound

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let payload = unwrapOutboundIn(data)
        do {
            let packet = try encode(payload: [UInt8](payload.readableBytesView),
                                    allocator: context.channel.allocator)
            context.write(wrapOutboundOut(packet), promise: promise)
        } catch {
            logger.error("Shadowsocks 2022 UDP encode failed: \(error)")
            promise?.fail(error)
        }
    }

    public func encode(payload: [UInt8], allocator: ByteBufferAllocator) throws -> ByteBuffer {
        // Plaintext separate header. Both the nonce and the identity headers derive from this, so it
        // is built once and reused before being encrypted.
        var separateHeader = clientSessionID
        separateHeader += clientPacketID.shadowsocksBytes
        clientPacketID &+= 1

        // ponytail: no padding on UDP packets. The spec makes padding optional here, and a datagram
        // that grows by up to 900 bytes risks crossing the path MTU and being fragmented or dropped —
        // a correctness problem traded against fingerprint resistance we do not need, since we
        // control both ends and confidentiality comes from the AEAD. Upgrade path: pad the first
        // packet only, bounded well under the MTU, if traffic analysis becomes a concern.
        var body = [Self.clientHeaderType]
        body += ShadowsocksConfiguration.currentTimestamp().shadowsocksBytes
        body += UInt16(0).shadowsocksBytes
        body += ShadowsocksConfiguration.addressBytes(host: targetHost, port: targetPort)
        body += payload

        let subkey = config.sessionSubkey(salt: Array(separateHeader.prefix(Self.sessionIDSize)))
        let sealed = try AES.GCM.seal(body,
                                      using: subkey,
                                      nonce: try Self.nonce(forSeparateHeader: separateHeader))

        // Client→server the separate header is keyed by the first PSK in the chain, which is iPSK0
        // when EIH is in use and simply the only PSK when it is not.
        var out = allocator.buffer(capacity: Self.separateHeaderSize
            + config.identityHeaderCount * ShadowsocksMethod.blockSize
            + sealed.ciphertext.count + ShadowsocksMethod.tagSize)
        out.writeBytes(try AESBlock.encrypt(block: separateHeader, key: config.psks[0]))
        out.writeBytes(try config.udpIdentityHeaders(separateHeader: separateHeader))
        out.writeBytes(sealed.ciphertext)
        out.writeBytes(sealed.tag)
        return out
    }

    // MARK: - Inbound

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let packet = unwrapInboundIn(data)
        do {
            let payload = try decode(packet: packet, allocator: context.channel.allocator)
            // A packet carrying only a header is valid but has nothing to relay.
            guard payload.readableBytes > 0 else { return }
            context.fireChannelRead(wrapInboundOut(payload))
        } catch {
            // A single bad datagram must not kill the session: UDP is unreliable and an off-path
            // attacker can inject packets, so dropping is the only safe response.
            logger.debug("Shadowsocks 2022 UDP: dropping packet (\(error))")
        }
    }

    public func decode(packet: ByteBuffer, allocator: ByteBufferAllocator) throws -> ByteBuffer {
        var packet = packet
        guard packet.readableBytes >= Self.separateHeaderSize + ShadowsocksMethod.tagSize,
              let encryptedSeparateHeader = packet.readBytes(length: Self.separateHeaderSize) else {
            throw ShadowsocksError.truncatedHeader
        }

        // Server→client the separate header is keyed by the uPSK, and responses carry no identity
        // headers, so the sealed body starts immediately after it.
        let separateHeader = try AESBlock.decrypt(block: encryptedSeparateHeader, key: config.sessionKey)
        let serverSessionID = Array(separateHeader.prefix(Self.sessionIDSize))
        let packetID = separateHeader[Self.sessionIDSize..<Self.separateHeaderSize]
            .reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }

        let subkey = config.sessionSubkey(salt: serverSessionID)
        let sealed = packet.readBytes(length: packet.readableBytes) ?? []
        let body = try Self.open(sealed,
                                 using: subkey,
                                 nonce: try Self.nonce(forSeparateHeader: separateHeader))

        // Header: type(1) ‖ timestamp(8) ‖ client session id(8) ‖ padding length(2) ‖ padding
        //         ‖ ATYP ‖ address ‖ port(2)
        var reader = allocator.buffer(capacity: body.count)
        reader.writeBytes(body)

        guard let type = reader.readInteger(as: UInt8.self) else {
            throw ShadowsocksError.truncatedHeader
        }
        guard type == Self.serverHeaderType else {
            throw ShadowsocksError.headerTypeMismatch(expected: Self.serverHeaderType, actual: type)
        }
        guard let timestamp = reader.readInteger(as: UInt64.self) else {
            throw ShadowsocksError.truncatedHeader
        }
        try ShadowsocksConfiguration.validateTimestamp(timestamp)

        guard let echoedClientSessionID = reader.readBytes(length: Self.sessionIDSize) else {
            throw ShadowsocksError.truncatedHeader
        }
        // Proves the response belongs to this session. A public value we sent ourselves, so a plain
        // comparison leaks nothing; the secret-bearing check already happened inside `open`.
        guard echoedClientSessionID == clientSessionID else {
            throw ShadowsocksError.sessionMismatch
        }

        guard let paddingLength = reader.readInteger(as: UInt16.self),
              reader.readSlice(length: Int(paddingLength)) != nil else {
            throw ShadowsocksError.truncatedHeader
        }

        // The echoed source address is discarded: the local-side encoder re-adds the address the
        // SOCKS client is expecting, exactly as the SOCKS-via-VPN path does.
        guard try ShadowsocksAddress.read(from: &reader) != nil else {
            throw ShadowsocksError.malformedAddress
        }

        // Replay filtering runs only now, after the packet authenticated and its type, timestamp and
        // session all validated (SIP022 §3.2.4) — otherwise forged packet IDs could poison the window.
        try acceptSession(serverSessionID, packetID: packetID)

        return reader.readSlice(length: reader.readableBytes) ?? allocator.buffer(capacity: 0)
    }

    // MARK: - Session tracking

    private func acceptSession(_ sessionID: [UInt8], packetID: UInt64) throws {
        if sessionID == currentServerSessionID {
            guard currentReplayWindow.accept(packetID) else {
                throw ShadowsocksError.replayedPacket(id: packetID)
            }
            currentLastSeen = now()
            return
        }

        if sessionID == oldServerSessionID {
            guard oldReplayWindow.accept(packetID) else {
                throw ShadowsocksError.replayedPacket(id: packetID)
            }
            return
        }

        // A session we have not seen. Accept it only if the current one has gone quiet, so a forged
        // session ID cannot displace a live one.
        if currentServerSessionID != nil,
           let currentLastSeen,
           now() - currentLastSeen < Self.serverSessionGracePeriod {
            throw ShadowsocksError.sessionMismatch
        }

        oldServerSessionID = currentServerSessionID
        oldReplayWindow = currentReplayWindow
        currentServerSessionID = sessionID
        currentReplayWindow = ReplayWindow()
        _ = currentReplayWindow.accept(packetID)
        currentLastSeen = now()
    }

    // MARK: - AEAD

    /// The nonce is the separate header minus its first 4 bytes: the tail of the session ID plus the
    /// full packet ID. Using the packet ID alone produces packets a server silently drops.
    private static func nonce(forSeparateHeader separateHeader: [UInt8]) throws -> AES.GCM.Nonce {
        try AES.GCM.Nonce(data: separateHeader[4..<separateHeaderSize])
    }

    private static func open(_ bytes: [UInt8],
                             using key: SymmetricKey,
                             nonce: AES.GCM.Nonce) throws -> [UInt8] {
        let tagSize = ShadowsocksMethod.tagSize
        guard bytes.count >= tagSize else { throw ShadowsocksError.truncatedHeader }
        do {
            let box = try AES.GCM.SealedBox(nonce: nonce,
                                            ciphertext: Data(bytes.prefix(bytes.count - tagSize)),
                                            tag: Data(bytes.suffix(tagSize)))
            return [UInt8](try AES.GCM.open(box, using: key))
        } catch {
            throw ShadowsocksError.authenticationFailed
        }
    }
}
