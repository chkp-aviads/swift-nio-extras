import Crypto
import Foundation
import NIOCore
@_spi(ShadowsocksTesting) import NIOShadowsocks

/// A minimal **server-side** Shadowsocks 2022 codec, for tests only.
///
/// Two reasons this exists rather than testing the client against itself:
///
/// 1. Every framing test needs a counterparty that produces valid responses.
/// 2. It is written from the specification independently of `Shadowsocks2022TCPHandler`, so an
///    asymmetric misreading of the header layout fails a test instead of round-tripping cleanly.
///    A client checked only against its own encoder agrees with itself and nothing else.
public struct ShadowsocksTestServer {
    public struct Request: Equatable {
        public var host: String
        public var port: UInt16
        /// Index into `psks` of the user the identity headers resolved to.
        public var resolvedUserIndex: Int
        public var paddingLength: Int
        public var identityHeaderCount: Int
    }

    public enum ServerError: Error, Equatable {
        case short
        case badType(UInt8)
        case identityHeaderMismatch
        case unknownAddressType(UInt8)
    }

    public let method: ShadowsocksMethod
    public let psks: [[UInt8]]

    /// Salt the client sent, which the response header must echo back. Settable so a test can build
    /// a response for a request it deliberately could not decode (the wrong-PSK case).
    public var observedRequestSalt = [UInt8]()

    private var requestSubkey: SymmetricKey?
    private var requestNonce = AEADNonceCounter()
    private var responseSubkey: SymmetricKey?
    private var responseNonce = AEADNonceCounter()
    private var responseHeaderSent = false

    public init(method: ShadowsocksMethod, psks: [[UInt8]]) {
        self.method = method
        self.psks = psks
    }

    private var uPSK: [UInt8] { psks[psks.count - 1] }

    // MARK: - Request side

    /// Consumes `salt ‖ identity headers ‖ AEAD(fixed header) ‖ AEAD(variable header)`.
    ///
    /// Atomic on failure, for the same reason as `decodePayloadChunk`.
    public mutating func decodeRequest(_ buffer: inout ByteBuffer) throws -> Request {
        let savedNonce = requestNonce
        let savedReaderIndex = buffer.readerIndex
        do {
            return try decodeRequestUnchecked(&buffer)
        } catch {
            requestNonce = savedNonce
            buffer.moveReaderIndex(to: savedReaderIndex)
            throw error
        }
    }

    private mutating func decodeRequestUnchecked(_ buffer: inout ByteBuffer) throws -> Request {
        guard let salt = buffer.readBytes(length: method.saltSize) else { throw ServerError.short }
        observedRequestSalt = salt

        // Resolve the user from the identity headers, exactly as a real server does: derive the
        // identity subkey for each iPSK, decrypt the header, and match against the next PSK's hash.
        let identityHeaderCount = psks.count - 1
        var resolvedUserIndex = psks.count - 1
        for index in 0..<identityHeaderCount {
            guard let header = buffer.readBytes(length: ShadowsocksMethod.blockSize) else {
                throw ServerError.short
            }
            let subkey = Array(
                BLAKE3.deriveKey(context: ShadowsocksConfiguration.identitySubkeyContext,
                                 keyMaterial: psks[index] + salt).prefix(method.keySize)
            )
            let plaintext = try AESBlock.decrypt(block: header, key: subkey)
            let expected = Array(BLAKE3.hash(psks[index + 1]).prefix(ShadowsocksMethod.blockSize))
            guard plaintext == expected else { throw ServerError.identityHeaderMismatch }
            resolvedUserIndex = index + 1
        }

        requestSubkey = SymmetricKey(
            data: Array(BLAKE3.deriveKey(context: ShadowsocksConfiguration.sessionSubkeyContext,
                                         keyMaterial: uPSK + salt).prefix(method.keySize))
        )
        requestNonce = AEADNonceCounter()

        // Fixed header: type(1) ‖ timestamp(8) ‖ length(2)
        guard let sealedFixed = buffer.readBytes(
            length: ShadowsocksMethod.requestFixedHeaderSize + ShadowsocksMethod.tagSize
        ) else { throw ServerError.short }
        let fixed = try openRequest(sealedFixed)
        guard fixed[0] == 0 else { throw ServerError.badType(fixed[0]) }
        let variableLength = Int(fixed[9]) << 8 | Int(fixed[10])

        guard let sealedVariable = buffer.readBytes(
            length: variableLength + ShadowsocksMethod.tagSize
        ) else { throw ServerError.short }
        let variable = try openRequest(sealedVariable)

        // Variable header: ATYP ‖ address ‖ port(2) ‖ paddingLength(2) ‖ padding
        var variableBuffer = ByteBufferAllocator().buffer(capacity: variable.count)
        variableBuffer.writeBytes(variable)

        guard let target = try ShadowsocksAddress.read(from: &variableBuffer),
              let paddingLength = variableBuffer.readInteger(as: UInt16.self) else {
            throw ServerError.short
        }
        let (host, port) = target
        guard variableBuffer.readableBytes == Int(paddingLength) else { throw ServerError.short }

        return Request(host: host,
                       port: port,
                       resolvedUserIndex: resolvedUserIndex,
                       paddingLength: Int(paddingLength),
                       identityHeaderCount: identityHeaderCount)
    }

    /// Consumes one `AEAD(length) ‖ AEAD(payload)` pair from the client stream.
    ///
    /// Atomic on failure: decoding the length chunk advances the AEAD nonce, so a chunk that turns out
    /// to be incomplete has to roll both the reader index *and* the nonce back, or the next attempt
    /// decrypts with the wrong nonce and the stream desynchronizes. That matters as soon as a real
    /// socket splits a chunk across reads.
    public mutating func decodePayloadChunk(_ buffer: inout ByteBuffer) throws -> [UInt8] {
        let savedNonce = requestNonce
        let savedReaderIndex = buffer.readerIndex
        do {
            guard let sealedLength = buffer.readBytes(length: 2 + ShadowsocksMethod.tagSize) else {
                throw ServerError.short
            }
            let lengthBytes = try openRequest(sealedLength)
            let length = Int(lengthBytes[0]) << 8 | Int(lengthBytes[1])

            guard let sealedPayload = buffer.readBytes(length: length + ShadowsocksMethod.tagSize) else {
                throw ServerError.short
            }
            return try openRequest(sealedPayload)
        } catch {
            requestNonce = savedNonce
            buffer.moveReaderIndex(to: savedReaderIndex)
            throw error
        }
    }

    // MARK: - Response side

    /// `salt ‖ AEAD(type ‖ timestamp ‖ requestSalt ‖ length)` followed by the first payload chunk.
    ///
    /// The overridable parameters exist so tests can produce deliberately invalid responses without
    /// a second encoder.
    public mutating func encodeResponseHeader(payload: [UInt8],
                                      type: UInt8 = 1,
                                      timestamp: UInt64? = nil,
                                      requestSalt: [UInt8]? = nil,
                                      allocator: ByteBufferAllocator = ByteBufferAllocator()) throws -> ByteBuffer {
        let salt = [UInt8](repeating: 0x5A, count: method.saltSize)
        responseSubkey = SymmetricKey(
            data: Array(BLAKE3.deriveKey(context: ShadowsocksConfiguration.sessionSubkeyContext,
                                         keyMaterial: uPSK + salt).prefix(method.keySize))
        )
        responseNonce = AEADNonceCounter()
        responseHeaderSent = true

        var header = [type]
        header += (timestamp ?? ShadowsocksConfiguration.currentTimestamp()).shadowsocksBytes
        header += requestSalt ?? observedRequestSalt
        header += UInt16(payload.count).shadowsocksBytes

        var out = allocator.buffer(capacity: salt.count + header.count + 64 + payload.count)
        out.writeBytes(salt)
        out.writeBytes(try sealResponse(header))
        out.writeBytes(try sealResponse(payload))
        return out
    }

    /// A subsequent `AEAD(length) ‖ AEAD(payload)` pair.
    public mutating func encodeResponseChunk(payload: [UInt8],
                                     allocator: ByteBufferAllocator = ByteBufferAllocator()) throws -> ByteBuffer {
        precondition(responseHeaderSent, "send the response header first")
        var out = allocator.buffer(capacity: payload.count + 64)
        out.writeBytes(try sealResponse(UInt16(payload.count).shadowsocksBytes))
        out.writeBytes(try sealResponse(payload))
        return out
    }

    // MARK: - UDP

    public struct UDPRequest: Equatable {
        public var host: String
        public var port: UInt16
        public var payload: [UInt8]
        public var sessionID: [UInt8]
        public var packetID: UInt64
        public var resolvedUserIndex: Int
        public var paddingLength: Int
    }

    /// Decodes one client→server datagram, written from the specification independently of
    /// `Shadowsocks2022UDPHandler` so an asymmetric misreading fails a test.
    public func decodeUDP(_ packet: ByteBuffer) throws -> UDPRequest {
        var packet = packet
        guard let encryptedSeparateHeader = packet.readBytes(length: 16) else { throw ServerError.short }

        // Client→server: keyed by the first PSK in the chain.
        let separateHeader = try AESBlock.decrypt(block: encryptedSeparateHeader, key: psks[0])
        let sessionID = Array(separateHeader.prefix(8))
        let packetID = separateHeader[8..<16].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }

        // Identity headers are keyed by the raw iPSK and XORed with the plaintext separate header.
        let identityHeaderCount = psks.count - 1
        var resolvedUserIndex = psks.count - 1
        for index in 0..<identityHeaderCount {
            guard let header = packet.readBytes(length: 16) else { throw ServerError.short }
            let plaintext = try AESBlock.decrypt(block: header, key: psks[index])
            let expected = zip(Array(BLAKE3.hash(psks[index + 1]).prefix(16)), separateHeader)
                .map { $0 ^ $1 }
            guard plaintext == expected else { throw ServerError.identityHeaderMismatch }
            resolvedUserIndex = index + 1
        }

        let subkey = SymmetricKey(
            data: Array(BLAKE3.deriveKey(context: ShadowsocksConfiguration.sessionSubkeyContext,
                                         keyMaterial: uPSK + sessionID).prefix(method.keySize))
        )
        let sealed = packet.readBytes(length: packet.readableBytes) ?? []
        let tagSize = ShadowsocksMethod.tagSize
        guard sealed.count >= tagSize else { throw ServerError.short }
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: separateHeader[4..<16]),
                                        ciphertext: Data(sealed.prefix(sealed.count - tagSize)),
                                        tag: Data(sealed.suffix(tagSize)))
        let body = [UInt8](try AES.GCM.open(box, using: subkey))

        // type(1) ‖ timestamp(8) ‖ padding length(2) ‖ padding ‖ ATYP ‖ address ‖ port(2) ‖ payload
        // Note padding precedes the address here, unlike the TCP variable-length header.
        var reader = ByteBufferAllocator().buffer(capacity: body.count)
        reader.writeBytes(body)
        guard let type = reader.readInteger(as: UInt8.self) else { throw ServerError.short }
        guard type == 0 else { throw ServerError.badType(type) }
        guard reader.readInteger(as: UInt64.self) != nil,
              let paddingLength = reader.readInteger(as: UInt16.self),
              reader.readSlice(length: Int(paddingLength)) != nil,
              let target = try ShadowsocksAddress.read(from: &reader) else {
            throw ServerError.short
        }
        let (host, port) = target

        return UDPRequest(host: host,
                          port: port,
                          payload: reader.readBytes(length: reader.readableBytes) ?? [],
                          sessionID: sessionID,
                          packetID: packetID,
                          resolvedUserIndex: resolvedUserIndex,
                          paddingLength: Int(paddingLength))
    }

    /// Builds a server→client datagram. Overridable fields let tests produce invalid responses.
    public func encodeUDP(payload: [UInt8],
                   clientSessionID: [UInt8],
                   serverSessionID: [UInt8],
                   packetID: UInt64,
                   type: UInt8 = 1,
                   timestamp: UInt64? = nil,
                   sourceHost: String = "203.0.113.9",
                   sourcePort: UInt16 = 53,
                   allocator: ByteBufferAllocator = ByteBufferAllocator()) throws -> ByteBuffer {
        var separateHeader = serverSessionID
        separateHeader += packetID.shadowsocksBytes

        // type(1) ‖ timestamp(8) ‖ client session id(8) ‖ padding length(2) ‖ padding
        //   ‖ ATYP ‖ address ‖ port(2) ‖ payload
        var body = [type]
        body += (timestamp ?? ShadowsocksConfiguration.currentTimestamp()).shadowsocksBytes
        body += clientSessionID
        body += UInt16(0).shadowsocksBytes
        body += ShadowsocksConfiguration.addressBytes(host: sourceHost, port: sourcePort)
        body += payload

        let subkey = SymmetricKey(
            data: Array(BLAKE3.deriveKey(context: ShadowsocksConfiguration.sessionSubkeyContext,
                                         keyMaterial: uPSK + Array(separateHeader.prefix(8)))
                .prefix(method.keySize))
        )
        let sealed = try AES.GCM.seal(body,
                                      using: subkey,
                                      nonce: try AES.GCM.Nonce(data: separateHeader[4..<16]))

        // Server→client: separate header keyed by the uPSK, and no identity headers.
        var out = allocator.buffer(capacity: 16 + sealed.ciphertext.count + 16)
        out.writeBytes(try AESBlock.encrypt(block: separateHeader, key: uPSK))
        out.writeBytes(sealed.ciphertext)
        out.writeBytes(sealed.tag)
        return out
    }

    // MARK: - AEAD

    private mutating func openRequest(_ bytes: [UInt8]) throws -> [UInt8] {
        guard let requestSubkey else { throw ServerError.short }
        let nonce = try requestNonce.next()
        let tagSize = ShadowsocksMethod.tagSize
        let box = try AES.GCM.SealedBox(nonce: nonce,
                                        ciphertext: Data(bytes.prefix(bytes.count - tagSize)),
                                        tag: Data(bytes.suffix(tagSize)))
        return [UInt8](try AES.GCM.open(box, using: requestSubkey))
    }

    private mutating func sealResponse(_ plaintext: [UInt8]) throws -> [UInt8] {
        guard let responseSubkey else { throw ServerError.short }
        let nonce = try responseNonce.next()
        let box = try AES.GCM.seal(plaintext, using: responseSubkey, nonce: nonce)
        return [UInt8](box.ciphertext) + [UInt8](box.tag)
    }
}
