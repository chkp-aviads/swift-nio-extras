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
//
//  Shadowsocks 2022 (SIP022) client cryptography.
//
//  Specifications:
//    https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
//    https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md
//
//  Behaviour cross-checked against shadowsocks-rust (MIT licensed,
//  https://github.com/shadowsocks/shadowsocks-rust) where the specification text is thin.
//

import Crypto

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A parsed PSK chain for one Shadowsocks 2022 server.
///
/// `psks.last` is the uPSK: it keys every session subkey and, for UDP, the response separate header.
/// Everything before it is an iPSK, and each one contributes one identity header so the server can
/// resolve which user is connecting. A single-element chain means no EIH at all.
///
/// `Hashable` because a proxy configuration holding one may itself be used as a connection-pool key:
/// two servers reached at the same address with different keys must never be conflated.
public struct ShadowsocksConfiguration: Sendable, Hashable {
    /// SIP022 caps request padding at 900 bytes.
    public static let maxPaddingLength = 900

    @_spi(ShadowsocksTesting) public static let sessionSubkeyContext = "shadowsocks 2022 session subkey"
    @_spi(ShadowsocksTesting) public static let identitySubkeyContext = "shadowsocks 2022 identity subkey"

    /// Servers accept timestamps within ±30s of their own clock.
    public static let maxTimestampSkew: UInt64 = 30

    public let method: ShadowsocksMethod

    /// `[iPSK…, uPSK]`, each exactly `method.keySize` bytes.
    public let psks: [[UInt8]]

    /// `blake3::hash(psks[i])[0..<16]` — the identity-header plaintexts, precomputed at parse time
    /// because they never change for the life of the configuration.
    @_spi(ShadowsocksTesting) public let pskHashes: [[UInt8]]

    /// Parses sing-box's own password format, so a server configuration can be pasted in verbatim:
    /// `base64(iPSK):…:base64(uPSK)`, each element base64 of exactly `method.keySize` raw bytes.
    ///
    /// This is a trust boundary — the string typically arrives from a remote configuration source — so
    /// every component is validated rather than best-effort decoded.
    public init(method: ShadowsocksMethod, password: String) throws {
        let components = password
            .split(separator: ":", omittingEmptySubsequences: false)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

        var parsed = [[UInt8]]()
        parsed.reserveCapacity(components.count)

        for component in components {
            guard !component.isEmpty else {
                throw ShadowsocksError.malformedPassword("empty PSK component")
            }
            guard let decoded = Data(base64Encoded: component) else {
                throw ShadowsocksError.malformedPassword("PSK is not valid base64")
            }
            guard decoded.count == method.keySize else {
                throw ShadowsocksError.badKeyLength(expected: method.keySize, actual: decoded.count)
            }
            parsed.append([UInt8](decoded))
        }

        try self.init(method: method, psks: parsed)
    }

    /// Builds a configuration from raw key material.
    public init(method: ShadowsocksMethod, psks: [[UInt8]]) throws {
        guard !psks.isEmpty else {
            throw ShadowsocksError.malformedPassword("PSK chain is empty")
        }
        for psk in psks where psk.count != method.keySize {
            throw ShadowsocksError.badKeyLength(expected: method.keySize, actual: psk.count)
        }

        self.method = method
        self.psks = psks
        self.pskHashes = psks.map { Array(BLAKE3.hash($0).prefix(ShadowsocksMethod.blockSize)) }
    }

    /// The uPSK — keys every session subkey.
    public var sessionKey: [UInt8] { self.psks[self.psks.count - 1] }

    /// Number of identity headers this chain produces.
    public var identityHeaderCount: Int { self.psks.count - 1 }

    // MARK: - Subkeys

    @_spi(ShadowsocksTesting) public func sessionSubkey(salt: [UInt8]) -> SymmetricKey {
        SymmetricKey(data: self.derive(context: Self.sessionSubkeyContext, keyMaterial: self.sessionKey + salt))
    }

    @_spi(ShadowsocksTesting) public func identitySubkey(index: Int, salt: [UInt8]) -> [UInt8] {
        self.derive(context: Self.identitySubkeyContext, keyMaterial: self.psks[index] + salt)
    }

    private func derive(context: String, keyMaterial: [UInt8]) -> [UInt8] {
        Array(BLAKE3.deriveKey(context: context, keyMaterial: keyMaterial).prefix(self.method.keySize))
    }

    // MARK: - Identity headers

    /// TCP identity headers: for each iPSK, one AES-ECB block encrypting the *next* PSK's hash under
    /// a salt-derived identity subkey.
    @_spi(ShadowsocksTesting) public func tcpIdentityHeaders(salt: [UInt8]) throws -> [UInt8] {
        var headers = [UInt8]()
        headers.reserveCapacity(self.identityHeaderCount * ShadowsocksMethod.blockSize)
        for index in 0..<self.identityHeaderCount {
            let subkey = self.identitySubkey(index: index, salt: salt)
            headers += try AESBlock.encrypt(block: self.pskHashes[index + 1], key: subkey)
        }
        return headers
    }

    /// UDP identity headers differ from TCP in two ways that are easy to miss: the key is the *raw*
    /// iPSK rather than a salt-derived subkey, and the plaintext is XORed with the separate header
    /// first so it varies per packet.
    @_spi(ShadowsocksTesting) public func udpIdentityHeaders(separateHeader: [UInt8]) throws -> [UInt8] {
        var headers = [UInt8]()
        headers.reserveCapacity(self.identityHeaderCount * ShadowsocksMethod.blockSize)
        for index in 0..<self.identityHeaderCount {
            let plaintext = zip(self.pskHashes[index + 1], separateHeader).map { $0 ^ $1 }
            headers += try AESBlock.encrypt(block: plaintext, key: self.psks[index])
        }
        return headers
    }

    // MARK: - Header field helpers

    /// Seconds since the Unix epoch. Injectable at the handler level so the ±30s window is testable
    /// without a real clock.
    public static func currentTimestamp() -> UInt64 {
        UInt64(Date().timeIntervalSince1970)
    }

    @_spi(ShadowsocksTesting) public static func validateTimestamp(
        _ timestamp: UInt64,
        now: UInt64 = ShadowsocksConfiguration.currentTimestamp()
    ) throws {
        // Unsigned subtraction in the correct order, so a wildly out-of-range timestamp cannot
        // overflow its way into the accepted window.
        let delta = timestamp > now ? timestamp - now : now - timestamp
        guard delta <= self.maxTimestampSkew else {
            let signed = Int64(clamping: delta)
            throw ShadowsocksError.timestampOutOfWindow(
                skewSeconds: timestamp > now ? signed : -signed
            )
        }
    }

    /// `ATYP ‖ address ‖ port`.
    @_spi(ShadowsocksTesting) public static func addressBytes(host: String, port: UInt16) -> [UInt8] {
        ShadowsocksAddress.bytes(host: host, port: port)
    }

    /// Random padding in `0...900`.
    @_spi(ShadowsocksTesting) public static func randomPadding() -> [UInt8] {
        let seed = self.randomBytes(count: 2)
        let length = Int(UInt16(seed[0]) << 8 | UInt16(seed[1])) % (self.maxPaddingLength + 1)
        return self.randomBytes(count: length)
    }

    /// Cryptographically secure random bytes.
    ///
    /// Sourced from `SymmetricKey(size:)` rather than `SystemRandomNumberGenerator` so the CSPRNG
    /// guarantee is swift-crypto's and the same on every platform — this replaces the Darwin-only
    /// `SecRandomCopyBytes` the code used before it moved here.
    @_spi(ShadowsocksTesting) public static func randomBytes(count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        return SymmetricKey(size: .init(bitCount: count * 8)).withUnsafeBytes { [UInt8]($0) }
    }
}
