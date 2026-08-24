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
import _CryptoExtras

// MARK: - Single-block AES-ECB

/// One AES block, no chaining and no padding — exactly what identity headers and the UDP separate
/// header need.
///
/// `Crypto` offers no block primitive (its only `AES` is GCM and key wrapping) and AES-GCM cannot be
/// coerced into one, because its counter blocks are derived from the nonce rather than chosen. The
/// primitive lives in `_CryptoExtras` as `AES.permute`, which is BoringSSL's `AES_encrypt` under a
/// public, cross-platform API.
@_spi(ShadowsocksTesting) public enum AESBlock {
    @_spi(ShadowsocksTesting) public static func encrypt(block: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try self.transform(block: block, key: key, encrypting: true)
    }

    @_spi(ShadowsocksTesting) public static func encrypt(block: [UInt8], key: SymmetricKey) throws -> [UInt8] {
        try self.transform(block: block, key: key, encrypting: true)
    }

    @_spi(ShadowsocksTesting) public static func decrypt(block: [UInt8], key: [UInt8]) throws -> [UInt8] {
        try self.transform(block: block, key: key, encrypting: false)
    }

    private static func transform(block: [UInt8], key: [UInt8], encrypting: Bool) throws -> [UInt8] {
        try self.transform(block: block, key: SymmetricKey(data: key), encrypting: encrypting)
    }

    private static func transform(block: [UInt8], key: SymmetricKey, encrypting: Bool) throws -> [UInt8] {
        var payload = block
        if encrypting {
            try AES.permute(&payload, key: key)
        } else {
            try AES.inversePermute(&payload, key: key)
        }
        return payload
    }
}

// MARK: - AEAD nonce counter

/// SIP022's TCP nonce: a 12-byte **little-endian** counter, incremented after every AEAD operation.
@_spi(ShadowsocksTesting) public struct AEADNonceCounter {
    private var bytes = [UInt8](repeating: 0, count: 12)

    @_spi(ShadowsocksTesting) public init() {}

    /// Exposed for tests; production code only ever calls `next()`.
    @_spi(ShadowsocksTesting) public var currentBytes: [UInt8] { self.bytes }

    /// Returns the nonce for the next AEAD operation and advances the counter.
    @_spi(ShadowsocksTesting) public mutating func next() throws -> AES.GCM.Nonce {
        let nonce = try AES.GCM.Nonce(data: self.bytes)
        self.increment()
        return nonce
    }

    private mutating func increment() {
        for index in self.bytes.indices {
            self.bytes[index] &+= 1
            if self.bytes[index] != 0 { return }
        }
    }
}

// MARK: - Replay window

/// A 64-packet sliding window over UDP packet IDs, in the style of WireGuard's replay filter.
///
/// Must be consulted only *after* the packet authenticates and its type and timestamp validate —
/// otherwise an attacker could poison the window with forged packet IDs (SIP022 §3.2.4).
@_spi(ShadowsocksTesting) public struct ReplayWindow {
    @_spi(ShadowsocksTesting) public static let windowSize: UInt64 = 64

    private var latest: UInt64 = 0
    private var bitmap: UInt64 = 0

    @_spi(ShadowsocksTesting) public init() {}

    /// Returns `false` if this packet ID is a duplicate or too old to judge.
    @_spi(ShadowsocksTesting) public mutating func accept(_ packetID: UInt64) -> Bool {
        if packetID > self.latest {
            let shift = packetID - self.latest
            self.bitmap = shift >= Self.windowSize ? 1 : (self.bitmap << shift) | 1
            self.latest = packetID
            return true
        }

        let offset = self.latest - packetID
        guard offset < Self.windowSize else { return false }
        let mask: UInt64 = 1 << offset
        guard self.bitmap & mask == 0 else { return false }
        self.bitmap |= mask
        return true
    }
}

// MARK: - Big-endian integer bytes

extension FixedWidthInteger {
    /// Big-endian bytes, as every SIP022 length, port, timestamp and packet ID is encoded.
    @_spi(ShadowsocksTesting) public var shadowsocksBytes: [UInt8] {
        withUnsafeBytes(of: self.bigEndian, Array.init)
    }
}
