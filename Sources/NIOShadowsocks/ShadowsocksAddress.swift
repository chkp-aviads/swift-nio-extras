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

import NIOCore

#if canImport(Darwin)
import Darwin
#elseif canImport(Musl)
import Musl
#elseif canImport(Android)
import Android
#elseif os(Windows)
import ucrt
import WinSDK
#else
import Glibc
#endif

/// The SOCKS5-shaped target address SIP022 embeds in every request header and UDP packet:
/// `ATYP ‖ address ‖ port(2)`, big-endian port.
///
/// `NIOSOCKS` implements this same encoding for its own messages, and its version is arguably better
/// shaped — it reads the port together with the address, exactly as SIP022 needs. It is not reused
/// here because its `ByteBuffer` read/write helpers are `internal` to that module, and widening the
/// API of an upstream-tracked file for an unrelated protocol costs more than these forty lines.
@_spi(ShadowsocksTesting) public enum ShadowsocksAddress {
    static let ipv4Type: UInt8 = 1
    static let domainType: UInt8 = 3
    static let ipv6Type: UInt8 = 4

    /// Encodes `ATYP ‖ address ‖ port`. An IP literal is emitted in its packed form; anything else is
    /// treated as a domain name, which is what a proxy client wants — the server resolves it.
    @_spi(ShadowsocksTesting) public static func bytes(host: String, port: UInt16) -> [UInt8] {
        var out = [UInt8]()
        if let address = try? SocketAddress(ipAddress: host, port: Int(port)) {
            switch address {
            case .v4(let v4):
                out.append(self.ipv4Type)
                out.append(contentsOf: withUnsafeBytes(of: v4.address.sin_addr.s_addr) { Array($0) })
            case .v6(let v6):
                out.append(self.ipv6Type)
                out.append(contentsOf: withUnsafeBytes(of: v6.address.sin6_addr) { Array($0) })
            case .unixDomainSocket:
                // Unrepresentable in SIP022; fall back to treating it as a name so this stays total.
                return self.domainBytes(host: host, port: port)
            }
        } else {
            return self.domainBytes(host: host, port: port)
        }
        out.append(contentsOf: [UInt8(truncatingIfNeeded: port >> 8), UInt8(truncatingIfNeeded: port)])
        return out
    }

    private static func domainBytes(host: String, port: UInt16) -> [UInt8] {
        let name = Array(host.utf8.prefix(255))
        return [self.domainType, UInt8(name.count)] + name
            + [UInt8(truncatingIfNeeded: port >> 8), UInt8(truncatingIfNeeded: port)]
    }

    /// Consumes `ATYP ‖ address ‖ port`, returning `nil` without advancing the reader index when the
    /// buffer is short — so an incremental parser can retry once more bytes arrive.
    @_spi(ShadowsocksTesting) public static func read(from buffer: inout ByteBuffer) throws -> (host: String, port: UInt16)? {
        let saved = buffer.readerIndex
        func rewind() -> (host: String, port: UInt16)? {
            buffer.moveReaderIndex(to: saved)
            return nil
        }

        guard let type = buffer.readInteger(as: UInt8.self) else { return rewind() }
        let host: String
        switch type {
        case self.ipv4Type, self.ipv6Type:
            // Rendered via SocketAddress rather than by hand, so the textual form matches the
            // platform's own (notably IPv6 zero-compression) and round-trips through `bytes(host:)`.
            let length = type == self.ipv4Type ? 4 : 16
            guard let packed = buffer.readSlice(length: length) else { return rewind() }
            guard let address = try? SocketAddress(packedIPAddress: packed, port: 0),
                  let rendered = address.ipAddress else {
                throw ShadowsocksError.malformedAddress
            }
            host = rendered
        case self.domainType:
            guard let length = buffer.readInteger(as: UInt8.self) else { return rewind() }
            guard let name = buffer.readString(length: Int(length)) else { return rewind() }
            host = name
        default:
            throw ShadowsocksError.malformedAddress
        }

        guard let port = buffer.readInteger(as: UInt16.self) else { return rewind() }
        return (host, port)
    }
}
