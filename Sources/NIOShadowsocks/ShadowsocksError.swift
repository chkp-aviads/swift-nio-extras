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

/// Errors surfaced by the Shadowsocks 2022 codec.
public enum ShadowsocksError: Error, Equatable, Sendable {
    case malformedPassword(String)
    case badKeyLength(expected: Int, actual: Int)
    /// The response header failed to authenticate. In practice this means the PSK is wrong.
    case authenticationFailed
    case headerTypeMismatch(expected: UInt8, actual: UInt8)
    case timestampOutOfWindow(skewSeconds: Int64)
    case requestSaltMismatch
    case sessionMismatch
    case replayedPacket(id: UInt64)
    case truncatedHeader
    case malformedAddress
}
