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

/// The AEAD-2022 methods this implementation supports.
///
/// Only the AES variants are here on purpose: extensible identity headers need a block cipher, and
/// `2022-blake3-chacha20-poly1305` has none — sing-box rejects a multi-user configuration that uses
/// it (SagerNet/sing-box#1652). Every size that varies by method is derived here so no `if method ==`
/// branching leaks into the handlers.
public enum ShadowsocksMethod: String, Sendable, Hashable, CaseIterable {
    case aes128gcm = "2022-blake3-aes-128-gcm"
    case aes256gcm = "2022-blake3-aes-256-gcm"

    /// Used when a configuration omits or misspells the method.
    public static let `default` = ShadowsocksMethod.aes128gcm

    /// AES block size. Identity headers and the UDP separate header are always exactly one block,
    /// for both methods — only the *key* size changes.
    public static let blockSize = 16

    /// AES-GCM tag length, both methods.
    public static let tagSize = 16

    /// `type(1) ‖ timestamp(8) ‖ length(2)`
    public static let requestFixedHeaderSize = 11

    /// PSK, salt and derived-subkey length.
    public var keySize: Int {
        switch self {
        case .aes128gcm: 16
        case .aes256gcm: 32
        }
    }

    /// SIP022 requires the salt to match the key length.
    public var saltSize: Int { self.keySize }

    /// `type(1) ‖ timestamp(8) ‖ requestSalt(saltSize) ‖ length(2)`
    public var responseHeaderSize: Int { 11 + self.saltSize }
}
