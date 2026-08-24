//
//  BLAKE3.swift
//  NIOShadowsocks
//
//  Derived from the BLAKE3 reference implementation and specification
//  (https://github.com/BLAKE3-team/BLAKE3), dual-licensed CC0-1.0 OR Apache-2.0.
//

/// BLAKE3 restricted to inputs that fit in a single 1024-byte chunk.
///
/// This is the only key-derivation function Shadowsocks 2022 (SIP022) uses, replacing the obsolete
/// HKDF-SHA1 of the 2017 AEAD ciphers. Every BLAKE3 input in SIP022 is tiny and fixed-size — a
/// 16- or 32-byte PSK concatenated with an equally sized salt, or a context string of at most 32
/// bytes — so the chaining-value stack, parent-node compression and extendable output of full
/// BLAKE3 are all unreachable here.
///
/// ponytail: single chunk only, no CV stack / parent nodes / XOF. That removes roughly two thirds
/// of BLAKE3 for code SIP022 can never reach, and avoids making this the package's first C target
/// just to vendor the reference implementation. Upgrade path: port the full tree hasher if BLAKE3
/// is ever needed for bulk data — `chunkRoot` traps rather than silently diverging.
@_spi(ShadowsocksTesting) public enum BLAKE3 {
    /// One BLAKE3 chunk. Inputs above this need tree hashing, which this port deliberately omits.
    static let maxInputLength = 1024

    /// SIP022 only ever wants 32 bytes (truncated to the method's key size by the caller).
    @_spi(ShadowsocksTesting) public static let outputLength = 32

    /// Unkeyed hash. Used for the `blake3::hash(PSK)` in identity headers.
    @_spi(ShadowsocksTesting) public static func hash(_ input: [UInt8]) -> [UInt8] {
        chunkRoot(input, key: iv, flags: 0)
    }

    /// Keyed hash. Unused by SIP022, but it is three lines and it lets the official keyed-hash
    /// vectors exercise the compression function's flag handling independently.
    @_spi(ShadowsocksTesting) public static func keyedHash(_ input: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(key.count == outputLength, "BLAKE3 keyed hash requires a 32-byte key")
        return chunkRoot(input, key: words(fromLittleEndian: key), flags: Flags.keyedHash)
    }

    /// `blake3::derive_key(context:key_material:)` — SIP022's session and identity subkey KDF.
    ///
    /// Two passes: the context string is hashed into a key, and that key then keys the hash of the
    /// key material. Getting the context string or the concatenation order wrong produces a
    /// perfectly valid-looking subkey that no server will agree with, so both are pinned by KATs.
    @_spi(ShadowsocksTesting) public static func deriveKey(context: String, keyMaterial: [UInt8]) -> [UInt8] {
        let contextKey = chunkRoot(Array(context.utf8), key: iv, flags: Flags.deriveKeyContext)
        return chunkRoot(keyMaterial,
                         key: words(fromLittleEndian: contextKey),
                         flags: Flags.deriveKeyMaterial)
    }

    // MARK: - Constants

    private enum Flags {
        static let chunkStart: UInt32 = 1
        static let chunkEnd: UInt32 = 2
        static let root: UInt32 = 8
        static let keyedHash: UInt32 = 16
        static let deriveKeyContext: UInt32 = 32
        static let deriveKeyMaterial: UInt32 = 64
    }

    /// The SHA-256 initialisation vector, which BLAKE3 reuses.
    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    private static let messagePermutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

    private static let blockLength = 64

    // MARK: - Chunk compression

    /// Compresses `input` as a single chunk and returns its 32-byte root output.
    private static func chunkRoot(_ input: [UInt8], key: [UInt32], flags: UInt32) -> [UInt8] {
        precondition(input.count <= maxInputLength,
                     "BLAKE3 here is single-chunk only; SIP022 inputs never exceed 64 bytes")

        var chainingValue = key
        // An empty input still compresses exactly one block, with a block length of zero.
        let blockCount = max(1, (input.count + blockLength - 1) / blockLength)

        for blockIndex in 0..<blockCount {
            let start = blockIndex * blockLength
            let usedBytes = min(blockLength, input.count - start)

            var block = [UInt8](repeating: 0, count: blockLength)
            if usedBytes > 0 {
                block.replaceSubrange(0..<usedBytes, with: input[start..<(start + usedBytes)])
            }

            var blockFlags = flags
            if blockIndex == 0 {
                blockFlags |= Flags.chunkStart
            }
            if blockIndex == blockCount - 1 {
                // Single chunk, so the last block of the chunk is also the root.
                blockFlags |= Flags.chunkEnd | Flags.root
            }

            // A single chunk is chunk 0, and the first 32 bytes of root output is output block 0,
            // so the counter is zero for every compression here.
            let state = compress(chainingValue: chainingValue,
                                 block: words(fromLittleEndian: block),
                                 counter: 0,
                                 blockLength: UInt32(usedBytes),
                                 flags: blockFlags)
            chainingValue = Array(state[0..<8])
        }

        return littleEndianBytes(chainingValue)
    }

    private static func compress(chainingValue: [UInt32],
                                 block: [UInt32],
                                 counter: UInt64,
                                 blockLength: UInt32,
                                 flags: UInt32) -> [UInt32] {
        var state: [UInt32] = [
            chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3],
            chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
            iv[0], iv[1], iv[2], iv[3],
            UInt32(truncatingIfNeeded: counter),
            UInt32(truncatingIfNeeded: counter >> 32),
            blockLength,
            flags,
        ]

        var message = block
        for round in 0..<7 {
            mixRound(&state, message)
            if round < 6 {
                message = messagePermutation.map { message[$0] }
            }
        }

        for index in 0..<8 {
            state[index] ^= state[index + 8]
            state[index + 8] ^= chainingValue[index]
        }
        return state
    }

    private static func mixRound(_ state: inout [UInt32], _ m: [UInt32]) {
        // Mix the columns.
        mix(&state, 0, 4, 8, 12, m[0], m[1])
        mix(&state, 1, 5, 9, 13, m[2], m[3])
        mix(&state, 2, 6, 10, 14, m[4], m[5])
        mix(&state, 3, 7, 11, 15, m[6], m[7])
        // Mix the diagonals.
        mix(&state, 0, 5, 10, 15, m[8], m[9])
        mix(&state, 1, 6, 11, 12, m[10], m[11])
        mix(&state, 2, 7, 8, 13, m[12], m[13])
        mix(&state, 3, 4, 9, 14, m[14], m[15])
    }

    private static func mix(_ s: inout [UInt32],
                            _ a: Int, _ b: Int, _ c: Int, _ d: Int,
                            _ mx: UInt32, _ my: UInt32) {
        s[a] = s[a] &+ s[b] &+ mx
        s[d] = rotateRight(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]
        s[b] = rotateRight(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b] &+ my
        s[d] = rotateRight(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]
        s[b] = rotateRight(s[b] ^ s[c], 7)
    }

    private static func rotateRight(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value >> count) | (value << (32 - count))
    }

    // MARK: - Word / byte conversion

    private static func words(fromLittleEndian bytes: [UInt8]) -> [UInt32] {
        precondition(bytes.count % 4 == 0, "BLAKE3 words must come from a multiple of 4 bytes")
        return stride(from: 0, to: bytes.count, by: 4).map { offset -> UInt32 in
            let byte0 = UInt32(bytes[offset])
            let byte1 = UInt32(bytes[offset + 1]) << 8
            let byte2 = UInt32(bytes[offset + 2]) << 16
            let byte3 = UInt32(bytes[offset + 3]) << 24
            return byte0 | byte1 | byte2 | byte3
        }
    }

    private static func littleEndianBytes(_ words: [UInt32]) -> [UInt8] {
        var bytes = [UInt8]()
        bytes.reserveCapacity(words.count * 4)
        for word in words {
            bytes.append(UInt8(truncatingIfNeeded: word))
            bytes.append(UInt8(truncatingIfNeeded: word >> 8))
            bytes.append(UInt8(truncatingIfNeeded: word >> 16))
            bytes.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return bytes
    }
}
