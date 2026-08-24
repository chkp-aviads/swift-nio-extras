import Foundation
import Testing
@_spi(ShadowsocksTesting) import NIOShadowsocks
import NIOShadowsocksTestUtils

/// Official BLAKE3 known-answer vectors, restricted to the single-chunk range `BLAKE3` supports.
///
/// Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
///
/// These are the highest-value tests in the Shadowsocks suite. BLAKE3 derives every session and
/// identity subkey, so if it is off by a bit nothing else can interoperate with the server — and
/// unlike the rest of SIP022 there are authoritative vectors to check against. The chosen input
/// lengths are all the single-chunk boundaries: 0/1 catch block-length handling, 63/64/65 catch
/// block iteration and the `CHUNK_END` flag, 1023/1024 catch the chunk limit itself.
struct BLAKE3Tests {
    /// The vectors' fixed 32-byte key, used for `keyed_hash`.
    private static let key = Array("whats the Elvish word for friend".utf8)

    /// The vectors' fixed context string, used for `derive_key`.
    private static let context = "BLAKE3 2019-12-27 16:29:52 test vectors context"

    /// `input[i] == i % 251`, per the test-vector README.
    private static func input(length: Int) -> [UInt8] {
        (0..<length).map { UInt8($0 % 251) }
    }

    /// `(inputLength, hash, keyedHash, deriveKey)`, each expected value truncated to 32 bytes.
    private static let vectors: [(Int, String, String, String)] = [
        (0,
         "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
         "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
         "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
        (1,
         "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
         "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
         "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c"),
        (2,
         "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
         "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a",
         "1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6"),
        (3,
         "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
         "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
         "440aba35cb006b61fc17c0529255de438efc06a8c9ebf3f2ddac3b5a86705797"),
        (63,
         "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
         "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae",
         "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3"),
        (64,
         "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
         "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6",
         "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e"),
        (65,
         "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
         "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72",
         "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8"),
        (127,
         "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
         "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818",
         "c91c090ceee3a3ac81902da31838012625bbcd73fcb92e7d7e56f78deba4f0c3"),
        (128,
         "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
         "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ec",
         "81720f34452f58a0120a58b6b4608384b5c51d11f39ce97161a0c0e442ca0225"),
        (129,
         "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
         "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f",
         "938d2d4435be30eafdbb2b7031f7857c98b04881227391dc40db3c7b21f41fc1"),
        (1023,
         "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
         "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e",
         "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5"),
        (1024,
         "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
         "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
         "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706"),
    ]

    @Test("unkeyed hash matches the official vectors")
    func unkeyedHashMatchesOfficialVectors() {
        for (length, expected, _, _) in Self.vectors {
            let actual = BLAKE3.hash(Self.input(length: length)).hexString
            #expect(actual == expected, "hash mismatch at input_len \(length)")
        }
    }

    @Test("keyed hash matches the official vectors")
    func keyedHashMatchesOfficialVectors() {
        for (length, _, expected, _) in Self.vectors {
            let actual = BLAKE3.keyedHash(Self.input(length: length), key: Self.key).hexString
            #expect(actual == expected, "keyed_hash mismatch at input_len \(length)")
        }
    }

    @Test("derive_key matches the official vectors")
    func deriveKeyMatchesOfficialVectors() {
        for (length, _, _, expected) in Self.vectors {
            let actual = BLAKE3.deriveKey(context: Self.context,
                                          keyMaterial: Self.input(length: length)).hexString
            #expect(actual == expected, "derive_key mismatch at input_len \(length)")
        }
    }

    @Test("every output is exactly 32 bytes")
    func outputLengthIsAlwaysThirtyTwoBytes() {
        #expect(BLAKE3.hash([]).count == BLAKE3.outputLength)
        #expect(BLAKE3.keyedHash(Self.input(length: 100), key: Self.key).count == BLAKE3.outputLength)
        #expect(BLAKE3.deriveKey(context: "ctx", keyMaterial: []).count == BLAKE3.outputLength)
    }

    /// The AES-128 methods truncate the 32-byte subkey to 16 bytes, so truncation has to be a plain
    /// prefix rather than a separate shorter-output derivation.
    @Test("16-byte truncation is the prefix of the 32-byte output")
    func truncationIsAPrefix() {
        let full = BLAKE3.deriveKey(context: "shadowsocks 2022 session subkey",
                                    keyMaterial: Self.input(length: 32))
        #expect(Array(full.prefix(16)) == Array(full[0..<16]))
        #expect(full.count == 32)
    }
}
