import Crypto
import Foundation
import Testing
@_spi(ShadowsocksTesting) import NIOShadowsocks
import NIOShadowsocksTestUtils

/// Shadowsocks 2022 primitive tests.
///
/// The SIP022 KATs below were generated once from a throwaway Go program using `github.com/zeebo/blake3`
/// — the same BLAKE3 implementation the Go Shadowsocks 2022 libraries use — with fixed PSKs and a
/// fixed salt. That matters: they are an *independent* derivation, so a shared misreading of the
/// specification (a typo in a context string, the wrong concatenation order, the wrong key for an
/// identity header) fails here instead of round-tripping cleanly against our own encoder.
struct ShadowsocksCryptoTests {
    // MARK: - Fixtures

    /// `0x01, 0x02, …` for `keySize` bytes — the iPSK the Go generator used.
    private static func iPSK(_ method: ShadowsocksMethod) -> [UInt8] {
        (0..<method.keySize).map { UInt8(0x01 + $0) }
    }

    /// `0x81, 0x82, …` for `keySize` bytes — the uPSK the Go generator used.
    private static func uPSK(_ method: ShadowsocksMethod) -> [UInt8] {
        (0..<method.keySize).map { UInt8(0x81 + $0) }
    }

    private static func salt(_ method: ShadowsocksMethod) -> [UInt8] {
        [UInt8](repeating: 0xAB, count: method.saltSize)
    }

    /// The 16-byte separate header the Go generator used for the UDP vectors.
    private static let separateHeader: [UInt8] = (0..<16).map { UInt8(0xC0 + $0) }

    private static func config(_ method: ShadowsocksMethod) throws -> ShadowsocksConfiguration {
        try ShadowsocksConfiguration(method: method, psks: [iPSK(method), uPSK(method)])
    }

    private struct Vectors {
        let sessionSubkey: String
        let identitySubkey: String
        let uPSKHash16: String
        let tcpIdentityHeader: String
        let udpIdentityHeader: String
        let udpSeparateHeaderUnderIPSK: String
        let udpSeparateHeaderUnderUPSK: String
        let udpSessionSubkey: String
    }

    private static func vectors(for method: ShadowsocksMethod) -> Vectors {
        switch method {
        case .aes128gcm:
            Vectors(
                sessionSubkey: "066fc92b0b8f9a52bce7ce100652c25a",
                identitySubkey: "23817ce11881bec01004f3404f50b83f",
                uPSKHash16: "baa574ca5829917b2d6e693961205332",
                tcpIdentityHeader: "ddfd09b7554fe9615dc759649acff085",
                udpIdentityHeader: "729255363987ee979b184d24d34e38d4",
                udpSeparateHeaderUnderIPSK: "52cc5730173533ef1a881cb705f9905b",
                udpSeparateHeaderUnderUPSK: "b766f3753d62464cc22740280d3c933e",
                udpSessionSubkey: "70ce6b2613a63275d356c47420aa653f"
            )
        case .aes256gcm:
            Vectors(
                sessionSubkey: "4209cab7c0005e079954b1bdc8d8401cd3d3483299296b7b0d81b7afab9938c9",
                identitySubkey: "849a1573a1e3d9f25b17ae2fe5e62793a71c1fc150ba1a32beaa68aecd2b8093",
                uPSKHash16: "ebe4e42ad2c4a3823c6b9e28f26108bb",
                tcpIdentityHeader: "9b2099ece618c69f572287a1d533d36a",
                udpIdentityHeader: "2d763eb58a1965b8d6f2cb2037fba2e7",
                udpSeparateHeaderUnderIPSK: "a67960a45588351d4c2e635c7cf7c8c6",
                udpSeparateHeaderUnderUPSK: "9920a524925910644d12cdaeb4000fb2",
                udpSessionSubkey: "f2ec6ee23d3e56dadae1998d2a2208e687750f9d753c817396ed62b3fc14d0cf"
            )
        }
    }

    // MARK: - Method table

    // Every method-dependent test loops over `ShadowsocksMethod.allCases` rather than using
    // `@Test(arguments:)`. Xcode's `-only-testing` cannot select individual parameterized cases, so
    // an `arguments:` test silently reports "not run" under the tooling this repo uses — and a test
    // that is awkward to run is a test that stops being run. The method appears in each `#expect`
    // comment, so failure attribution is unchanged.

    @Test("method sizes are derived correctly")
    func methodSizes() {
        for method in ShadowsocksMethod.allCases {
            let expectedKeySize = method == .aes128gcm ? 16 : 32
            #expect(method.keySize == expectedKeySize, "key size for \(method.rawValue)")
            #expect(method.saltSize == method.keySize,
                    "SIP022 requires salt length == key length, \(method.rawValue)")
            #expect(method.responseHeaderSize == 11 + method.keySize,
                    "response header size for \(method.rawValue)")
            #expect(ShadowsocksMethod(rawValue: method.rawValue) == method)
        }
    }

    @Test("aes-128 is the default and chacha20 is not a supported method")
    func defaultMethodAndUnsupportedMethods() {
        #expect(ShadowsocksMethod.default == .aes128gcm)
        // EIH needs a block cipher, and sing-box rejects multi-user chacha20 configurations.
        #expect(ShadowsocksMethod(rawValue: "2022-blake3-chacha20-poly1305") == nil)
        #expect(ShadowsocksMethod(rawValue: "aes-256-gcm") == nil)
        #expect(ShadowsocksMethod.allCases.count == 2)
    }

    // MARK: - SIP022 subkey and identity-header KATs

    @Test("session subkey matches the independent Go vector")
    func sessionSubkeyMatchesVector() throws {
        for method in ShadowsocksMethod.allCases {
            let subkey = try Self.config(method).sessionSubkey(salt: Self.salt(method))
            let bytes = subkey.withUnsafeBytes { [UInt8]($0) }
            #expect(bytes.hexString == Self.vectors(for: method).sessionSubkey,
                    "session subkey for \(method.rawValue)")
            #expect(bytes.count == method.keySize)
        }
    }

    @Test("identity subkey matches the independent Go vector")
    func identitySubkeyMatchesVector() throws {
        for method in ShadowsocksMethod.allCases {
            let subkey = try Self.config(method).identitySubkey(index: 0, salt: Self.salt(method))
            #expect(subkey.hexString == Self.vectors(for: method).identitySubkey,
                    "identity subkey for \(method.rawValue)")
            #expect(subkey.count == method.keySize)
        }
    }

    @Test("PSK hashes are blake3(psk) truncated to one block")
    func pskHashesMatchVector() throws {
        for method in ShadowsocksMethod.allCases {
            let config = try Self.config(method)
            #expect(config.pskHashes[1].hexString == Self.vectors(for: method).uPSKHash16,
                    "hash(uPSK)[0..<16] for \(method.rawValue)")
            #expect(config.pskHashes.allSatisfy { $0.count == ShadowsocksMethod.blockSize })
        }
    }

    @Test("TCP identity header matches the independent Go vector")
    func tcpIdentityHeaderMatchesVector() throws {
        for method in ShadowsocksMethod.allCases {
            let headers = try Self.config(method).tcpIdentityHeaders(salt: Self.salt(method))
            #expect(headers.hexString == Self.vectors(for: method).tcpIdentityHeader,
                    "TCP identity header for \(method.rawValue)")
            #expect(headers.count == ShadowsocksMethod.blockSize)
        }
    }

    /// UDP identity headers are keyed by the *raw* iPSK and XOR the plaintext with the separate
    /// header — both differences from TCP, and both easy to get wrong in a way only a server notices.
    @Test("UDP identity header matches the independent Go vector")
    func udpIdentityHeaderMatchesVector() throws {
        for method in ShadowsocksMethod.allCases {
            let headers = try Self.config(method)
                .udpIdentityHeaders(separateHeader: Self.separateHeader)
            #expect(headers.hexString == Self.vectors(for: method).udpIdentityHeader,
                    "UDP identity header for \(method.rawValue)")
        }
    }

    @Test("UDP identity header differs from the TCP one for the same inputs")
    func udpAndTcpIdentityHeadersDiffer() throws {
        for method in ShadowsocksMethod.allCases {
            let config = try Self.config(method)
            let tcp = try config.tcpIdentityHeaders(salt: Self.salt(method))
            let udp = try config.udpIdentityHeaders(separateHeader: Self.separateHeader)
            #expect(tcp != udp,
                    "the TCP construction must not accidentally agree with UDP, \(method.rawValue)")
        }
    }

    /// The client encrypts the separate header under iPSK0; the server answers under the uPSK.
    @Test("UDP separate header encrypts under the expected PSK per direction")
    func udpSeparateHeaderKeys() throws {
        for method in ShadowsocksMethod.allCases {
            let vectors = Self.vectors(for: method)
            let clientToServer = try AESBlock.encrypt(block: Self.separateHeader, key: Self.iPSK(method))
            let serverToClient = try AESBlock.encrypt(block: Self.separateHeader, key: Self.uPSK(method))
            #expect(clientToServer.hexString == vectors.udpSeparateHeaderUnderIPSK,
                    "client->server separate header for \(method.rawValue)")
            #expect(serverToClient.hexString == vectors.udpSeparateHeaderUnderUPSK,
                    "server->client separate header for \(method.rawValue)")
        }
    }

    /// The UDP session subkey uses only the first 8 bytes of the separate header as salt.
    @Test("UDP session subkey uses the first 8 separate-header bytes as salt")
    func udpSessionSubkeyUsesSessionIDAsSalt() throws {
        for method in ShadowsocksMethod.allCases {
            let subkey = try Self.config(method)
                .sessionSubkey(salt: Array(Self.separateHeader.prefix(8)))
            let bytes = subkey.withUnsafeBytes { [UInt8]($0) }
            #expect(bytes.hexString == Self.vectors(for: method).udpSessionSubkey,
                    "UDP session subkey for \(method.rawValue)")
        }
    }

    // MARK: - Password parsing (trust boundary)

    @Test("parses a two-element chain into one identity header")
    func parsesTwoElementChain() throws {
        for method in ShadowsocksMethod.allCases {
            let password = "\(Data(Self.iPSK(method)).base64EncodedString()):"
                + Data(Self.uPSK(method)).base64EncodedString()
            let config = try ShadowsocksConfiguration(method: method, password: password)

            #expect(config.psks.count == 2, "chain length for \(method.rawValue)")
            #expect(config.identityHeaderCount == 1)
            #expect(config.psks[0] == Self.iPSK(method))
            #expect(config.sessionKey == Self.uPSK(method), "the last PSK is the uPSK")
        }
    }

    @Test("a single-element chain produces no identity headers")
    func parsesSingleElementChain() throws {
        for method in ShadowsocksMethod.allCases {
            let password = Data(Self.uPSK(method)).base64EncodedString()
            let config = try ShadowsocksConfiguration(method: method, password: password)

            #expect(config.identityHeaderCount == 0, "no EIH for \(method.rawValue)")
            #expect(try config.tcpIdentityHeaders(salt: Self.salt(method)).isEmpty)
            #expect(try config.udpIdentityHeaders(separateHeader: Self.separateHeader).isEmpty)
        }
    }

    @Test("a three-element chain produces two identity headers")
    func parsesThreeElementChain() throws {
        let method = ShadowsocksMethod.aes128gcm
        let keys = [Self.iPSK(method), Self.salt(method), Self.uPSK(method)]
        let password = keys.map { Data($0).base64EncodedString() }.joined(separator: ":")
        let config = try ShadowsocksConfiguration(method: method, password: password)

        #expect(config.identityHeaderCount == 2)
        #expect(try config.tcpIdentityHeaders(salt: Self.salt(method)).count == 32)
    }

    @Test("surrounding whitespace in a PSK component is tolerated")
    func toleratesWhitespace() throws {
        let method = ShadowsocksMethod.aes128gcm
        let encoded = Data(Self.uPSK(method)).base64EncodedString()
        let config = try ShadowsocksConfiguration(method: method, password: "  \(encoded)\n")
        #expect(config.sessionKey == Self.uPSK(method))
    }

    @Test("malformed passwords are rejected")
    func rejectsMalformedPasswords() {
        for password in ["", ":", "::", "   ", "not base64 at all!!", "aGVsbG8="] {
            #expect(throws: (any Error).self, "password \(password.debugDescription) must be rejected") {
                try ShadowsocksConfiguration(method: .aes128gcm, password: password)
            }
        }
    }

    @Test("an empty component between valid PSKs is rejected")
    func rejectsEmptyComponentBetweenValidPSKs() {
        let encoded = Data(Self.uPSK(.aes128gcm)).base64EncodedString()
        #expect(throws: ShadowsocksError.malformedPassword("empty PSK component")) {
            try ShadowsocksConfiguration(method: .aes128gcm, password: "\(encoded)::\(encoded)")
        }
    }

    /// The failure mode dual-method support introduces: a PSK sized for the other method.
    @Test("a PSK sized for the other method is rejected")
    func rejectsCrossMethodKeyLength() {
        let long = Data(Self.uPSK(.aes256gcm)).base64EncodedString()
        #expect(throws: ShadowsocksError.badKeyLength(expected: 16, actual: 32)) {
            try ShadowsocksConfiguration(method: .aes128gcm, password: long)
        }

        let short = Data(Self.uPSK(.aes128gcm)).base64EncodedString()
        #expect(throws: ShadowsocksError.badKeyLength(expected: 32, actual: 16)) {
            try ShadowsocksConfiguration(method: .aes256gcm, password: short)
        }
    }

    @Test("an empty PSK chain is rejected")
    func rejectsEmptyPSKChain() {
        #expect(throws: ShadowsocksError.malformedPassword("PSK chain is empty")) {
            try ShadowsocksConfiguration(method: .aes128gcm, psks: [])
        }
    }

    // MARK: - AES-ECB

    /// NIST FIPS-197 Appendix C known-answer vectors.
    @Test("single-block AES-ECB matches FIPS-197")
    func aesBlockMatchesFIPS197() throws {
        let plaintext = [UInt8](hex: "00112233445566778899aabbccddeeff")

        let key128 = [UInt8](hex: "000102030405060708090a0b0c0d0e0f")
        let encrypted = try AESBlock.encrypt(block: plaintext, key: key128)
        #expect(encrypted.hexString == "69c4e0d86a7b0430d8cdb78070b4c55a")

        let key256 = [UInt8](hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let encrypted256 = try AESBlock.encrypt(block: plaintext, key: key256)
        #expect(encrypted256.hexString == "8ea2b7ca516745bfeafc49904b496089")
    }

    @Test("AES-ECB round-trips and dispatches on key size")
    func aesBlockRoundTripsAndDispatchesOnKeySize() throws {
        let plaintext = [UInt8](hex: "00112233445566778899aabbccddeeff")
        let key128 = [UInt8](hex: "000102030405060708090a0b0c0d0e0f")
        let key256 = [UInt8](hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

        let round128 = try AESBlock.decrypt(block: try AESBlock.encrypt(block: plaintext, key: key128),
                                            key: key128)
        let round256 = try AESBlock.decrypt(block: try AESBlock.encrypt(block: plaintext, key: key256),
                                            key: key256)
        #expect(round128 == plaintext)
        #expect(round256 == plaintext)

        let with128 = try AESBlock.encrypt(block: plaintext, key: key128)
        let with256 = try AESBlock.encrypt(block: plaintext, key: key256)
        #expect(with128 != with256)
    }

    // MARK: - Nonce counter

    @Test("the AEAD nonce counter is a 12-byte little-endian counter")
    func nonceCounterIsLittleEndian() throws {
        var counter = AEADNonceCounter()
        #expect(counter.currentBytes == [UInt8](repeating: 0, count: 12))

        _ = try counter.next()
        #expect(counter.currentBytes.hexString == "010000000000000000000000",
                "the low-order byte must advance first")

        // Carry across the first byte boundary: little-endian gives 00 01, big-endian would give 01 00.
        for _ in 1..<256 {
            _ = try counter.next()
        }
        #expect(counter.currentBytes.hexString == "000100000000000000000000")

        // Carry across the second byte boundary.
        for _ in 256..<65536 {
            _ = try counter.next()
        }
        #expect(counter.currentBytes.hexString == "000001000000000000000000")
    }

    @Test("successive nonces are distinct")
    func noncesAreDistinct() throws {
        var counter = AEADNonceCounter()
        var nonces = [String]()
        for _ in 0..<1000 {
            nonces.append([UInt8](try counter.next()).hexString)
        }
        #expect(Set(nonces).count == nonces.count)
    }

    // MARK: - Replay window

    /// `#expect` evaluates its expression in a closure, so `accept` cannot be called inside one.
    /// Replaying a whole sequence and comparing the verdicts reads better regardless.
    private static func replayVerdicts(_ ids: [UInt64]) -> [Bool] {
        var window = ReplayWindow()
        return ids.map { window.accept($0) }
    }

    @Test("the replay window accepts in-order and rejects duplicates")
    func replayWindowBasics() {
        // Packet ID 0 is a legitimate first packet; the repeats of 2 and 0 are not.
        #expect(Self.replayVerdicts([0, 1, 2, 2, 0]) == [true, true, true, false, false])
    }

    @Test("the replay window accepts out-of-order packets inside the window")
    func replayWindowAcceptsReordering() {
        #expect(Self.replayVerdicts([0, 1, 2, 5, 3, 4, 3])
            == [true, true, true, true, true, true, false])
    }

    /// Off-by-one at the window edge is the classic bug in this algorithm.
    @Test("the replay window edge is exactly 64 packets")
    func replayWindowEdge() {
        // Offset 63 is inside the window; offset 64 is not.
        #expect(Self.replayVerdicts([1000, 1000 - 63, 1000 - 64, 0])
            == [true, true, false, false])
    }

    @Test("a far-forward jump reslides the window")
    func replayWindowJump() {
        // After resliding, 10_000 is still a duplicate, 9_999 is new, and 0 is far behind.
        #expect(Self.replayVerdicts([0, 10_000, 10_000, 9_999, 0])
            == [true, true, false, true, false])
    }

    @Test("a rejected packet ID does not perturb window state")
    func replayWindowRejectionIsInert() {
        // The two rejections in the middle must leave the window able to accept 101 and 99.
        #expect(Self.replayVerdicts([100, 100, 0, 101, 99])
            == [true, false, false, true, true])
    }

    // MARK: - Timestamps

    @Test("timestamps within ±30s are accepted and beyond are rejected")
    func timestampWindow() throws {
        let now: UInt64 = 1_700_000_000

        for skew in [0, 1, 29, 30] as [UInt64] {
            #expect(throws: Never.self) {
                try ShadowsocksConfiguration.validateTimestamp(now + skew, now: now)
            }
            #expect(throws: Never.self) {
                try ShadowsocksConfiguration.validateTimestamp(now - skew, now: now)
            }
        }

        #expect(throws: ShadowsocksError.timestampOutOfWindow(skewSeconds: 31)) {
            try ShadowsocksConfiguration.validateTimestamp(now + 31, now: now)
        }
        #expect(throws: ShadowsocksError.timestampOutOfWindow(skewSeconds: -31)) {
            try ShadowsocksConfiguration.validateTimestamp(now - 31, now: now)
        }
    }

    /// A wildly out-of-range value must not overflow its way into the accepted window.
    @Test("extreme timestamps are rejected without overflowing")
    func timestampExtremesDoNotOverflow() {
        let now: UInt64 = 1_700_000_000
        #expect(throws: (any Error).self) {
            try ShadowsocksConfiguration.validateTimestamp(.max, now: now)
        }
        #expect(throws: (any Error).self) {
            try ShadowsocksConfiguration.validateTimestamp(0, now: now)
        }
    }

    // MARK: - Padding and addresses

    @Test("random padding stays within the specified bound and varies")
    func randomPaddingBounds() {
        var lengths = Set<Int>()
        for _ in 0..<100 {
            let padding = ShadowsocksConfiguration.randomPadding()
            #expect(padding.count <= ShadowsocksConfiguration.maxPaddingLength)
            lengths.insert(padding.count)
        }
        #expect(lengths.count > 1, "padding length must actually vary")
    }

    @Test("address encoding covers domains, IPv4 and IPv6")
    func addressEncoding() {
        let domain = ShadowsocksConfiguration.addressBytes(host: "example.com", port: 443)
        #expect(domain[0] == 3, "ATYP 3 is a domain name")
        #expect(domain[1] == 11, "length-prefixed domain")
        #expect(Array(domain.suffix(2)) == [0x01, 0xBB], "port 443 big-endian")

        let v4 = ShadowsocksConfiguration.addressBytes(host: "192.0.2.10", port: 8388)
        #expect(v4[0] == 1, "ATYP 1 is IPv4")
        #expect(Array(v4[1..<5]) == [192, 0, 2, 10])
        #expect(Array(v4.suffix(2)) == [0x20, 0xC4], "port 8388 big-endian")

        let v6 = ShadowsocksConfiguration.addressBytes(host: "2001:db8::1", port: 443)
        #expect(v6[0] == 4, "ATYP 4 is IPv6")
        #expect(v6.count == 1 + 16 + 2)
    }
}
