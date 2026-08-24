import Foundation

/// Hex conversion shared by the Shadowsocks and BLAKE3 test suites, all of which are driven by
/// known-answer vectors pasted in as hex literals.
extension [UInt8] {
    public var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Parses an even-length hex string. Traps on malformed input — these are test literals, so a
    /// typo should fail loudly at the point of the mistake rather than silently produce short data.
    public init(hex: String) {
        precondition(hex.count.isMultiple(of: 2), "hex literal must have an even length: \(hex)")
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else {
                preconditionFailure("invalid hex literal: \(hex)")
            }
            bytes.append(byte)
            index = next
        }
        self = bytes
    }
}
