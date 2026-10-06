import Foundation

/// PPAL Level 2 baseline: keys live in the native Rust boundary, encrypted at rest,
/// wrapped by a platform KEK. The Secure Enclave is NOT assumed to run Ed25519/X25519.
enum Ppal { case level1HardwareIsolated, level2WrappedAtRest }

struct KekCapabilities { let secureEnclaveBackedWrapping: Bool; let achievedPpal: Ppal }

protocol PlatformKek {
    func discover() -> KekCapabilities
    func wrap(_ blob: Data) throws -> Data
    func unwrap(_ blob: Data) throws -> Data
}

/// Phase A: intentionally unimplemented.
struct UnimplementedPlatformKek: PlatformKek {
    func discover() -> KekCapabilities { fatalError("Phase B: Keychain/App Group capability discovery") }
    func wrap(_ blob: Data) throws -> Data { fatalError("Phase B") }
    func unwrap(_ blob: Data) throws -> Data { fatalError("Phase B") }
}
