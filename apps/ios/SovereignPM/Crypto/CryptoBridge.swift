import Foundation

/// Future UniFFI boundary. Operational secrets never cross it; callers hold opaque handles.
/// Sole audited exception: the recovery mnemonic during setup/import (transient, never persisted).
struct SessionHandle { let id: UInt64 }

protocol CryptoBridge {
    func decodeStrictCanonical(_ bytes: Data) throws -> Data
}
