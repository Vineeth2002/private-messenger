# iOS skeleton (Phase A)

Swift/SwiftUI app + Notification Service Extension boundary. No Xcode project file is
checked in yet: generate one (e.g. XcodeGen) when Stage 2 starts.

Non-claims: the Secure Enclave does not execute Ed25519/X25519 for this protocol. Platform
Keychain / App Group storage protects wrapped key blobs (PPAL Level 2); the protocol
algorithms run in the native Rust boundary.
