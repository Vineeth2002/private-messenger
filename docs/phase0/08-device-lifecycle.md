# 08 - Account and Device Lifecycle

Status: ARCHITECTURAL (frozen).

Account root: AccountID, username, account epoch, IRC. Device: DeviceID, DSK (Ed25519), DDHK (X25519),
signed prekey, one-time prekeys, push key, device certificate. Account identity is never conflated
with device cryptographic identity.

## Platform key protection (PPAL)
- Level 1 (hardware-isolated execution of the algorithms): capability-dependent, future/deferred for
  Ed25519/X25519; NOT assumed on stock Android/iOS.
- Level 2 (V1 baseline): keys generated/operated in the zeroizing native Rust boundary, encrypted at
  rest, wrapped by a platform KEK. Android: Keystore (prefer StrongBox/TEE, capability discovery, no
  assumed hardware Ed25519). iOS: Keychain/App Group storage; no claim that the Secure Enclave runs
  Ed25519/X25519.

## Catastrophic recovery (Model A)
1 fresh device derives recovery key; 2 generates new epoch keys; 3 signs epoch-transition certificate;
4 directory verifies commitment; 5 verifies recovery signature; 6 enters 48-hour timelock; 7 active
devices alerted; 8 an active device can abort; 9 after timeout the new epoch is authoritative.
Recovery secret rotation is possible from an authenticated existing device via the frozen procedure
(resolved by the architects; the procedure text is to be added to this document before it is implemented).
