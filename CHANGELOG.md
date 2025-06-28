## v1.0.3-e2e — Security hardening

### Added
- Immediate **forward secrecy**: handshake now prefers fresh Kyber *ephemeral* keys; shared secret derives from Ephemeral ⊕ Identity.
- **Random-salt HKDF** per message; 32-byte salt rides in the ciphertext header and is covered by the AEAD tag.
- **Authenticated-Data (AAD)** binding: sender/recipient IDs, timestamp, rotation epoch & salt are now included in every ChaCha20-Poly1305 MAC.
- **TLS certificate channel-binding**: the SHA-256 fingerprint of the QUIC self-signed certificate is signed inside each peer-announcement and verified after the TLS handshake — blocks early MITM.

### Changed
- Structs updated: `EncryptedMessage.Salt`, `PeerAnnouncement.TLSCertFingerprint`.
- Key derivation uses `deriveKeyWithSalt()` for new messages; fallback remains for legacy traffic.
- QUIC transport now computes its local certificate fingerprint and validates the remote one on connect.

### Removed
- Deterministic HKDF salt.

### Compatibility
Wire-compatible with ≤ v1.0.2; new protections activate automatically when **both** sides run ≥ v1.0.3. 