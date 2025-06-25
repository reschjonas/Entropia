# QuantTerm 🛡️

<p align="center">
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"></a>
  <img src="https://img.shields.io/badge/Status-Prototype-orange?style=for-the-badge" alt="Project Status">
</p>

 Post-Quantum End-to-End Encrypted Terminal Chat
 ==============================================

> **Prototype – not production-ready.  Do **NOT** rely on it for real secrets.**

QuantTerm is a tiny two-peer chat client that showcases how modern **post-quantum cryptography** can be combined with some neat discovery tricks to create a secure channel over any IP network in only a few hundred lines of Go.

**Actively developed & headed toward production-readiness — feedback and PRs welcome!**

Instead of trying to replace Signal or Matrix, the project focuses on demonstrating:

* a cryptographically authenticated *identity*,
* quantum-safe key agreement (Kyber-1024),
* message authentication (Dilithium-5),
* periodic key rotation for forward secrecy, and
* a super-lightweight UDP transport that usually lives inside a WireGuard tunnel.

Curious about the internals?  See **TECHNICAL_OVERVIEW.md**.

---

## Table of Contents

- [Caveats & Threat Model](#️-caveats--threat-model)
- [Highlight Features](#highlight-features)
- [Quick-Start](#quick-start)
- [Fingerprint Verification](#fingerprint-verification)
- [Roadmap / Ideas](#roadmap--ideas)
- [Licence](#licence)

---

## ⚠️  Caveats & Threat Model

* **Not audited.**  Only hobbyist eyes have looked at the code so far.
* **Only two peers.**  There is one *creator* (listener) and one *joiner* (dialer).
* **IP address exposure.**  Peers connect directly; your public IP is visible to your chat partner.
* **Trust on first use.**  Always compare the **identity fingerprints** via a trusted channel before chatting.

---

## Highlight Features

|  |  |
| :--- | :--- |
| 🛡 | **Post-quantum crypto** – Kyber-1024 KEM & Dilithium-5 signatures |
| 🔄 | **Perfect forward secrecy** – automatic key rotation every 15 min |
| 🔍 | **LAN discovery** – mDNS plus UDP broadcast |
| 🌐 | **Internet discovery** – STUN for external IP + address published on `kvdb.io` |
| 📡 | **Transport** – raw UDP with a small JSON wrapper (best inside WireGuard) |
| 👀 | **TUI** – shows peer list, verification status & fingerprints |

---

## Installation

### Prerequisites

- **Go 1.24+** – install from <https://go.dev/dl/> or your OS package manager.
- **UDP reachable** network (firewalls/NAT that allow an arbitrary UDP port).
- *(Optional)* **WireGuard** if you prefer to tunnel traffic: `sudo apt install wireguard-tools`.

### 1. Grab a pre-built binary *(coming soon)*

When GitHub Releases are enabled you will simply download the archive for your OS/CPU, unpack and run `./quantterm`.

### 2. Build from source (cross-platform)

```bash
# Clone & build
git clone https://github.com/reschjonas/quantterm.git
cd quantterm

# Static binary for your OS/arch
go build -trimpath -ldflags="-s -w" -o quantterm .

# Or install into $GOBIN in one line (Go >= 1.20)
go install github.com/reschjonas/quantterm@latest
```

**Verify build** (optional):

```bash
quantterm --version  # should print the version banner
```

---

## Quick-Start

Prerequisite: **Go 1.24+**

```bash
# build
go build -o quantterm .

# Terminal 1 – creator
./quantterm create

# Terminal 2 – joiner (auto-discovery)
./quantterm join <RoomID>

# Terminal 2 – joiner (manual address)
./quantterm join <RoomID> <ip:port>
```

You can start chatting once *both* sides print:

```
🟢 Handshake complete — you can start chatting securely.
```

---

## Fingerprint Verification

Every peer prints a fingerprint derived from its long-term public keys.  Compare these fingerprints **out-of-band** (phone, video call, etc.) before trusting any messages.

---

## Roadmap / Ideas

* NAT traversal via ICE/QUIC
* Simple group chats (N-peers)
* File transfer & chat history persistence
* Replace `kvdb.io` with a small DHT
* Actual GUI

PRs and suggestions are welcome!

---

## Licence

MIT 