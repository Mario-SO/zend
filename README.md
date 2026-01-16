# zend

A secure peer-to-peer file transfer engine written in Zig.

## Features

- **Identity management** using Ed25519 keypairs
- **Secure transport** using Noise IK protocol
- **Peer authentication** with TOFU (Trust On First Use)
- **Encrypted file transfer** with integrity verification
- **JSON output** for IPC with hermes

## Cryptographic Primitives

| Purpose | Algorithm |
|---------|-----------|
| Identity | Ed25519 |
| Key Agreement | X25519 (Noise IK) |
| AEAD | ChaCha20-Poly1305 |
| Hashing | SHA-256 |
| KDF | HKDF-SHA256 |

All cryptography uses Zig's standard library (`std.crypto`), which wraps audited implementations.

## Building

Requires Zig 0.15.2 or later.

```bash
# Build
zig build

# Run tests
zig build test

# Build release
zig build -Doptimize=ReleaseSafe
```

## Usage

All output is JSON (one object per line) for machine consumption.

### Identity Management

```bash
# Generate a new identity
zend id init

# Show your identity (public key and fingerprint)
zend id show
```

Output:
```json
{"event":"identity_created","public_key":"<base64>","fingerprint":"<hex>"}
```

### Peer Management

```bash
# Add a trusted peer
zend peer add alice "their_public_key_base64" "192.168.1.100:7654"

# Update trust state
zend peer trust alice blocked

# List all peers
zend peer list

# Remove a peer
zend peer remove alice
```

### File Transfer

```bash
# Send a file to a peer
zend send document.pdf alice

# Receive files (listen on default port 7654)
zend receive

# Receive on a custom port
zend receive --port 8080
```

## Using with Tailscale

For transferring files between computers across the internet (different cities, countries, etc.), we recommend [Tailscale](https://tailscale.com) - a free mesh VPN that requires no port forwarding or firewall changes.

### Setup (one time per device)

```bash
# Install Tailscale
# see https://tailscale.com/download

# Start and authenticate
sudo tailscale up

# Get your Tailscale IP
tailscale ip -4
# Example: 100.64.0.2
```

### Example: Country A to Country B

**Friend in Country B (receiver):**
```bash
tailscale ip -4              # Note: 100.64.0.2
zend id show                 # Share the public_key with sender
zend receive
```

**You in Country A (sender):**
```bash
zend peer add country_b "FRIENDS_PUBLIC_KEY" "100.64.0.2:7654"
zend send vacation_photos.zip country_b
```

### Why Tailscale?

- **No port forwarding** - works through NAT and firewalls automatically
- **Private network** - the `100.x.x.x` IPs are only reachable by your Tailscale devices
- **Double encryption** - Tailscale (WireGuard) + zend (Noise IK)
- **Free** for personal use (up to 100 devices)

## JSON Events

| Event | Fields | Description |
|-------|--------|-------------|
| `identity_created` | `public_key`, `fingerprint` | New identity generated |
| `identity_loaded` | `public_key`, `fingerprint` | Identity loaded from disk |
| `peer_added` | `name`, `fingerprint` | Peer added to trusted list |
| `peer_removed` | `name` | Peer removed |
| `peer_trust_updated` | `name`, `trust` | Peer trust updated |
| `peer_list` | `peers` | List of all peers |
| `connecting` | `peer`, `address` | Connecting to peer |
| `listening` | `port` | Listening for connections |
| `handshake_complete` | `peer` | Noise handshake succeeded |
| `transfer_start` | `file`, `size`, `peer` | File transfer started |
| `progress` | `bytes`, `percent` | Transfer progress |
| `transfer_complete` | `file`, `hash` | Transfer completed |
| `error` | `code`, `message` | Error occurred |

## Noise IK Protocol

zend uses the Noise IK handshake pattern for authenticated key exchange:

```
-> e, es, s, ss   (initiator sends ephemeral, encrypts static key)
<- e, ee, se      (responder completes handshake)
```

The IK pattern assumes the initiator knows the responder's static public key (from the trusted peers list), enabling immediate mutual authentication.

## Security Guarantees

**Protected against:**
- Network interception (all traffic encrypted)
- Man-in-the-middle attacks (mutual authentication)
- Data tampering (authenticated encryption + hash verification)
- Replay attacks (nonce-based encryption)

**Not protected against:**
- Compromised operating system
- Malicious authorized peers
- Side-channel attacks

## Architecture

```
zend/src/
├── main.zig              # CLI entry, command parsing
├── root.zig              # Public library API
├── identity/
│   ├── keypair.zig       # Ed25519 key generation
│   └── storage.zig       # Identity file I/O
├── peer/
│   ├── manager.zig       # Peer CRUD operations
│   └── storage.zig       # JSON persistence
├── transport/
│   ├── tcp.zig           # TCP client/server
│   ├── frame.zig         # Length-prefixed framing
│   ├── noise.zig         # Noise IK implementation
│   └── channel.zig       # Secure channel abstraction
├── protocol/
│   ├── messages.zig      # Message serialization
│   └── transfer.zig      # File transfer state machine
└── utils/
    ├── json.zig          # JSON event output
    └── memory.zig        # Secure memory wiping
```

## File Locations

- Identity: `~/.zend/identity`
- Peers: `~/.zend/peers.json`
- Received files: Current working directory

## License

MIT
