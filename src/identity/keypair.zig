//! Ed25519/X25519 key generation and identity management.
//!
//! Ed25519 keys are used for identity and signing.
//! X25519 keys are derived from Ed25519 for Noise protocol key agreement.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const memory = @import("../utils/memory.zig");

/// Ed25519 public key size in bytes
pub const ed25519_public_key_len = Ed25519.PublicKey.encoded_length;
/// Ed25519 secret key size in bytes
pub const ed25519_secret_key_len = Ed25519.SecretKey.encoded_length;
/// X25519 public key size in bytes
pub const x25519_public_key_len = X25519.public_length;
/// X25519 secret key size in bytes
pub const x25519_secret_key_len = X25519.secret_length;
/// Fingerprint size (SHA-256 hash, hex-encoded)
pub const fingerprint_len = 64;

/// An Ed25519 keypair representing a zend identity
pub const Identity = struct {
    public_key: [ed25519_public_key_len]u8,
    secret_key: [ed25519_secret_key_len]u8,

    /// Securely wipe the secret key from memory
    pub fn wipe(self: *Identity) void {
        memory.secureZero(&self.secret_key);
    }

    /// Compute the fingerprint (SHA-256 hash of public key, hex-encoded)
    pub fn fingerprint(self: *const Identity) [fingerprint_len]u8 {
        return computeFingerprint(&self.public_key);
    }

    /// Get X25519 public key for Noise protocol
    pub fn x25519PublicKey(self: *const Identity) ![x25519_public_key_len]u8 {
        return ed25519PublicKeyToX25519(self.public_key);
    }

    /// Get X25519 secret key for Noise protocol
    pub fn x25519SecretKey(self: *Identity) [x25519_secret_key_len]u8 {
        return ed25519SecretKeyToX25519(self.secret_key);
    }
};

/// Generate a new identity (Ed25519 keypair)
pub fn generateIdentity() Identity {
    const kp = Ed25519.KeyPair.generate();
    return Identity{
        .public_key = kp.public_key.toBytes(),
        .secret_key = kp.secret_key.toBytes(),
    };
}

/// Compute fingerprint from public key bytes
pub fn computeFingerprint(public_key: *const [ed25519_public_key_len]u8) [fingerprint_len]u8 {
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(public_key, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

/// Convert an Ed25519 public key to an X25519 public key
pub fn ed25519PublicKeyToX25519(ed_public: [ed25519_public_key_len]u8) ![x25519_public_key_len]u8 {
    const ed_pk = Ed25519.PublicKey.fromBytes(ed_public) catch {
        return error.InvalidPublicKey;
    };
    return X25519.publicKeyFromEd25519(ed_pk) catch {
        return error.InvalidPublicKey;
    };
}

/// Convert an Ed25519 secret key to an X25519 secret key
pub fn ed25519SecretKeyToX25519(ed_secret: [ed25519_secret_key_len]u8) [x25519_secret_key_len]u8 {
    // The Ed25519 secret key contains seed (first 32 bytes) + public key (last 32 bytes)
    // Hash the seed with SHA-512 and take first 32 bytes (clamped)
    var hash: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(ed_secret[0..32], &hash, .{});

    // Clamp the scalar (same clamping as X25519)
    var x25519_secret: [32]u8 = hash[0..32].*;
    x25519_secret[0] &= 248;
    x25519_secret[31] &= 127;
    x25519_secret[31] |= 64;

    // Wipe the hash
    memory.secureZero(&hash);

    return x25519_secret;
}

/// Perform X25519 key agreement (Diffie-Hellman)
pub fn x25519KeyAgreement(
    our_secret: [x25519_secret_key_len]u8,
    their_public: [x25519_public_key_len]u8,
) ![32]u8 {
    return X25519.scalarmult(our_secret, their_public) catch {
        return error.KeyAgreementFailed;
    };
}

/// Encode bytes to base64 standard encoding
pub fn encodeBase64(input: []const u8, output: []u8) []const u8 {
    return std.base64.standard.Encoder.encode(output, input);
}

/// Calculate the required buffer size for base64 encoding
pub fn base64EncodedLen(input_len: usize) usize {
    return std.base64.standard.Encoder.calcSize(input_len);
}

/// Decode base64 to bytes
pub fn decodeBase64(input: []const u8, output: []u8) ![]u8 {
    const len = try std.base64.standard.Decoder.calcSizeForSlice(input);
    try std.base64.standard.Decoder.decode(output[0..len], input);
    return output[0..len];
}

// Tests
test "generate identity" {
    var id = generateIdentity();
    defer id.wipe();

    // Public key should not be all zeros
    var all_zero = true;
    for (id.public_key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "fingerprint generation" {
    var id = generateIdentity();
    defer id.wipe();

    const fp = id.fingerprint();

    // Fingerprint should be 64 hex characters
    try std.testing.expectEqual(@as(usize, 64), fp.len);

    // All characters should be valid hex
    for (fp) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "ed25519 to x25519 conversion" {
    var id = generateIdentity();
    defer id.wipe();

    const x_public = try id.x25519PublicKey();
    var x_secret = id.x25519SecretKey();
    defer memory.secureZero(&x_secret);

    // Verify that the derived X25519 keypair is valid
    const expected_public = X25519.recoverPublicKey(x_secret) catch unreachable;
    try std.testing.expectEqualSlices(u8, &expected_public, &x_public);
}

test "x25519 key agreement" {
    var id1 = generateIdentity();
    defer id1.wipe();
    var id2 = generateIdentity();
    defer id2.wipe();

    const x1_pub = try id1.x25519PublicKey();
    var x1_sec = id1.x25519SecretKey();
    defer memory.secureZero(&x1_sec);

    const x2_pub = try id2.x25519PublicKey();
    var x2_sec = id2.x25519SecretKey();
    defer memory.secureZero(&x2_sec);

    // Both parties should derive the same shared secret
    const shared1 = try x25519KeyAgreement(x1_sec, x2_pub);
    const shared2 = try x25519KeyAgreement(x2_sec, x1_pub);

    try std.testing.expectEqualSlices(u8, &shared1, &shared2);
}

test "base64 round trip" {
    const original = "Hello, World!";
    var encoded: [256]u8 = undefined;
    var decoded: [256]u8 = undefined;

    const enc_slice = encodeBase64(original, &encoded);
    const dec_slice = try decodeBase64(enc_slice, &decoded);

    try std.testing.expectEqualSlices(u8, original, dec_slice);
}
