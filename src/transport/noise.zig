//! Noise IK handshake implementation.
//!
//! Implements the Noise IK pattern for authenticated key exchange.
//! IK pattern: initiator knows responder's static public key.
//!
//! Handshake pattern:
//!   -> e, es, s, ss   (initiator sends ephemeral, encrypts static)
//!   <- e, ee, se      (responder sends ephemeral, derives keys)
//!
//! Uses: X25519 for DH, ChaChaPoly for AEAD, SHA256 for hashing

const std = @import("std");
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const memory = @import("../utils/memory.zig");
const keypair = @import("../identity/keypair.zig");

/// Noise protocol name for IK pattern
const protocol_name = "Noise_IK_25519_ChaChaPoly_SHA256";

/// Key sizes
pub const key_size: usize = 32;
pub const nonce_size: usize = 12;
pub const tag_size: usize = 16;

/// Cipher state for symmetric encryption
pub const CipherState = struct {
    key: [key_size]u8,
    nonce: u64,

    pub fn init(key: [key_size]u8) CipherState {
        return CipherState{
            .key = key,
            .nonce = 0,
        };
    }

    /// Encrypt plaintext with associated data
    pub fn encrypt(self: *CipherState, plaintext: []const u8, ad: []const u8, ciphertext: []u8) ![tag_size]u8 {
        var nonce_bytes: [nonce_size]u8 = .{0} ** nonce_size;
        std.mem.writeInt(u64, nonce_bytes[4..12], self.nonce, .little);

        var tag: [tag_size]u8 = undefined;
        ChaCha20Poly1305.encrypt(ciphertext[0..plaintext.len], &tag, plaintext, ad, nonce_bytes, self.key);

        self.nonce += 1;
        return tag;
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(self: *CipherState, ciphertext: []const u8, tag: [tag_size]u8, ad: []const u8, plaintext: []u8) !void {
        var nonce_bytes: [nonce_size]u8 = .{0} ** nonce_size;
        std.mem.writeInt(u64, nonce_bytes[4..12], self.nonce, .little);

        ChaCha20Poly1305.decrypt(plaintext[0..ciphertext.len], ciphertext, tag, ad, nonce_bytes, self.key) catch {
            return error.DecryptionFailed;
        };

        self.nonce += 1;
    }

    /// Wipe the key from memory
    pub fn wipe(self: *CipherState) void {
        memory.secureZero(&self.key);
    }
};

/// Symmetric state for Noise handshake
const SymmetricState = struct {
    chaining_key: [key_size]u8,
    hash: [key_size]u8,
    cipher: ?CipherState,

    fn init() SymmetricState {
        // Initialize with protocol name hash
        var hash: [Sha256.digest_length]u8 = undefined;
        if (protocol_name.len <= key_size) {
            var padded: [key_size]u8 = .{0} ** key_size;
            @memcpy(padded[0..protocol_name.len], protocol_name);
            hash = padded;
        } else {
            Sha256.hash(protocol_name, &hash, .{});
        }

        return SymmetricState{
            .chaining_key = hash,
            .hash = hash,
            .cipher = null,
        };
    }

    fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hasher = Sha256.init(.{});
        hasher.update(&self.hash);
        hasher.update(data);
        self.hash = hasher.finalResult();
    }

    fn mixKey(self: *SymmetricState, input_key_material: []const u8) void {
        // HKDF with chaining key
        var temp_key: [key_size]u8 = undefined;
        var output1: [key_size]u8 = undefined;
        var output2: [key_size]u8 = undefined;

        hkdf(&self.chaining_key, input_key_material, &temp_key, &output1, &output2);

        self.chaining_key = output1;
        self.cipher = CipherState.init(output2);

        memory.secureZero(&temp_key);
    }

    fn encryptAndHash(self: *SymmetricState, plaintext: []const u8, ciphertext: []u8) ![tag_size]u8 {
        if (self.cipher) |*cipher| {
            const tag = try cipher.encrypt(plaintext, &self.hash, ciphertext);
            // Use fixed buffer for hash input (max key_size + tag_size)
            var to_hash: [key_size + tag_size]u8 = undefined;
            @memcpy(to_hash[0..plaintext.len], ciphertext[0..plaintext.len]);
            @memcpy(to_hash[plaintext.len..][0..tag_size], &tag);
            self.mixHash(to_hash[0 .. plaintext.len + tag_size]);
            return tag;
        } else {
            @memcpy(ciphertext[0..plaintext.len], plaintext);
            self.mixHash(plaintext);
            return .{0} ** tag_size;
        }
    }

    fn decryptAndHash(self: *SymmetricState, ciphertext: []const u8, tag: [tag_size]u8, plaintext: []u8) !void {
        if (self.cipher) |*cipher| {
            // Use fixed buffer for hash input (max key_size + tag_size)
            var to_hash: [key_size + tag_size]u8 = undefined;
            @memcpy(to_hash[0..ciphertext.len], ciphertext);
            @memcpy(to_hash[ciphertext.len..][0..tag_size], &tag);

            try cipher.decrypt(ciphertext, tag, &self.hash, plaintext);
            self.mixHash(to_hash[0 .. ciphertext.len + tag_size]);
        } else {
            @memcpy(plaintext[0..ciphertext.len], ciphertext);
            self.mixHash(ciphertext);
        }
    }

    fn split(self: *SymmetricState) struct { send: CipherState, recv: CipherState } {
        var temp_key: [key_size]u8 = undefined;
        var key1: [key_size]u8 = undefined;
        var key2: [key_size]u8 = undefined;

        hkdf(&self.chaining_key, &.{}, &temp_key, &key1, &key2);
        memory.secureZero(&temp_key);

        return .{
            .send = CipherState.init(key1),
            .recv = CipherState.init(key2),
        };
    }

    fn wipe(self: *SymmetricState) void {
        memory.secureZero(&self.chaining_key);
        memory.secureZero(&self.hash);
        if (self.cipher) |*c| {
            c.wipe();
        }
    }
};

/// HKDF using HMAC-SHA256
fn hkdf(chaining_key: *const [key_size]u8, input: []const u8, temp_key: *[key_size]u8, out1: *[key_size]u8, out2: *[key_size]u8) void {
    // Extract
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    HmacSha256.create(temp_key, input, chaining_key);

    // Expand - output 1
    var one: [1]u8 = .{0x01};
    HmacSha256.create(out1, &one, temp_key);

    // Expand - output 2
    var combined: [key_size + 1]u8 = undefined;
    @memcpy(combined[0..key_size], out1);
    combined[key_size] = 0x02;
    HmacSha256.create(out2, &combined, temp_key);
}

/// Handshake state
pub const HandshakeState = struct {
    symmetric: SymmetricState,
    local_static: [key_size]u8,
    local_ephemeral: X25519.KeyPair,
    remote_static: ?[key_size]u8,
    remote_ephemeral: ?[key_size]u8,
    is_initiator: bool,

    /// Initialize handshake as initiator (we know their static key)
    pub fn initInitiator(
        local_static_secret: [key_size]u8,
        remote_static_public: [key_size]u8,
    ) HandshakeState {
        var state = HandshakeState{
            .symmetric = SymmetricState.init(),
            .local_static = local_static_secret,
            .local_ephemeral = X25519.KeyPair.generate(),
            .remote_static = remote_static_public,
            .remote_ephemeral = null,
            .is_initiator = true,
        };

        // Mix in remote static public key (pre-message pattern)
        state.symmetric.mixHash(&remote_static_public);

        return state;
    }

    /// Initialize handshake as responder
    pub fn initResponder(local_static_secret: [key_size]u8) HandshakeState {
        // Compute our public key
        const local_public = X25519.recoverPublicKey(local_static_secret) catch unreachable;

        var state = HandshakeState{
            .symmetric = SymmetricState.init(),
            .local_static = local_static_secret,
            .local_ephemeral = X25519.KeyPair.generate(),
            .remote_static = null,
            .remote_ephemeral = null,
            .is_initiator = false,
        };

        // Mix in our static public key (pre-message pattern)
        state.symmetric.mixHash(&local_public);

        return state;
    }

    /// Write first handshake message (initiator -> responder)
    /// Pattern: e, es, s, ss
    /// Returns message to send
    pub fn writeMessage1(self: *HandshakeState, buffer: []u8) ![]u8 {
        if (!self.is_initiator) return error.WrongRole;

        var offset: usize = 0;

        // e: send ephemeral public key
        @memcpy(buffer[offset..][0..key_size], &self.local_ephemeral.public_key);
        self.symmetric.mixHash(&self.local_ephemeral.public_key);
        offset += key_size;

        // es: DH(ephemeral, remote static)
        const es = X25519.scalarmult(self.local_ephemeral.secret_key, self.remote_static.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&es);

        // s: encrypt and send static public key
        const local_static_public = X25519.recoverPublicKey(self.local_static) catch unreachable;
        const tag = try self.symmetric.encryptAndHash(&local_static_public, buffer[offset..][0..key_size]);
        offset += key_size;
        @memcpy(buffer[offset..][0..tag_size], &tag);
        offset += tag_size;

        // ss: DH(static, remote static)
        const ss = X25519.scalarmult(self.local_static, self.remote_static.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&ss);

        return buffer[0..offset];
    }

    /// Read first handshake message (responder reads from initiator)
    pub fn readMessage1(self: *HandshakeState, message: []const u8) !void {
        if (self.is_initiator) return error.WrongRole;
        if (message.len < key_size + key_size + tag_size) return error.MessageTooShort;

        var offset: usize = 0;

        // e: receive ephemeral public key
        self.remote_ephemeral = message[offset..][0..key_size].*;
        self.symmetric.mixHash(message[offset..][0..key_size]);
        offset += key_size;

        // es: DH(static, remote ephemeral)
        const es = X25519.scalarmult(self.local_static, self.remote_ephemeral.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&es);

        // s: decrypt remote static public key
        var remote_static: [key_size]u8 = undefined;
        const tag: [tag_size]u8 = message[offset + key_size ..][0..tag_size].*;
        try self.symmetric.decryptAndHash(message[offset..][0..key_size], tag, &remote_static);
        self.remote_static = remote_static;
        offset += key_size + tag_size;

        // ss: DH(static, remote static)
        const ss = X25519.scalarmult(self.local_static, self.remote_static.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&ss);
    }

    /// Write second handshake message (responder -> initiator)
    /// Pattern: e, ee, se
    pub fn writeMessage2(self: *HandshakeState, buffer: []u8) ![]u8 {
        if (self.is_initiator) return error.WrongRole;

        var offset: usize = 0;

        // e: send ephemeral public key
        @memcpy(buffer[offset..][0..key_size], &self.local_ephemeral.public_key);
        self.symmetric.mixHash(&self.local_ephemeral.public_key);
        offset += key_size;

        // ee: DH(ephemeral, remote ephemeral)
        const ee = X25519.scalarmult(self.local_ephemeral.secret_key, self.remote_ephemeral.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&ee);

        // se: DH(static, remote ephemeral)
        const se = X25519.scalarmult(self.local_static, self.remote_ephemeral.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&se);

        return buffer[0..offset];
    }

    /// Read second handshake message (initiator reads from responder)
    pub fn readMessage2(self: *HandshakeState, message: []const u8) !void {
        if (!self.is_initiator) return error.WrongRole;
        if (message.len < key_size) return error.MessageTooShort;

        var offset: usize = 0;

        // e: receive ephemeral public key
        self.remote_ephemeral = message[offset..][0..key_size].*;
        self.symmetric.mixHash(message[offset..][0..key_size]);
        offset += key_size;

        // ee: DH(ephemeral, remote ephemeral)
        const ee = X25519.scalarmult(self.local_ephemeral.secret_key, self.remote_ephemeral.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&ee);

        // se: DH(ephemeral, remote static)
        const se = X25519.scalarmult(self.local_ephemeral.secret_key, self.remote_static.?) catch {
            return error.DHFailed;
        };
        self.symmetric.mixKey(&se);
    }

    /// Result of finalize
    pub const FinalizeResult = struct {
        send: CipherState,
        recv: CipherState,
        remote_static: [key_size]u8,
    };

    /// Finalize handshake and get cipher states
    pub fn finalize(self: *HandshakeState) FinalizeResult {
        const ciphers = self.symmetric.split();

        if (self.is_initiator) {
            return FinalizeResult{
                .send = ciphers.send,
                .recv = ciphers.recv,
                .remote_static = self.remote_static.?,
            };
        } else {
            return FinalizeResult{
                .send = ciphers.recv,
                .recv = ciphers.send,
                .remote_static = self.remote_static.?,
            };
        }
    }

    /// Wipe sensitive data
    pub fn wipe(self: *HandshakeState) void {
        memory.secureZero(&self.local_static);
        memory.secureZero(&self.local_ephemeral.secret_key);
        self.symmetric.wipe();
    }
};

/// Message 1 size: ephemeral(32) + encrypted_static(32) + tag(16)
pub const message1_size: usize = key_size + key_size + tag_size;
/// Message 2 size: ephemeral(32)
pub const message2_size: usize = key_size;

// Tests
test "noise ik handshake" {
    // Generate static keys for both parties
    var initiator_static = X25519.KeyPair.generate();
    const responder_static = X25519.KeyPair.generate();

    // Initiator knows responder's public key
    var initiator = HandshakeState.initInitiator(initiator_static.secret_key, responder_static.public_key);
    defer initiator.wipe();

    var responder = HandshakeState.initResponder(responder_static.secret_key);
    defer responder.wipe();

    // Message 1: initiator -> responder
    var msg1_buf: [256]u8 = undefined;
    const msg1 = try initiator.writeMessage1(&msg1_buf);
    try std.testing.expectEqual(message1_size, msg1.len);

    try responder.readMessage1(msg1);

    // Responder should have learned initiator's static key
    try std.testing.expectEqualSlices(u8, &initiator_static.public_key, &responder.remote_static.?);

    // Message 2: responder -> initiator
    var msg2_buf: [256]u8 = undefined;
    const msg2 = try responder.writeMessage2(&msg2_buf);
    try std.testing.expectEqual(message2_size, msg2.len);

    try initiator.readMessage2(msg2);

    // Finalize
    var i_result = initiator.finalize();
    var r_result = responder.finalize();
    defer i_result.send.wipe();
    defer i_result.recv.wipe();
    defer r_result.send.wipe();
    defer r_result.recv.wipe();

    // Test encryption/decryption
    const plaintext = "Hello, World!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tag = try i_result.send.encrypt(plaintext, &.{}, &ciphertext);
    try r_result.recv.decrypt(&ciphertext, tag, &.{}, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}
