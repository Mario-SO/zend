//! Secure channel abstraction.
//!
//! Provides an encrypted bidirectional channel after Noise handshake.
//! Combines TCP, framing, and Noise encryption.

const std = @import("std");
const tcp = @import("tcp.zig");
const frame = @import("frame.zig");
const noise = @import("noise.zig");
const keypair = @import("../identity/keypair.zig");
const memory = @import("../utils/memory.zig");

/// Maximum payload size (frame max - tag)
pub const max_payload_size: usize = frame.max_frame_size - noise.tag_size;

/// Secure channel for encrypted communication
pub const SecureChannel = struct {
    conn: tcp.TcpConnection,
    framed: frame.FramedConnection,
    send_cipher: noise.CipherState,
    recv_cipher: noise.CipherState,
    remote_static: [noise.key_size]u8,
    send_buffer: [frame.max_frame_size]u8 = undefined,

    /// Close the channel and wipe keys
    pub fn close(self: *SecureChannel) void {
        self.send_cipher.wipe();
        self.recv_cipher.wipe();
        memory.secureZero(&self.remote_static);
        self.conn.close();
    }

    /// Send encrypted data
    pub fn send(self: *SecureChannel, data: []const u8) !void {
        if (data.len > max_payload_size) {
            return error.PayloadTooLarge;
        }

        // Encrypt data
        const tag = try self.send_cipher.encrypt(data, &.{}, self.send_buffer[0..data.len]);

        // Append tag
        @memcpy(self.send_buffer[data.len..][0..noise.tag_size], &tag);

        // Send framed message
        try self.framed.send(self.send_buffer[0 .. data.len + noise.tag_size]);
    }

    /// Receive and decrypt data
    /// Returns decrypted data (slice into internal buffer)
    pub fn receive(self: *SecureChannel) ![]u8 {
        // Receive framed message
        const encrypted = try self.framed.receive();

        if (encrypted.len < noise.tag_size) {
            return error.MessageTooShort;
        }

        const ciphertext_len = encrypted.len - noise.tag_size;
        const ciphertext = encrypted[0..ciphertext_len];
        const tag: [noise.tag_size]u8 = encrypted[ciphertext_len..][0..noise.tag_size].*;

        // Decrypt in place
        try self.recv_cipher.decrypt(ciphertext, tag, &.{}, self.framed.read_buffer[0..ciphertext_len]);

        return self.framed.read_buffer[0..ciphertext_len];
    }

    /// Get remote peer's static public key
    pub fn getRemoteStatic(self: *const SecureChannel) [noise.key_size]u8 {
        return self.remote_static;
    }

    /// Get remote peer's fingerprint
    pub fn getRemoteFingerprint(self: *const SecureChannel) [keypair.fingerprint_len]u8 {
        // Note: remote_static is X25519, but we compute fingerprint the same way
        return keypair.computeFingerprint(&self.remote_static);
    }
};

/// Perform handshake as initiator and return secure channel
pub fn connectSecure(
    address: []const u8,
    local_x25519_secret: [noise.key_size]u8,
    remote_x25519_public: [noise.key_size]u8,
) !SecureChannel {
    // Connect
    var conn = try tcp.TcpClient.connect(address);
    errdefer conn.close();

    var framed = frame.FramedConnection.init(&conn);

    // Initialize handshake
    var handshake = noise.HandshakeState.initInitiator(local_x25519_secret, remote_x25519_public);
    defer handshake.wipe();

    // Send message 1
    var msg1_buf: [noise.message1_size]u8 = undefined;
    const msg1 = try handshake.writeMessage1(&msg1_buf);
    try framed.send(msg1);

    // Receive message 2
    const msg2 = try framed.receive();
    try handshake.readMessage2(msg2);

    // Finalize
    const result = handshake.finalize();

    return SecureChannel{
        .conn = conn,
        .framed = framed,
        .send_cipher = result.send,
        .recv_cipher = result.recv,
        .remote_static = result.remote_static,
    };
}

/// Accept connection and perform handshake as responder
pub fn acceptSecure(
    server: *tcp.TcpServer,
    local_x25519_secret: [noise.key_size]u8,
) !SecureChannel {
    // Accept connection
    var conn = try server.accept();
    errdefer conn.close();

    var framed = frame.FramedConnection.init(&conn);

    // Initialize handshake
    var handshake = noise.HandshakeState.initResponder(local_x25519_secret);
    defer handshake.wipe();

    // Receive message 1
    const msg1 = try framed.receive();
    try handshake.readMessage1(msg1);

    // Send message 2
    var msg2_buf: [noise.message2_size]u8 = undefined;
    const msg2 = try handshake.writeMessage2(&msg2_buf);
    try framed.send(msg2);

    // Finalize
    const result = handshake.finalize();

    return SecureChannel{
        .conn = conn,
        .framed = framed,
        .send_cipher = result.send,
        .recv_cipher = result.recv,
        .remote_static = result.remote_static,
    };
}

// Tests require actual network connections, so we test the cipher state directly
test "secure channel cipher integration" {
    // This tests the cipher state that would be used by SecureChannel
    var key1: [noise.key_size]u8 = undefined;
    var key2: [noise.key_size]u8 = undefined;
    std.crypto.random.bytes(&key1);
    @memcpy(&key2, &key1);

    var sender = noise.CipherState.init(key1);
    var receiver = noise.CipherState.init(key2);
    defer sender.wipe();
    defer receiver.wipe();

    const plaintext = "Hello, secure world!";
    var ciphertext: [plaintext.len]u8 = undefined;
    var decrypted: [plaintext.len]u8 = undefined;

    const tag = try sender.encrypt(plaintext, &.{}, &ciphertext);
    try receiver.decrypt(&ciphertext, tag, &.{}, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
}
