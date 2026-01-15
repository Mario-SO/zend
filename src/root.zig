//! zend - P2P Transport Engine
//!
//! Secure peer-to-peer file transfer using Noise IK protocol.
//! Provides identity management, peer authentication (TOFU),
//! encrypted transport, and file transfer with integrity verification.
//!
//! This module exports the public API for use as a library.

const std = @import("std");

// Re-export identity management
pub const keypair = @import("identity/keypair.zig");
pub const identity_storage = @import("identity/storage.zig");

// Re-export peer management
pub const peer_manager = @import("peer/manager.zig");
pub const peer_storage = @import("peer/storage.zig");

// Re-export transport layer
pub const tcp = @import("transport/tcp.zig");
pub const frame = @import("transport/frame.zig");
pub const noise = @import("transport/noise.zig");
pub const channel = @import("transport/channel.zig");

// Re-export protocol
pub const messages = @import("protocol/messages.zig");
pub const transfer = @import("protocol/transfer.zig");

// Re-export utilities
pub const memory = @import("utils/memory.zig");
pub const json = @import("utils/json.zig");

/// Default port for zend connections
pub const default_port = tcp.default_port;

/// Identity type alias
pub const Identity = keypair.Identity;

/// Peer type alias
pub const Peer = peer_manager.Peer;

/// PeerManager type alias
pub const PeerManager = peer_manager.PeerManager;

/// SecureChannel type alias
pub const SecureChannel = channel.SecureChannel;

/// Generate a new identity
pub fn generateIdentity() Identity {
    return keypair.generateIdentity();
}

/// Load identity from disk
pub fn loadIdentity(allocator: std.mem.Allocator) !Identity {
    return identity_storage.loadIdentity(allocator);
}

/// Save identity to disk
pub fn saveIdentity(allocator: std.mem.Allocator, identity: *const Identity) !void {
    return identity_storage.saveIdentity(allocator, identity);
}

/// Check if identity exists
pub fn identityExists(allocator: std.mem.Allocator) !bool {
    return identity_storage.identityExists(allocator);
}

/// Load peers from disk
pub fn loadPeers(allocator: std.mem.Allocator, manager: *PeerManager) !void {
    return peer_storage.loadPeers(allocator, manager);
}

/// Save peers to disk
pub fn savePeers(allocator: std.mem.Allocator, manager: *const PeerManager) !void {
    return peer_storage.savePeers(allocator, manager);
}

/// Connect to a peer securely
pub fn connectToPeer(
    address: []const u8,
    local_identity: *Identity,
    remote_pubkey: [keypair.ed25519_public_key_len]u8,
) !SecureChannel {
    var local_x25519 = local_identity.x25519SecretKey();
    defer memory.secureZero(&local_x25519);

    const remote_x25519 = try keypair.ed25519PublicKeyToX25519(remote_pubkey);

    return channel.connectSecure(address, local_x25519, remote_x25519);
}

/// Listen for incoming connections
pub fn listen(port: u16) !tcp.TcpServer {
    return tcp.TcpServer.listen(port);
}

/// Accept a secure connection
pub fn acceptConnection(server: *tcp.TcpServer, local_identity: *Identity) !SecureChannel {
    var local_x25519 = local_identity.x25519SecretKey();
    defer memory.secureZero(&local_x25519);

    return channel.acceptSecure(server, local_x25519);
}

/// Send a file to a peer
pub fn sendFile(
    secure_channel: *SecureChannel,
    file_path: []const u8,
    progress_callback: ?transfer.ProgressCallback,
) !void {
    return transfer.sendFile(secure_channel, file_path, progress_callback);
}

/// Receive a file from a peer
pub fn receiveFile(
    secure_channel: *SecureChannel,
    output_dir: []const u8,
    allocator: std.mem.Allocator,
    progress_callback: ?transfer.ProgressCallback,
) ![]u8 {
    return transfer.receiveFile(secure_channel, output_dir, allocator, progress_callback);
}

// Tests
test "library exports" {
    // Verify all modules are accessible
    _ = keypair.generateIdentity;
    _ = identity_storage.saveIdentity;
    _ = peer_manager.PeerManager;
    _ = peer_storage.savePeers;
    _ = tcp.TcpServer;
    _ = frame.FramedConnection;
    _ = noise.HandshakeState;
    _ = channel.SecureChannel;
    _ = messages.FileOffer;
    _ = transfer.sendFile;
    _ = memory.secureZero;
    _ = json.emitError;
}

test "generate and save identity" {
    var id = generateIdentity();
    defer id.wipe();

    // Check fingerprint is valid
    const fp = id.fingerprint();
    try std.testing.expectEqual(@as(usize, 64), fp.len);
}
