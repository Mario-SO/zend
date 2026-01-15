//! Peer management - CRUD operations for trusted peers.
//!
//! Peers are identified by their Ed25519 public key fingerprint.
//! TOFU (Trust On First Use) model: first connection records fingerprint,
//! subsequent connections verify it hasn't changed.

const std = @import("std");
const keypair = @import("../identity/keypair.zig");

/// A trusted peer
pub const Peer = struct {
    /// User-friendly name
    name: []const u8,
    /// Ed25519 public key (32 bytes)
    public_key: [keypair.ed25519_public_key_len]u8,
    /// Network address (host:port)
    address: []const u8,
    /// SHA-256 fingerprint (hex-encoded, 64 chars)
    fingerprint: [keypair.fingerprint_len]u8,
    /// Unix timestamp of first contact
    first_seen: i64,
    /// Unix timestamp of last contact
    last_seen: i64,

    /// Free allocated memory for this peer
    pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.address);
    }

    /// Clone a peer (deep copy)
    pub fn clone(self: *const Peer, allocator: std.mem.Allocator) !Peer {
        return Peer{
            .name = try allocator.dupe(u8, self.name),
            .public_key = self.public_key,
            .address = try allocator.dupe(u8, self.address),
            .fingerprint = self.fingerprint,
            .first_seen = self.first_seen,
            .last_seen = self.last_seen,
        };
    }
};

/// Peer manager - manages a list of trusted peers
pub const PeerManager = struct {
    peers: std.ArrayListUnmanaged(Peer),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) PeerManager {
        return PeerManager{
            .peers = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *PeerManager) void {
        for (self.peers.items) |*peer| {
            peer.deinit(self.allocator);
        }
        self.peers.deinit(self.allocator);
    }

    /// Add a new peer
    pub fn addPeer(
        self: *PeerManager,
        name: []const u8,
        public_key: [keypair.ed25519_public_key_len]u8,
        address: []const u8,
    ) !void {
        // Check if peer with this name already exists
        if (self.findByName(name) != null) {
            return error.PeerAlreadyExists;
        }

        // Compute fingerprint from public key
        const fingerprint = keypair.computeFingerprint(&public_key);

        const now = std.time.timestamp();

        const peer = Peer{
            .name = try self.allocator.dupe(u8, name),
            .public_key = public_key,
            .address = try self.allocator.dupe(u8, address),
            .fingerprint = fingerprint,
            .first_seen = now,
            .last_seen = now,
        };

        try self.peers.append(self.allocator, peer);
    }

    /// Find peer by name
    pub fn findByName(self: *const PeerManager, name: []const u8) ?*const Peer {
        for (self.peers.items) |*peer| {
            if (std.mem.eql(u8, peer.name, name)) {
                return peer;
            }
        }
        return null;
    }

    /// Find peer by fingerprint
    pub fn findByFingerprint(self: *const PeerManager, fingerprint: []const u8) ?*const Peer {
        for (self.peers.items) |*peer| {
            if (std.mem.eql(u8, &peer.fingerprint, fingerprint)) {
                return peer;
            }
        }
        return null;
    }

    /// Remove peer by name
    pub fn removePeer(self: *PeerManager, name: []const u8) !void {
        for (self.peers.items, 0..) |*peer, i| {
            if (std.mem.eql(u8, peer.name, name)) {
                peer.deinit(self.allocator);
                _ = self.peers.orderedRemove(i);
                return;
            }
        }
        return error.PeerNotFound;
    }

    /// Update last_seen timestamp for a peer
    pub fn updateLastSeen(self: *PeerManager, name: []const u8) !void {
        for (self.peers.items) |*peer| {
            if (std.mem.eql(u8, peer.name, name)) {
                peer.last_seen = std.time.timestamp();
                return;
            }
        }
        return error.PeerNotFound;
    }

    /// Get list of all peers
    pub fn listPeers(self: *const PeerManager) []const Peer {
        return self.peers.items;
    }

    /// Verify peer fingerprint (TOFU check)
    /// Returns true if fingerprint matches, false if it changed
    pub fn verifyFingerprint(
        self: *const PeerManager,
        name: []const u8,
        fingerprint: [keypair.fingerprint_len]u8,
    ) !bool {
        const peer = self.findByName(name) orelse return error.PeerNotFound;
        return std.mem.eql(u8, &peer.fingerprint, &fingerprint);
    }
};

// Tests
test "peer manager add and find" {
    const allocator = std.testing.allocator;
    var manager = PeerManager.init(allocator);
    defer manager.deinit();

    // Generate a test public key
    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    std.crypto.random.bytes(&public_key);

    try manager.addPeer("alice", public_key, "192.168.1.100:7654");

    const found = manager.findByName("alice");
    try std.testing.expect(found != null);
    try std.testing.expectEqualSlices(u8, "alice", found.?.name);
    try std.testing.expectEqualSlices(u8, "192.168.1.100:7654", found.?.address);
}

test "peer manager duplicate name rejected" {
    const allocator = std.testing.allocator;
    var manager = PeerManager.init(allocator);
    defer manager.deinit();

    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    std.crypto.random.bytes(&public_key);

    try manager.addPeer("alice", public_key, "192.168.1.100:7654");

    // Second add with same name should fail
    const result = manager.addPeer("alice", public_key, "192.168.1.101:7654");
    try std.testing.expectError(error.PeerAlreadyExists, result);
}

test "peer manager remove" {
    const allocator = std.testing.allocator;
    var manager = PeerManager.init(allocator);
    defer manager.deinit();

    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    std.crypto.random.bytes(&public_key);

    try manager.addPeer("alice", public_key, "192.168.1.100:7654");
    try manager.removePeer("alice");

    try std.testing.expect(manager.findByName("alice") == null);
}

test "peer fingerprint verification" {
    const allocator = std.testing.allocator;
    var manager = PeerManager.init(allocator);
    defer manager.deinit();

    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    std.crypto.random.bytes(&public_key);

    try manager.addPeer("alice", public_key, "192.168.1.100:7654");

    const fingerprint = keypair.computeFingerprint(&public_key);
    try std.testing.expect(try manager.verifyFingerprint("alice", fingerprint));

    // Different fingerprint should not match
    var wrong_fingerprint: [keypair.fingerprint_len]u8 = undefined;
    @memset(&wrong_fingerprint, 'x');
    try std.testing.expect(!try manager.verifyFingerprint("alice", wrong_fingerprint));
}
