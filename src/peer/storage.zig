//! Peer storage - JSON persistence for trusted peers.
//!
//! Peers are stored at ~/.zend/peers.json

const std = @import("std");
const manager = @import("manager.zig");
const keypair = @import("../identity/keypair.zig");
const identity_storage = @import("../identity/storage.zig");

/// Peers file name
pub const peers_file_name = "peers.json";

/// Get the peers file path
pub fn getPeersPath(allocator: std.mem.Allocator) ![]u8 {
    const config_dir = try identity_storage.getConfigDir(allocator);
    defer allocator.free(config_dir);

    return std.fs.path.join(allocator, &.{ config_dir, peers_file_name });
}

/// Save peers to disk as JSON
pub fn savePeers(allocator: std.mem.Allocator, peer_manager: *const manager.PeerManager) !void {
    // Ensure config directory exists
    const config_dir = try identity_storage.getConfigDir(allocator);
    defer allocator.free(config_dir);

    std.fs.cwd().makePath(config_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };

    const path = try getPeersPath(allocator);
    defer allocator.free(path);

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    // Build JSON in memory first for efficiency
    var buffer: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("[\n");

    const peers = peer_manager.listPeers();
    for (peers, 0..) |peer, i| {
        try writer.writeAll("  {\n");

        // Name
        try writer.writeAll("    \"name\": \"");
        try writeJsonString(writer, peer.name);
        try writer.writeAll("\",\n");

        // Public key (base64)
        var pubkey_b64: [keypair.base64EncodedLen(keypair.ed25519_public_key_len)]u8 = undefined;
        const pubkey_encoded = keypair.encodeBase64(&peer.public_key, &pubkey_b64);
        try writer.writeAll("    \"public_key\": \"");
        try writer.writeAll(pubkey_encoded);
        try writer.writeAll("\",\n");

        // Address
        try writer.writeAll("    \"address\": \"");
        try writeJsonString(writer, peer.address);
        try writer.writeAll("\",\n");

        // Fingerprint
        try writer.writeAll("    \"fingerprint\": \"");
        try writer.writeAll(&peer.fingerprint);
        try writer.writeAll("\",\n");

        // Trust
        try writer.writeAll("    \"trust\": \"");
        try writer.writeAll(@tagName(peer.trust));
        try writer.writeAll("\",\n");

        // Timestamps
        try writer.print("    \"first_seen\": {d},\n", .{peer.first_seen});
        try writer.print("    \"last_seen\": {d}\n", .{peer.last_seen});

        try writer.writeAll("  }");
        if (i < peers.len - 1) {
            try writer.writeAll(",");
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("]\n");
    try file.writeAll(fbs.getWritten());
}

/// Load peers from disk
pub fn loadPeers(allocator: std.mem.Allocator, peer_manager: *manager.PeerManager) !void {
    const path = try getPeersPath(allocator);
    defer allocator.free(path);

    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            // No peers file yet, that's fine
            return;
        }
        return err;
    };
    defer file.close();

    // Read entire file
    const content = try file.readToEndAlloc(allocator, 1024 * 1024); // 1MB max
    defer allocator.free(content);

    // Parse JSON
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, content, .{}) catch {
        return error.InvalidPeersFile;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .array) {
        return error.InvalidPeersFile;
    }

    for (root.array.items) |item| {
        if (item != .object) continue;
        const obj = item.object;

        // Extract fields
        const name_val = obj.get("name") orelse continue;
        const pubkey_val = obj.get("public_key") orelse continue;
        const address_val = obj.get("address") orelse continue;
        const first_seen_val = obj.get("first_seen") orelse continue;
        const last_seen_val = obj.get("last_seen") orelse continue;
        const trust_val = obj.get("trust");

        if (name_val != .string or pubkey_val != .string or address_val != .string) continue;
        if (first_seen_val != .integer or last_seen_val != .integer) continue;

        // Decode public key from base64
        var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
        _ = keypair.decodeBase64(pubkey_val.string, &public_key) catch continue;

        // Compute fingerprint
        const fingerprint = keypair.computeFingerprint(&public_key);

        const trust = parseTrust(trust_val);

        const peer = manager.Peer{
            .name = try allocator.dupe(u8, name_val.string),
            .public_key = public_key,
            .address = try allocator.dupe(u8, address_val.string),
            .fingerprint = fingerprint,
            .trust = trust,
            .first_seen = first_seen_val.integer,
            .last_seen = last_seen_val.integer,
        };

        try peer_manager.peers.append(peer_manager.allocator, peer);
    }
}

fn parseTrust(value: ?std.json.Value) manager.TrustLevel {
    if (value) |val| {
        if (val == .string) {
            if (std.mem.eql(u8, val.string, "blocked") or std.mem.eql(u8, val.string, "untrusted")) {
                return .blocked;
            }
            if (std.mem.eql(u8, val.string, "trusted")) {
                return .trusted;
            }
        }
    }
    return .trusted;
}

/// Write a JSON-escaped string
fn writeJsonString(writer: anytype, str: []const u8) !void {
    for (str) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

// Tests
test "peers path" {
    const allocator = std.testing.allocator;
    const path = try getPeersPath(allocator);
    defer allocator.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, "peers.json"));
}
