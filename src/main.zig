//! zend CLI - P2P Transport Engine Command Line Interface
//!
//! Commands:
//!   id init             Generate a new identity
//!   id show             Show identity public key and fingerprint
//!   peer add            Add a trusted peer
//!   peer list           List all peers
//!   peer remove         Remove a peer
//!   peer trust          Update peer trust state
//!   send <file> <peer>  Send a file to a peer
//!   receive             Listen for incoming files
//!
//! All output is JSON for IPC with hermes.

const std = @import("std");
const zend = @import("zend");

const keypair = zend.keypair;
const identity_storage = zend.identity_storage;
const peer_manager = zend.peer_manager;
const peer_storage = zend.peer_storage;
const tcp = zend.tcp;
const channel = zend.channel;
const transfer = zend.transfer;
const memory = zend.memory;
const json = zend.json;

/// Global state for progress reporting
var g_total_size: u64 = 0;
var g_last_progress_percent: u64 = 0;
var g_peer_name: []const u8 = "";

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try emitUsageError();
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "id")) {
        if (args.len < 3) {
            try json.emitError("usage", "Usage: zend id <init|show>");
            std.process.exit(1);
        }
        const subcommand = args[2];
        if (std.mem.eql(u8, subcommand, "init")) {
            try cmdIdInit(allocator);
        } else if (std.mem.eql(u8, subcommand, "show")) {
            try cmdIdShow(allocator);
        } else {
            try json.emitError("unknown_command", "Unknown id command. Use: init, show");
            std.process.exit(1);
        }
    } else if (std.mem.eql(u8, command, "peer")) {
        if (args.len < 3) {
            try json.emitError("usage", "Usage: zend peer <add|list|remove|trust>");
            std.process.exit(1);
        }
        const subcommand = args[2];
        if (std.mem.eql(u8, subcommand, "add")) {
            try cmdPeerAdd(allocator, args[3..]);
        } else if (std.mem.eql(u8, subcommand, "list")) {
            try cmdPeerList(allocator);
        } else if (std.mem.eql(u8, subcommand, "remove")) {
            try cmdPeerRemove(allocator, args[3..]);
        } else if (std.mem.eql(u8, subcommand, "trust")) {
            try cmdPeerTrust(allocator, args[3..]);
        } else {
            try json.emitError("unknown_command", "Unknown peer command. Use: add, list, remove, trust");
            std.process.exit(1);
        }
    } else if (std.mem.eql(u8, command, "send")) {
        try cmdSend(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "receive")) {
        try cmdReceive(allocator, args[2..]);
    } else {
        try json.emitError("unknown_command", "Unknown command. Use: id, peer, send, receive");
        std.process.exit(1);
    }
}

fn emitUsageError() !void {
    try json.emitError("usage", "Usage: zend <id|peer|send|receive> [options]");
}

/// Initialize a new identity
fn cmdIdInit(allocator: std.mem.Allocator) !void {
    // Check if identity already exists
    const exists = identity_storage.identityExists(allocator) catch false;
    if (exists) {
        try json.emitError("identity_exists", "Identity already exists. Delete ~/.zend/identity to create a new one.");
        std.process.exit(1);
    }

    // Generate new identity
    var identity = keypair.generateIdentity();
    defer identity.wipe();

    // Save to disk
    identity_storage.saveIdentity(allocator, &identity) catch |err| {
        try json.emitError("save_error", @errorName(err));
        std.process.exit(1);
    };

    // Encode public key to base64
    var pub_b64: [keypair.base64EncodedLen(keypair.ed25519_public_key_len)]u8 = undefined;
    const pub_encoded = keypair.encodeBase64(&identity.public_key, &pub_b64);

    // Get fingerprint
    const fp = identity.fingerprint();

    try json.emitIdentityCreated(pub_encoded, &fp);
}

/// Show current identity
fn cmdIdShow(allocator: std.mem.Allocator) !void {
    var identity = identity_storage.loadIdentity(allocator) catch |err| {
        if (err == error.FileNotFound) {
            try json.emitError("no_identity", "No identity found. Run 'zend id init' first.");
        } else {
            try json.emitError("load_error", @errorName(err));
        }
        std.process.exit(1);
    };
    defer identity.wipe();

    // Encode public key to base64
    var pub_b64: [keypair.base64EncodedLen(keypair.ed25519_public_key_len)]u8 = undefined;
    const pub_encoded = keypair.encodeBase64(&identity.public_key, &pub_b64);

    // Get fingerprint
    const fp = identity.fingerprint();

    try json.emitIdentityLoaded(pub_encoded, &fp);
}

/// Add a new peer
fn cmdPeerAdd(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 3) {
        try json.emitError("usage", "Usage: zend peer add <name> <pubkey> <address>");
        std.process.exit(1);
    }

    const name = args[0];
    const pubkey_b64 = args[1];
    const address = args[2];

    // Decode public key
    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    _ = keypair.decodeBase64(pubkey_b64, &public_key) catch |err| {
        try json.emitError("invalid_pubkey", @errorName(err));
        std.process.exit(1);
    };

    // Load existing peers
    var manager = peer_manager.PeerManager.init(allocator);
    defer manager.deinit();

    peer_storage.loadPeers(allocator, &manager) catch {};

    // Add new peer
    manager.addPeer(name, public_key, address) catch |err| {
        if (err == error.PeerAlreadyExists) {
            try json.emitError("peer_exists", "A peer with this name already exists");
        } else {
            try json.emitError("add_error", @errorName(err));
        }
        std.process.exit(1);
    };

    // Save peers
    peer_storage.savePeers(allocator, &manager) catch |err| {
        try json.emitError("save_error", @errorName(err));
        std.process.exit(1);
    };

    // Get fingerprint
    const fp = keypair.computeFingerprint(&public_key);

    try json.emitPeerAdded(name, &fp);
}

/// List all peers
fn cmdPeerList(allocator: std.mem.Allocator) !void {
    var manager = peer_manager.PeerManager.init(allocator);
    defer manager.deinit();

    peer_storage.loadPeers(allocator, &manager) catch {};

    const peers = manager.listPeers();

    // Build JSON array in buffer then write to stdout
    var buffer: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try writer.writeAll("{\"event\":\"peer_list\",\"peers\":[\n");

    for (peers, 0..) |peer, i| {
        try writer.writeAll("  {");

        // Name
        try writer.writeAll("\"name\":\"");
        try writer.writeAll(peer.name);
        try writer.writeAll("\",");

        // Public key (base64)
        var pub_b64: [keypair.base64EncodedLen(keypair.ed25519_public_key_len)]u8 = undefined;
        const pub_encoded = keypair.encodeBase64(&peer.public_key, &pub_b64);
        try writer.writeAll("\"public_key\":\"");
        try writer.writeAll(pub_encoded);
        try writer.writeAll("\",");

        // Address
        try writer.writeAll("\"address\":\"");
        try writer.writeAll(peer.address);
        try writer.writeAll("\",");

        // Fingerprint
        try writer.writeAll("\"fingerprint\":\"");
        try writer.writeAll(&peer.fingerprint);
        try writer.writeAll("\",");

        // Trust
        try writer.writeAll("\"trust\":\"");
        try writer.writeAll(@tagName(peer.trust));
        try writer.writeAll("\",");

        // Timestamps
        try writer.print("\"first_seen\":{d},", .{peer.first_seen});
        try writer.print("\"last_seen\":{d}", .{peer.last_seen});

        try writer.writeAll("}");
        if (i < peers.len - 1) {
            try writer.writeAll(",");
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("]}\n");

    const stdout = std.fs.File.stdout();
    stdout.writeAll(fbs.getWritten()) catch {};
}

/// Remove a peer
fn cmdPeerRemove(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 1) {
        try json.emitError("usage", "Usage: zend peer remove <name>");
        std.process.exit(1);
    }

    const name = args[0];

    var manager = peer_manager.PeerManager.init(allocator);
    defer manager.deinit();

    peer_storage.loadPeers(allocator, &manager) catch {};

    manager.removePeer(name) catch |err| {
        if (err == error.PeerNotFound) {
            try json.emitError("peer_not_found", "No peer found with this name");
        } else {
            try json.emitError("remove_error", @errorName(err));
        }
        std.process.exit(1);
    };

    peer_storage.savePeers(allocator, &manager) catch |err| {
        try json.emitError("save_error", @errorName(err));
        std.process.exit(1);
    };

    try json.emitPeerRemoved(name);
}

/// Update peer trust state
fn cmdPeerTrust(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        try json.emitError("usage", "Usage: zend peer trust <name> <trusted|blocked>");
        std.process.exit(1);
    }

    const name = args[0];
    const trust_value = args[1];

    const trust = if (std.mem.eql(u8, trust_value, "trusted"))
        peer_manager.TrustLevel.trusted
    else if (std.mem.eql(u8, trust_value, "blocked") or std.mem.eql(u8, trust_value, "untrusted"))
        peer_manager.TrustLevel.blocked
    else {
        try json.emitError("invalid_trust", "Trust must be trusted or blocked");
        std.process.exit(1);
    };

    var manager = peer_manager.PeerManager.init(allocator);
    defer manager.deinit();

    peer_storage.loadPeers(allocator, &manager) catch {};

    manager.updateTrust(name, trust) catch |err| {
        if (err == error.PeerNotFound) {
            try json.emitError("peer_not_found", "No peer found with this name");
        } else {
            try json.emitError("trust_error", @errorName(err));
        }
        std.process.exit(1);
    };

    peer_storage.savePeers(allocator, &manager) catch |err| {
        try json.emitError("save_error", @errorName(err));
        std.process.exit(1);
    };

    try json.emitPeerTrustUpdated(name, @tagName(trust));
}

/// Send a file to a peer
fn cmdSend(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        try json.emitError("usage", "Usage: zend send <file> <peer-name>");
        std.process.exit(1);
    }

    const file_path = args[0];
    const peer_name = args[1];

    // Load identity
    var identity = identity_storage.loadIdentity(allocator) catch |err| {
        if (err == error.FileNotFound) {
            try json.emitError("no_identity", "No identity found. Run 'zend id init' first.");
        } else {
            try json.emitError("load_error", @errorName(err));
        }
        std.process.exit(1);
    };
    defer identity.wipe();

    // Load peers
    var manager = peer_manager.PeerManager.init(allocator);
    defer manager.deinit();

    peer_storage.loadPeers(allocator, &manager) catch {};

    // Find peer
    const peer = manager.findByName(peer_name) orelse {
        try json.emitError("peer_not_found", "No peer found with this name");
        std.process.exit(1);
    };
    if (peer.trust == .blocked) {
        try json.emitError("peer_blocked", "Peer is marked untrusted");
        std.process.exit(1);
    }

    // Get file size
    const file = std.fs.cwd().openFile(file_path, .{}) catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };
    const file_size = file.getEndPos() catch |err| {
        try json.emitError("file_error", @errorName(err));
        std.process.exit(1);
    };
    file.close();

    g_total_size = file_size;
    g_last_progress_percent = 0;
    g_peer_name = peer_name;

    try json.emitConnecting(peer_name, peer.address);

    // Connect to peer
    var secure_channel = zend.connectToPeer(peer.address, &identity, peer.public_key) catch |err| {
        try json.emitError("connect_error", @errorName(err));
        std.process.exit(1);
    };
    defer secure_channel.close();

    try json.emitHandshakeComplete(peer_name);

    // Emit transfer start
    const filename = std.fs.path.basename(file_path);
    try json.emitTransferStart(filename, file_size, peer_name);

    // Send file
    transfer.sendFile(&secure_channel, file_path, progressCallback) catch |err| {
        try json.emitError("transfer_error", @errorName(err));
        std.process.exit(1);
    };

    // Compute hash for output
    const hash = transfer.computeFileHash(file_path) catch |err| {
        try json.emitError("hash_error", @errorName(err));
        std.process.exit(1);
    };
    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    try json.emitTransferComplete(filename, &hash_hex);
}

/// Receive files from peers
fn cmdReceive(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var port: u16 = tcp.default_port;

    // Parse options
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port")) {
            if (i + 1 >= args.len) {
                try json.emitError("usage", "--port requires a port number");
                std.process.exit(1);
            }
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch {
                try json.emitError("invalid_port", "Invalid port number");
                std.process.exit(1);
            };
        }
    }

    // Load identity
    var identity = identity_storage.loadIdentity(allocator) catch |err| {
        if (err == error.FileNotFound) {
            try json.emitError("no_identity", "No identity found. Run 'zend id init' first.");
        } else {
            try json.emitError("load_error", @errorName(err));
        }
        std.process.exit(1);
    };
    defer identity.wipe();

    // Start listening
    var server = tcp.TcpServer.listen(port) catch |err| {
        try json.emitError("listen_error", @errorName(err));
        std.process.exit(1);
    };
    defer server.close();

    try json.emitListening(server.getPort());

    // Accept one connection
    var secure_channel = zend.acceptConnection(&server, &identity) catch |err| {
        try json.emitError("accept_error", @errorName(err));
        std.process.exit(1);
    };
    defer secure_channel.close();

    // Get remote fingerprint
    const remote_fp = secure_channel.getRemoteFingerprint();
    try json.emitHandshakeComplete(&remote_fp);

    // Receive file to current directory
    const output_dir = ".";

    g_total_size = 0;
    g_last_progress_percent = 0;

    const filename = transfer.receiveFile(&secure_channel, output_dir, allocator, progressCallback) catch |err| {
        try json.emitError("receive_error", @errorName(err));
        std.process.exit(1);
    };
    defer allocator.free(filename);

    // Compute hash of received file
    const hash = transfer.computeFileHash(filename) catch |err| {
        try json.emitError("hash_error", @errorName(err));
        std.process.exit(1);
    };
    const hash_hex = std.fmt.bytesToHex(hash, .lower);

    try json.emitTransferComplete(filename, &hash_hex);
}

/// Progress callback for file transfers
fn progressCallback(bytes_transferred: u64, total_bytes: u64) void {
    if (g_total_size == 0) {
        g_total_size = total_bytes;
    }

    const percent: u64 = if (g_total_size > 0)
        (bytes_transferred * 100) / g_total_size
    else
        100;

    // Only emit progress every 5%
    if (percent >= g_last_progress_percent + 5 or percent == 100) {
        g_last_progress_percent = percent;
        const percent_f: f64 = @as(f64, @floatFromInt(bytes_transferred)) / @as(f64, @floatFromInt(g_total_size)) * 100.0;
        json.emitProgress(bytes_transferred, percent_f) catch {};
    }
}

// Tests
test "main module imports" {
    _ = zend;
}
