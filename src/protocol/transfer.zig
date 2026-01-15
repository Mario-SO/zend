//! File transfer state machine.
//!
//! Handles the complete file transfer workflow:
//! 1. Sender offers file with metadata and hash
//! 2. Receiver accepts or rejects
//! 3. Sender streams chunks, receiver acknowledges
//! 4. Sender sends completion, receiver verifies hash

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const channel = @import("../transport/channel.zig");
const messages = @import("messages.zig");
const json = @import("../utils/json.zig");

/// Default chunk size (64KB)
pub const default_chunk_size: u32 = 64 * 1024;

/// Transfer state
pub const TransferState = enum {
    idle,
    offering,
    waiting_accept,
    transferring,
    waiting_complete,
    verifying,
    complete,
    failed,
};

/// Progress callback type
pub const ProgressCallback = *const fn (bytes_transferred: u64, total_bytes: u64) void;

/// Send a file to a peer
pub fn sendFile(
    secure_channel: *channel.SecureChannel,
    file_path: []const u8,
    progress_callback: ?ProgressCallback,
) !void {
    // Open the file
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const file_size = try file.getEndPos();

    // Compute file hash
    var hasher = Sha256.init(.{});
    var hash_buf: [8192]u8 = undefined;
    while (true) {
        const bytes_read = try file.read(&hash_buf);
        if (bytes_read == 0) break;
        hasher.update(hash_buf[0..bytes_read]);
    }
    const file_hash = hasher.finalResult();

    // Reset file position
    try file.seekTo(0);

    // Extract filename from path
    const filename = std.fs.path.basename(file_path);

    // Calculate chunks
    const total_chunks: u32 = @intCast((file_size + default_chunk_size - 1) / default_chunk_size);

    // Send file offer
    const offer = messages.FileOffer{
        .filename = filename,
        .size = file_size,
        .hash = file_hash,
        .chunk_size = default_chunk_size,
        .total_chunks = if (total_chunks == 0) 1 else total_chunks,
    };

    var offer_buf: [1024]u8 = undefined;
    const offer_msg = try offer.serialize(&offer_buf);
    try secure_channel.send(offer_msg);

    // Wait for accept/reject
    const response = try secure_channel.receive();
    const msg_type = try messages.parseMessageType(response);

    switch (msg_type) {
        .file_accept => {
            // Proceed with transfer
        },
        .file_reject => {
            return error.TransferRejected;
        },
        else => {
            return error.UnexpectedMessage;
        },
    }

    // Send chunks
    var chunk_buf: [default_chunk_size + 64]u8 = undefined;
    var send_buf: [default_chunk_size + 128]u8 = undefined;
    var bytes_sent: u64 = 0;
    var chunk_index: u32 = 0;

    while (bytes_sent < file_size) {
        const to_read = @min(default_chunk_size, file_size - bytes_sent);
        const bytes_read = try file.readAll(chunk_buf[0..to_read]);

        if (bytes_read == 0) break;

        const chunk = messages.Chunk{
            .index = chunk_index,
            .data = chunk_buf[0..bytes_read],
        };

        const chunk_msg = try chunk.serialize(&send_buf);
        try secure_channel.send(chunk_msg);

        // Wait for ack
        const ack_response = try secure_channel.receive();
        const ack_type = try messages.parseMessageType(ack_response);

        if (ack_type != .chunk_ack) {
            return error.UnexpectedMessage;
        }

        const ack = try messages.ChunkAck.deserialize(ack_response);
        if (ack.index != chunk_index) {
            return error.ChunkAckMismatch;
        }

        bytes_sent += bytes_read;
        chunk_index += 1;

        if (progress_callback) |callback| {
            callback(bytes_sent, file_size);
        }
    }

    // Send transfer complete
    const complete = messages.TransferComplete{ .hash = file_hash };
    var complete_buf: [64]u8 = undefined;
    const complete_msg = try complete.serialize(&complete_buf);
    try secure_channel.send(complete_msg);
}

/// Receive a file from a peer
pub fn receiveFile(
    secure_channel: *channel.SecureChannel,
    output_dir: []const u8,
    allocator: std.mem.Allocator,
    progress_callback: ?ProgressCallback,
) ![]u8 {
    // Wait for file offer
    const offer_data = try secure_channel.receive();
    const msg_type = try messages.parseMessageType(offer_data);

    if (msg_type != .file_offer) {
        return error.UnexpectedMessage;
    }

    var offer = try messages.FileOffer.deserialize(offer_data, allocator);
    defer offer.deinit(allocator);

    // Create output file path
    const output_path = try std.fs.path.join(allocator, &.{ output_dir, offer.filename });
    defer allocator.free(output_path);

    // Open output file
    const output_file = try std.fs.cwd().createFile(output_path, .{});
    defer output_file.close();

    // Send accept
    var accept_buf: [8]u8 = undefined;
    const accept_msg = try messages.FileAccept.serialize(&accept_buf);
    try secure_channel.send(accept_msg);

    // Receive chunks
    var hasher = Sha256.init(.{});
    var bytes_received: u64 = 0;
    var expected_chunk: u32 = 0;

    while (bytes_received < offer.size) {
        const chunk_data = try secure_channel.receive();
        const chunk_type = try messages.parseMessageType(chunk_data);

        if (chunk_type == .transfer_complete) {
            break;
        }

        if (chunk_type != .chunk) {
            return error.UnexpectedMessage;
        }

        const chunk = try messages.Chunk.deserialize(chunk_data);

        if (chunk.index != expected_chunk) {
            return error.ChunkOrderMismatch;
        }

        // Write to file
        try output_file.writeAll(chunk.data);

        // Update hash
        hasher.update(chunk.data);

        bytes_received += chunk.data.len;
        expected_chunk += 1;

        // Send ack
        const ack = messages.ChunkAck{ .index = chunk.index };
        var ack_buf: [16]u8 = undefined;
        const ack_msg = try ack.serialize(&ack_buf);
        try secure_channel.send(ack_msg);

        if (progress_callback) |callback| {
            callback(bytes_received, offer.size);
        }
    }

    // Wait for transfer complete message if we haven't received it
    if (bytes_received >= offer.size) {
        const complete_data = try secure_channel.receive();
        const complete_type = try messages.parseMessageType(complete_data);

        if (complete_type != .transfer_complete) {
            return error.UnexpectedMessage;
        }
    }

    // Verify hash
    const computed_hash = hasher.finalResult();
    if (!std.mem.eql(u8, &computed_hash, &offer.hash)) {
        return error.HashMismatch;
    }

    // Return the output filename
    return try allocator.dupe(u8, offer.filename);
}

/// Compute SHA-256 hash of a file
pub fn computeFileHash(file_path: []const u8) ![Sha256.digest_length]u8 {
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var hasher = Sha256.init(.{});
    var buf: [8192]u8 = undefined;

    while (true) {
        const bytes_read = try file.read(&buf);
        if (bytes_read == 0) break;
        hasher.update(buf[0..bytes_read]);
    }

    return hasher.finalResult();
}

// Tests
test "compute file hash" {
    // Create a temporary test file
    const allocator = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    const test_content = "Hello, World! This is a test file for hashing.";
    const file = try tmp_dir.dir.createFile("test.txt", .{});
    try file.writeAll(test_content);
    file.close();

    // Get the path
    const path = try tmp_dir.dir.realpathAlloc(allocator, "test.txt");
    defer allocator.free(path);

    // Compute hash
    const hash = try computeFileHash(path);

    // Verify it's not all zeros
    var all_zero = true;
    for (hash) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "default chunk size" {
    try std.testing.expectEqual(@as(u32, 64 * 1024), default_chunk_size);
}
