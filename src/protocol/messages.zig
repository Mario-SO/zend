//! Protocol message types and serialization.
//!
//! All messages are serialized as: [1-byte type][payload]
//! Strings are length-prefixed: [2-byte length][data]

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Message types
pub const MessageType = enum(u8) {
    file_offer = 0x01,
    file_accept = 0x02,
    file_reject = 0x03,
    chunk = 0x04,
    chunk_ack = 0x05,
    transfer_complete = 0x06,
    @"error" = 0xFF,
};

/// File offer message - sender offers a file to receiver
pub const FileOffer = struct {
    filename: []const u8,
    size: u64,
    hash: [Sha256.digest_length]u8,
    chunk_size: u32,
    total_chunks: u32,

    /// Serialize to buffer
    pub fn serialize(self: *const FileOffer, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        // Message type
        try writer.writeByte(@intFromEnum(MessageType.file_offer));

        // Filename (length-prefixed)
        if (self.filename.len > std.math.maxInt(u16)) return error.FilenameTooLong;
        try writer.writeInt(u16, @intCast(self.filename.len), .big);
        try writer.writeAll(self.filename);

        // Size
        try writer.writeInt(u64, self.size, .big);

        // Hash
        try writer.writeAll(&self.hash);

        // Chunk info
        try writer.writeInt(u32, self.chunk_size, .big);
        try writer.writeInt(u32, self.total_chunks, .big);

        return fbs.getWritten();
    }

    /// Deserialize from buffer
    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !FileOffer {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        // Skip message type (already verified)
        _ = try reader.readByte();

        // Filename
        const filename_len = try reader.readInt(u16, .big);
        const filename = try allocator.alloc(u8, filename_len);
        errdefer allocator.free(filename);
        _ = try reader.readAll(filename);

        // Size
        const size = try reader.readInt(u64, .big);

        // Hash
        var hash: [Sha256.digest_length]u8 = undefined;
        _ = try reader.readAll(&hash);

        // Chunk info
        const chunk_size = try reader.readInt(u32, .big);
        const total_chunks = try reader.readInt(u32, .big);

        return FileOffer{
            .filename = filename,
            .size = size,
            .hash = hash,
            .chunk_size = chunk_size,
            .total_chunks = total_chunks,
        };
    }

    pub fn deinit(self: *FileOffer, allocator: std.mem.Allocator) void {
        allocator.free(self.filename);
    }
};

/// File accept message
pub const FileAccept = struct {
    /// Serialize to buffer
    pub fn serialize(buffer: []u8) ![]u8 {
        if (buffer.len < 1) return error.BufferTooSmall;
        buffer[0] = @intFromEnum(MessageType.file_accept);
        return buffer[0..1];
    }
};

/// File reject message
pub const FileReject = struct {
    reason: []const u8,

    pub fn serialize(self: *const FileReject, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        try writer.writeByte(@intFromEnum(MessageType.file_reject));

        if (self.reason.len > std.math.maxInt(u16)) return error.ReasonTooLong;
        try writer.writeInt(u16, @intCast(self.reason.len), .big);
        try writer.writeAll(self.reason);

        return fbs.getWritten();
    }

    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !FileReject {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        _ = try reader.readByte(); // Skip type

        const reason_len = try reader.readInt(u16, .big);
        const reason = try allocator.alloc(u8, reason_len);
        _ = try reader.readAll(reason);

        return FileReject{ .reason = reason };
    }

    pub fn deinit(self: *FileReject, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

/// Chunk message - file data chunk
pub const Chunk = struct {
    index: u32,
    data: []const u8,

    pub fn serialize(self: *const Chunk, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        try writer.writeByte(@intFromEnum(MessageType.chunk));
        try writer.writeInt(u32, self.index, .big);
        try writer.writeInt(u32, @intCast(self.data.len), .big);
        try writer.writeAll(self.data);

        return fbs.getWritten();
    }

    pub fn deserialize(data: []const u8) !Chunk {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        _ = try reader.readByte(); // Skip type

        const index = try reader.readInt(u32, .big);
        const chunk_len = try reader.readInt(u32, .big);

        const pos = fbs.pos;
        if (data.len < pos + chunk_len) return error.UnexpectedEof;

        return Chunk{
            .index = index,
            .data = data[pos .. pos + chunk_len],
        };
    }
};

/// Chunk acknowledgment
pub const ChunkAck = struct {
    index: u32,

    pub fn serialize(self: *const ChunkAck, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        try writer.writeByte(@intFromEnum(MessageType.chunk_ack));
        try writer.writeInt(u32, self.index, .big);

        return fbs.getWritten();
    }

    pub fn deserialize(data: []const u8) !ChunkAck {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        _ = try reader.readByte(); // Skip type
        const index = try reader.readInt(u32, .big);

        return ChunkAck{ .index = index };
    }
};

/// Transfer complete message
pub const TransferComplete = struct {
    hash: [Sha256.digest_length]u8,

    pub fn serialize(self: *const TransferComplete, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        try writer.writeByte(@intFromEnum(MessageType.transfer_complete));
        try writer.writeAll(&self.hash);

        return fbs.getWritten();
    }

    pub fn deserialize(data: []const u8) !TransferComplete {
        if (data.len < 1 + Sha256.digest_length) return error.UnexpectedEof;

        var hash: [Sha256.digest_length]u8 = undefined;
        @memcpy(&hash, data[1..][0..Sha256.digest_length]);

        return TransferComplete{ .hash = hash };
    }
};

/// Error message
pub const ErrorMessage = struct {
    code: []const u8,
    message: []const u8,

    pub fn serialize(self: *const ErrorMessage, buffer: []u8) ![]u8 {
        var fbs = std.io.fixedBufferStream(buffer);
        const writer = fbs.writer();

        try writer.writeByte(@intFromEnum(MessageType.@"error"));

        try writer.writeInt(u16, @intCast(self.code.len), .big);
        try writer.writeAll(self.code);

        try writer.writeInt(u16, @intCast(self.message.len), .big);
        try writer.writeAll(self.message);

        return fbs.getWritten();
    }

    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !ErrorMessage {
        var fbs = std.io.fixedBufferStream(data);
        const reader = fbs.reader();

        _ = try reader.readByte(); // Skip type

        const code_len = try reader.readInt(u16, .big);
        const code = try allocator.alloc(u8, code_len);
        errdefer allocator.free(code);
        _ = try reader.readAll(code);

        const msg_len = try reader.readInt(u16, .big);
        const message = try allocator.alloc(u8, msg_len);
        errdefer allocator.free(message);
        _ = try reader.readAll(message);

        return ErrorMessage{ .code = code, .message = message };
    }

    pub fn deinit(self: *ErrorMessage, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.message);
    }
};

/// Parse message type from first byte
pub fn parseMessageType(data: []const u8) !MessageType {
    if (data.len < 1) return error.EmptyMessage;
    return std.meta.intToEnum(MessageType, data[0]) catch error.UnknownMessageType;
}

// Tests
test "file offer serialization" {
    const allocator = std.testing.allocator;

    var hash: [Sha256.digest_length]u8 = undefined;
    @memset(&hash, 0xAB);

    const offer = FileOffer{
        .filename = "test.txt",
        .size = 1024,
        .hash = hash,
        .chunk_size = 64 * 1024,
        .total_chunks = 1,
    };

    var buffer: [1024]u8 = undefined;
    const serialized = try offer.serialize(&buffer);

    var parsed = try FileOffer.deserialize(serialized, allocator);
    defer parsed.deinit(allocator);

    try std.testing.expectEqualSlices(u8, "test.txt", parsed.filename);
    try std.testing.expectEqual(@as(u64, 1024), parsed.size);
    try std.testing.expectEqualSlices(u8, &hash, &parsed.hash);
}

test "chunk serialization" {
    const chunk = Chunk{
        .index = 42,
        .data = "Hello, World!",
    };

    var buffer: [1024]u8 = undefined;
    const serialized = try chunk.serialize(&buffer);

    const parsed = try Chunk.deserialize(serialized);

    try std.testing.expectEqual(@as(u32, 42), parsed.index);
    try std.testing.expectEqualSlices(u8, "Hello, World!", parsed.data);
}

test "chunk ack serialization" {
    const ack = ChunkAck{ .index = 123 };

    var buffer: [16]u8 = undefined;
    const serialized = try ack.serialize(&buffer);

    const parsed = try ChunkAck.deserialize(serialized);

    try std.testing.expectEqual(@as(u32, 123), parsed.index);
}

test "parse message type" {
    const offer_msg = [_]u8{0x01} ++ [_]u8{0} ** 10;
    try std.testing.expectEqual(MessageType.file_offer, try parseMessageType(&offer_msg));

    const chunk_msg = [_]u8{0x04} ++ [_]u8{0} ** 10;
    try std.testing.expectEqual(MessageType.chunk, try parseMessageType(&chunk_msg));
}
