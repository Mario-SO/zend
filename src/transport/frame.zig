//! Length-prefixed message framing.
//!
//! All messages are framed as: [4-byte big-endian length][payload]
//! Maximum frame size is 64KB to match zenc chunk size.

const std = @import("std");
const tcp = @import("tcp.zig");

/// Maximum frame size (64KB)
pub const max_frame_size: usize = 64 * 1024;

/// Frame header size (4 bytes for length)
pub const header_size: usize = 4;

/// Framed connection wrapper
pub const FramedConnection = struct {
    conn: *tcp.TcpConnection,
    read_buffer: [max_frame_size + header_size]u8 = undefined,

    /// Initialize a framed connection
    pub fn init(conn: *tcp.TcpConnection) FramedConnection {
        return FramedConnection{
            .conn = conn,
        };
    }

    /// Send a framed message
    pub fn send(self: *FramedConnection, data: []const u8) !void {
        if (data.len > max_frame_size) {
            return error.FrameTooLarge;
        }

        // Write length header (big-endian)
        var header: [header_size]u8 = undefined;
        std.mem.writeInt(u32, &header, @intCast(data.len), .big);

        try self.conn.writeAll(&header);
        try self.conn.writeAll(data);
    }

    /// Receive a framed message
    /// Returns the message payload (slice into internal buffer)
    pub fn receive(self: *FramedConnection) ![]u8 {
        // Read length header
        var header: [header_size]u8 = undefined;
        const header_read = try self.conn.readAll(&header);
        if (header_read < header_size) {
            return error.ConnectionClosed;
        }

        const length = std.mem.readInt(u32, &header, .big);

        if (length > max_frame_size) {
            return error.FrameTooLarge;
        }

        if (length == 0) {
            return self.read_buffer[0..0];
        }

        // Read payload
        const payload_read = try self.conn.readAll(self.read_buffer[0..length]);
        if (payload_read < length) {
            return error.ConnectionClosed;
        }

        return self.read_buffer[0..length];
    }
};

/// Create a length-prefixed frame in the provided buffer
/// Returns the complete frame (header + payload)
pub fn createFrame(buffer: []u8, payload: []const u8) ![]u8 {
    if (payload.len > max_frame_size) {
        return error.FrameTooLarge;
    }
    if (buffer.len < header_size + payload.len) {
        return error.BufferTooSmall;
    }

    // Write length header
    std.mem.writeInt(u32, buffer[0..header_size], @intCast(payload.len), .big);

    // Copy payload
    @memcpy(buffer[header_size .. header_size + payload.len], payload);

    return buffer[0 .. header_size + payload.len];
}

/// Parse a frame header to get the payload length
pub fn parseFrameHeader(header: [header_size]u8) u32 {
    return std.mem.readInt(u32, &header, .big);
}

// Tests
test "create and parse frame" {
    var buffer: [1024]u8 = undefined;
    const payload = "Hello, World!";

    const frame = try createFrame(&buffer, payload);

    // Verify header
    const length = parseFrameHeader(frame[0..header_size].*);
    try std.testing.expectEqual(@as(u32, 13), length);

    // Verify payload
    try std.testing.expectEqualSlices(u8, payload, frame[header_size..]);
}

test "frame too large rejected" {
    var buffer: [max_frame_size + header_size + 1]u8 = undefined;
    var large_payload: [max_frame_size + 1]u8 = undefined;

    const result = createFrame(&buffer, &large_payload);
    try std.testing.expectError(error.FrameTooLarge, result);
}

test "buffer too small rejected" {
    var buffer: [10]u8 = undefined;
    const payload = "This is too long for the buffer";

    const result = createFrame(&buffer, payload);
    try std.testing.expectError(error.BufferTooSmall, result);
}
