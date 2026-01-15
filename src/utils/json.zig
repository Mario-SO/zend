//! JSON event output helpers for zend.
//!
//! Provides structured JSON output for IPC with hermes.
//! All output is line-delimited JSON to stdout.

const std = @import("std");

/// Event types for JSON output
pub const EventType = enum {
    identity_created,
    identity_loaded,
    peer_added,
    peer_removed,
    peer_list,
    connecting,
    listening,
    connection_accepted,
    handshake_complete,
    transfer_start,
    progress,
    transfer_complete,
    @"error",
};

/// Stdout writer buffer (thread-local for safety)
threadlocal var stdout_buffer: [8192]u8 = undefined;

/// Write a JSON event to stdout
fn writeEvent(event_type: EventType, fields: anytype) !void {
    // Build JSON in buffer first, then write all at once
    var fbs = std.io.fixedBufferStream(&stdout_buffer);
    try writeEventTo(fbs.writer(), event_type, fields);

    // Write to stdout
    const stdout = std.fs.File.stdout();
    stdout.writeAll(fbs.getWritten()) catch {};
}

/// Write a JSON event to a specific writer (useful for testing)
pub fn writeEventTo(writer: anytype, event_type: EventType, fields: anytype) !void {
    try writer.writeAll("{\"event\":\"");
    try writer.writeAll(@tagName(event_type));
    try writer.writeAll("\"");

    // Write additional fields
    inline for (std.meta.fields(@TypeOf(fields))) |field| {
        try writer.writeAll(",\"");
        try writer.writeAll(field.name);
        try writer.writeAll("\":");

        const value = @field(fields, field.name);
        try writeValue(writer, value);
    }

    try writer.writeAll("}\n");
}

/// Write a JSON value
fn writeValue(writer: anytype, value: anytype) !void {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .int, .comptime_int => {
            try writer.print("{d}", .{value});
        },
        .float, .comptime_float => {
            try writer.print("{d:.2}", .{value});
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .optional => {
            if (value) |v| {
                try writeValue(writer, v);
            } else {
                try writer.writeAll("null");
            }
        },
        .pointer => |ptr| {
            if (ptr.size == .slice) {
                if (ptr.child == u8) {
                    // String
                    try writeString(writer, value);
                } else {
                    // Array of other types
                    try writer.writeAll("[");
                    for (value, 0..) |item, i| {
                        if (i > 0) try writer.writeAll(",");
                        try writeValue(writer, item);
                    }
                    try writer.writeAll("]");
                }
            } else if (ptr.size == .one) {
                // Pointer to array - dereference and write
                if (@typeInfo(ptr.child) == .array) {
                    const arr_info = @typeInfo(ptr.child).array;
                    if (arr_info.child == u8) {
                        try writeString(writer, value);
                    } else {
                        try writer.writeAll("[");
                        for (value.*, 0..) |item, i| {
                            if (i > 0) try writer.writeAll(",");
                            try writeValue(writer, item);
                        }
                        try writer.writeAll("]");
                    }
                } else {
                    try writeValue(writer, value.*);
                }
            } else {
                @compileError("Unsupported pointer type for JSON serialization");
            }
        },
        .array => |arr| {
            if (arr.child == u8) {
                try writeString(writer, &value);
            } else {
                try writer.writeAll("[");
                for (value, 0..) |item, i| {
                    if (i > 0) try writer.writeAll(",");
                    try writeValue(writer, item);
                }
                try writer.writeAll("]");
            }
        },
        else => {
            @compileError("Unsupported type for JSON serialization: " ++ @typeName(T));
        },
    }
}

/// Write a JSON-escaped string
fn writeString(writer: anytype, str: []const u8) !void {
    try writer.writeAll("\"");
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
    try writer.writeAll("\"");
}

// Convenience functions for zend events

/// Emit identity created event
pub fn emitIdentityCreated(public_key: []const u8, fingerprint: []const u8) !void {
    try writeEvent(.identity_created, .{ .public_key = public_key, .fingerprint = fingerprint });
}

/// Emit identity loaded event
pub fn emitIdentityLoaded(public_key: []const u8, fingerprint: []const u8) !void {
    try writeEvent(.identity_loaded, .{ .public_key = public_key, .fingerprint = fingerprint });
}

/// Emit peer added event
pub fn emitPeerAdded(name: []const u8, fingerprint: []const u8) !void {
    try writeEvent(.peer_added, .{ .name = name, .fingerprint = fingerprint });
}

/// Emit peer removed event
pub fn emitPeerRemoved(name: []const u8) !void {
    try writeEvent(.peer_removed, .{ .name = name });
}

/// Emit connecting event
pub fn emitConnecting(peer: []const u8, address: []const u8) !void {
    try writeEvent(.connecting, .{ .peer = peer, .address = address });
}

/// Emit listening event
pub fn emitListening(port: u16) !void {
    try writeEvent(.listening, .{ .port = port });
}

/// Emit connection accepted event
pub fn emitConnectionAccepted(address: []const u8) !void {
    try writeEvent(.connection_accepted, .{ .address = address });
}

/// Emit handshake complete event
pub fn emitHandshakeComplete(peer: []const u8) !void {
    try writeEvent(.handshake_complete, .{ .peer = peer });
}

/// Emit transfer start event
pub fn emitTransferStart(file: []const u8, size: u64, peer: []const u8) !void {
    try writeEvent(.transfer_start, .{ .file = file, .size = size, .peer = peer });
}

/// Emit a progress event
pub fn emitProgress(bytes: u64, percent: f64) !void {
    try writeEvent(.progress, .{ .bytes = bytes, .percent = percent });
}

/// Emit transfer complete event
pub fn emitTransferComplete(file: []const u8, hash: []const u8) !void {
    try writeEvent(.transfer_complete, .{ .file = file, .hash = hash });
}

/// Emit an error event
pub fn emitError(code: []const u8, message: []const u8) !void {
    try writeEvent(.@"error", .{ .code = code, .message = message });
}

/// Write raw JSON string to stdout (for peer list)
pub fn emitRaw(data: []const u8) !void {
    const stdout = std.fs.File.stdout();
    stdout.writeAll(data) catch {};
}

// Tests
test "json string escaping" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeString(fbs.writer(), "hello\"world\\test\n");
    const result = fbs.getWritten();

    try std.testing.expectEqualSlices(u8, "\"hello\\\"world\\\\test\\n\"", result);
}

test "write event with fields" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeEventTo(fbs.writer(), .identity_created, .{ .public_key = "abc123", .fingerprint = "def456" });
    const result = fbs.getWritten();

    try std.testing.expectEqualSlices(u8, "{\"event\":\"identity_created\",\"public_key\":\"abc123\",\"fingerprint\":\"def456\"}\n", result);
}

test "write progress event" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeEventTo(fbs.writer(), .progress, .{ .bytes = @as(u64, 65536), .percent = @as(f64, 42.50) });
    const result = fbs.getWritten();

    try std.testing.expectEqualSlices(u8, "{\"event\":\"progress\",\"bytes\":65536,\"percent\":42.50}\n", result);
}

test "write error event" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    try writeEventTo(fbs.writer(), .@"error", .{ .code = "invalid_file", .message = "File not found" });
    const result = fbs.getWritten();

    try std.testing.expectEqualSlices(u8, "{\"event\":\"error\",\"code\":\"invalid_file\",\"message\":\"File not found\"}\n", result);
}
