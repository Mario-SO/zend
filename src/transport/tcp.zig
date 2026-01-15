//! TCP connection handling - client and server operations.
//!
//! Provides basic TCP networking primitives for zend.

const std = @import("std");
const posix = std.posix;

/// Default zend port
pub const default_port: u16 = 7654;

/// TCP connection wrapper
pub const TcpConnection = struct {
    stream: std.net.Stream,

    /// Close the connection
    pub fn close(self: *TcpConnection) void {
        self.stream.close();
    }

    /// Read data from connection
    pub fn read(self: *TcpConnection, buffer: []u8) !usize {
        return self.stream.read(buffer);
    }

    /// Read exactly n bytes (blocks until buffer is full or EOF)
    pub fn readAll(self: *TcpConnection, buffer: []u8) !usize {
        var total_read: usize = 0;
        while (total_read < buffer.len) {
            const bytes_read = self.stream.read(buffer[total_read..]) catch |err| {
                if (total_read > 0) return total_read;
                return err;
            };
            if (bytes_read == 0) break; // EOF
            total_read += bytes_read;
        }
        return total_read;
    }

    /// Write data to connection
    pub fn write(self: *TcpConnection, data: []const u8) !usize {
        return self.stream.write(data);
    }

    /// Write all data to connection
    pub fn writeAll(self: *TcpConnection, data: []const u8) !void {
        var total_written: usize = 0;
        while (total_written < data.len) {
            const bytes_written = try self.stream.write(data[total_written..]);
            if (bytes_written == 0) return error.ConnectionClosed;
            total_written += bytes_written;
        }
    }

    /// Get peer address as string
    pub fn getPeerAddress(self: *const TcpConnection, buffer: []u8) ![]const u8 {
        const addr = self.stream.getRemoteAddress();
        return std.fmt.bufPrint(buffer, "{}", .{addr}) catch return error.BufferTooSmall;
    }
};

/// TCP client - connect to a peer
pub const TcpClient = struct {
    /// Connect to a peer at the given address
    pub fn connect(address: []const u8) !TcpConnection {
        // Parse address (host:port format)
        const parsed = parseAddress(address) catch {
            return error.InvalidAddress;
        };

        const stream = std.net.tcpConnectToHost(std.heap.page_allocator, parsed.host, parsed.port) catch {
            return error.ConnectionFailed;
        };

        return TcpConnection{ .stream = stream };
    }
};

/// TCP server - listen for incoming connections
pub const TcpServer = struct {
    server: std.net.Server,

    /// Start listening on the given port
    pub fn listen(port: u16) !TcpServer {
        const address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        const server = address.listen(.{
            .reuse_address = true,
        }) catch {
            return error.ListenFailed;
        };

        return TcpServer{ .server = server };
    }

    /// Accept an incoming connection
    pub fn accept(self: *TcpServer) !TcpConnection {
        const conn = self.server.accept() catch {
            return error.AcceptFailed;
        };
        return TcpConnection{ .stream = conn.stream };
    }

    /// Get the port we're listening on
    pub fn getPort(self: *const TcpServer) u16 {
        return self.server.listen_address.getPort();
    }

    /// Close the server
    pub fn close(self: *TcpServer) void {
        self.server.deinit();
    }
};

/// Parsed address (host and port)
pub const ParsedAddress = struct {
    host: []const u8,
    port: u16,
};

/// Parse an address string in host:port format
pub fn parseAddress(address: []const u8) !ParsedAddress {
    // Find the last colon (to handle IPv6 addresses)
    var last_colon: ?usize = null;
    for (address, 0..) |c, i| {
        if (c == ':') {
            last_colon = i;
        }
    }

    if (last_colon) |colon_pos| {
        const host = address[0..colon_pos];
        const port_str = address[colon_pos + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch {
            return error.InvalidPort;
        };
        return ParsedAddress{
            .host = host,
            .port = port,
        };
    } else {
        // No port specified, use default
        return ParsedAddress{
            .host = address,
            .port = default_port,
        };
    }
}

// Tests
test "parse address with port" {
    const parsed = try parseAddress("192.168.1.100:7654");
    try std.testing.expectEqualSlices(u8, "192.168.1.100", parsed.host);
    try std.testing.expectEqual(@as(u16, 7654), parsed.port);
}

test "parse address without port" {
    const parsed = try parseAddress("192.168.1.100");
    try std.testing.expectEqualSlices(u8, "192.168.1.100", parsed.host);
    try std.testing.expectEqual(default_port, parsed.port);
}

test "parse address with hostname" {
    const parsed = try parseAddress("localhost:8080");
    try std.testing.expectEqualSlices(u8, "localhost", parsed.host);
    try std.testing.expectEqual(@as(u16, 8080), parsed.port);
}
