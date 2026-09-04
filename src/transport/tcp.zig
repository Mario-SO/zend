//! TCP connection handling - client and server operations.
//!
//! Provides basic TCP networking primitives for zend.

const std = @import("std");
const net = std.Io.net;

/// Default zend port
pub const default_port: u16 = 7654;

/// TCP connection wrapper
pub const TcpConnection = struct {
    io: std.Io,
    stream: net.Stream,

    /// Close the connection
    pub fn close(self: *TcpConnection) void {
        self.stream.close(self.io);
    }

    /// Read data from connection
    pub fn read(self: *TcpConnection, buffer: []u8) !usize {
        var reader = self.stream.reader(self.io, &.{});
        return reader.interface.readSliceShort(buffer);
    }

    /// Read exactly n bytes (blocks until buffer is full or EOF)
    pub fn readAll(self: *TcpConnection, buffer: []u8) !usize {
        var reader = self.stream.reader(self.io, &.{});
        var total_read: usize = 0;
        while (total_read < buffer.len) {
            const bytes_read = reader.interface.readSliceShort(buffer[total_read..]) catch |err| {
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
        var writer = self.stream.writer(self.io, &.{});
        return writer.interface.writeVec(&.{data});
    }

    /// Write all data to connection
    pub fn writeAll(self: *TcpConnection, data: []const u8) !void {
        var writer = self.stream.writer(self.io, &.{});
        try writer.interface.writeAll(data);
    }
};

/// TCP client - connect to a peer
pub const TcpClient = struct {
    /// Connect to a peer at the given address
    pub fn connect(io: std.Io, address: []const u8) !TcpConnection {
        // Parse address (host:port format)
        const parsed = parseAddress(address) catch {
            return error.InvalidAddress;
        };

        const host = net.HostName.init(parsed.host) catch return error.InvalidAddress;
        const stream = host.connect(io, parsed.port, .{
            .mode = .stream,
            .protocol = .tcp,
        }) catch {
            return error.ConnectionFailed;
        };

        return TcpConnection{ .io = io, .stream = stream };
    }
};

/// TCP server - listen for incoming connections
pub const TcpServer = struct {
    io: std.Io,
    server: net.Server,
    port: u16,

    /// Start listening on the given port
    pub fn listen(io: std.Io, port: u16) !TcpServer {
        const address: net.IpAddress = .{ .ip4 = .unspecified(port) };
        const server = address.listen(io, .{
            .reuse_address = true,
        }) catch {
            return error.ListenFailed;
        };

        return TcpServer{ .io = io, .server = server, .port = port };
    }

    /// Accept an incoming connection
    pub fn accept(self: *TcpServer) !TcpConnection {
        const stream = self.server.accept(self.io) catch {
            return error.AcceptFailed;
        };
        return TcpConnection{ .io = self.io, .stream = stream };
    }

    /// Get the port we're listening on
    pub fn getPort(self: *const TcpServer) u16 {
        return self.port;
    }

    /// Close the server
    pub fn close(self: *TcpServer) void {
        self.server.deinit(self.io);
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
