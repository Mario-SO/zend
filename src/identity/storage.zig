//! Identity storage - load/save identity to disk.
//!
//! Identity is stored at ~/.zend/identity as a plaintext file
//! containing the 64-byte Ed25519 secret key.

const std = @import("std");
const keypair = @import("keypair.zig");
const memory = @import("../utils/memory.zig");

/// Default zend config directory name
pub const config_dir_name = ".zend";
/// Identity file name
pub const identity_file_name = "identity";

/// Get the zend config directory path
pub fn getConfigDir(environ: *const std.process.Environ.Map, allocator: std.mem.Allocator) ![]u8 {
    const home = environ.get("HOME") orelse return error.HomeNotFound;
    return std.fs.path.join(allocator, &.{ home, config_dir_name });
}

/// Get the identity file path
pub fn getIdentityPath(environ: *const std.process.Environ.Map, allocator: std.mem.Allocator) ![]u8 {
    const config_dir = try getConfigDir(environ, allocator);
    defer allocator.free(config_dir);

    return std.fs.path.join(allocator, &.{ config_dir, identity_file_name });
}

/// Check if identity exists
pub fn identityExists(io: std.Io, environ: *const std.process.Environ.Map, allocator: std.mem.Allocator) !bool {
    const path = try getIdentityPath(environ, allocator);
    defer allocator.free(path);

    std.Io.Dir.cwd().access(io, path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return false;
        }
        return err;
    };
    return true;
}

/// Save identity to disk
pub fn saveIdentity(io: std.Io, environ: *const std.process.Environ.Map, allocator: std.mem.Allocator, identity: *const keypair.Identity) !void {
    // Ensure config directory exists
    const config_dir = try getConfigDir(environ, allocator);
    defer allocator.free(config_dir);

    try std.Io.Dir.cwd().createDirPath(io, config_dir);

    // Get identity file path
    const path = try getIdentityPath(environ, allocator);
    defer allocator.free(path);

    // Write secret key to file (plaintext)
    const permissions: std.Io.File.Permissions = if (comptime std.Io.File.Permissions.has_executable_bit)
        @enumFromInt(0o600)
    else
        .default_file;
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .permissions = permissions });
    defer file.close(io);

    try file.writeStreamingAll(io, &identity.secret_key);
}

/// Load identity from disk
pub fn loadIdentity(io: std.Io, environ: *const std.process.Environ.Map, allocator: std.mem.Allocator) !keypair.Identity {
    const path = try getIdentityPath(environ, allocator);
    defer allocator.free(path);

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var secret_key: [keypair.ed25519_secret_key_len]u8 = undefined;
    const bytes_read = try file.readPositionalAll(io, &secret_key, 0);

    if (bytes_read != keypair.ed25519_secret_key_len) {
        return error.InvalidIdentityFile;
    }

    // Ed25519 secret key is 64 bytes: first 32 are seed, last 32 are public key
    // Extract public key from the secret key
    var public_key: [keypair.ed25519_public_key_len]u8 = undefined;
    @memcpy(&public_key, secret_key[32..64]);

    return keypair.Identity{
        .public_key = public_key,
        .secret_key = secret_key,
    };
}

/// Delete identity from disk
pub fn deleteIdentity(io: std.Io, environ: *const std.process.Environ.Map, allocator: std.mem.Allocator) !void {
    const path = try getIdentityPath(environ, allocator);
    defer allocator.free(path);

    try std.Io.Dir.cwd().deleteFile(io, path);
}

// Tests
test "config dir path" {
    const allocator = std.testing.allocator;
    var environ = std.process.Environ.Map.init(allocator);
    defer environ.deinit();
    try environ.put("HOME", "/tmp/zend-test-home");
    const path = try getConfigDir(&environ, allocator);
    defer allocator.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, ".zend"));
}

test "identity path" {
    const allocator = std.testing.allocator;
    var environ = std.process.Environ.Map.init(allocator);
    defer environ.deinit();
    try environ.put("HOME", "/tmp/zend-test-home");
    const path = try getIdentityPath(&environ, allocator);
    defer allocator.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, "identity"));
}
