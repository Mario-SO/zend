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
pub fn getConfigDir(allocator: std.mem.Allocator) ![]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| {
        if (err == error.EnvironmentVariableNotFound) {
            return error.HomeNotFound;
        }
        return err;
    };
    defer allocator.free(home);

    return std.fs.path.join(allocator, &.{ home, config_dir_name });
}

/// Get the identity file path
pub fn getIdentityPath(allocator: std.mem.Allocator) ![]u8 {
    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    return std.fs.path.join(allocator, &.{ config_dir, identity_file_name });
}

/// Check if identity exists
pub fn identityExists(allocator: std.mem.Allocator) !bool {
    const path = try getIdentityPath(allocator);
    defer allocator.free(path);

    std.fs.cwd().access(path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return false;
        }
        return err;
    };
    return true;
}

/// Save identity to disk
pub fn saveIdentity(allocator: std.mem.Allocator, identity: *const keypair.Identity) !void {
    // Ensure config directory exists
    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    std.fs.cwd().makePath(config_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };

    // Get identity file path
    const path = try getIdentityPath(allocator);
    defer allocator.free(path);

    // Write secret key to file (plaintext)
    const file = try std.fs.cwd().createFile(path, .{ .mode = 0o600 });
    defer file.close();

    try file.writeAll(&identity.secret_key);
}

/// Load identity from disk
pub fn loadIdentity(allocator: std.mem.Allocator) !keypair.Identity {
    const path = try getIdentityPath(allocator);
    defer allocator.free(path);

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var secret_key: [keypair.ed25519_secret_key_len]u8 = undefined;
    const bytes_read = try file.readAll(&secret_key);

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
pub fn deleteIdentity(allocator: std.mem.Allocator) !void {
    const path = try getIdentityPath(allocator);
    defer allocator.free(path);

    try std.fs.cwd().deleteFile(path);
}

// Tests
test "config dir path" {
    const allocator = std.testing.allocator;
    const path = try getConfigDir(allocator);
    defer allocator.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, ".zend"));
}

test "identity path" {
    const allocator = std.testing.allocator;
    const path = try getIdentityPath(allocator);
    defer allocator.free(path);

    try std.testing.expect(std.mem.endsWith(u8, path, "identity"));
}
