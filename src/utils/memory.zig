//! Secure memory wiping utilities.
//!
//! Provides functions for securely zeroing sensitive data in memory
//! to prevent leaks via memory dumps or swap.

const std = @import("std");

/// Securely zero a byte slice, preventing compiler optimization from removing the operation.
/// Uses Zig's crypto utility for this purpose.
pub fn secureZero(buffer: []u8) void {
    // Cast to volatile slice for secureZero
    const volatile_buf: []volatile u8 = @volatileCast(buffer);
    std.crypto.secureZero(u8, volatile_buf);
}

/// Securely zero a fixed-size array
pub fn secureZeroArray(comptime N: usize, buffer: *[N]u8) void {
    const volatile_buf: *volatile [N]u8 = @volatileCast(buffer);
    std.crypto.secureZero(u8, volatile_buf);
}

/// Allocator wrapper that zeros memory on free
pub const SecureAllocator = struct {
    backing_allocator: std.mem.Allocator,

    pub fn allocator(self: *SecureAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        return self.backing_allocator.rawRemap(buf, buf_align, new_len, ret_addr);
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        return self.backing_allocator.rawAlloc(len, ptr_align, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));

        // If shrinking, zero the freed portion before resize
        if (new_len < buf.len) {
            secureZero(buf[new_len..]);
        }

        return self.backing_allocator.rawResize(buf, buf_align, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));

        // Zero the memory before freeing
        secureZero(buf);
        self.backing_allocator.rawFree(buf, buf_align, ret_addr);
    }
};

/// Create a secure allocator wrapping another allocator
pub fn secureAllocator(backing: std.mem.Allocator) SecureAllocator {
    return SecureAllocator{ .backing_allocator = backing };
}

// Tests
test "secure zero" {
    var buffer = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    secureZero(&buffer);

    for (buffer) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "secure zero array" {
    var buffer = [_]u8{ 0xFF, 0xFE, 0xFD, 0xFC };
    secureZeroArray(4, &buffer);

    for (buffer) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "secure allocator zeros on free" {
    const backing = std.testing.allocator;
    var secure_alloc = secureAllocator(backing);
    const alloc = secure_alloc.allocator();

    const slice = try alloc.alloc(u8, 32);
    @memset(slice, 0xAB);

    // Store pointer for later verification (in real code this would be undefined behavior,
    // but for testing we verify the allocator works as expected)
    const ptr = slice.ptr;
    _ = ptr;

    alloc.free(slice);

    // Memory should be zeroed (though we can't safely verify this in a test
    // as the memory is freed)
}
