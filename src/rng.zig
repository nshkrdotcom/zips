//rng.zig
const std = @import("std");
const crypto = std.crypto;
const Error = @import("error.zig").Error;

pub const RandomnessError = Error.RandomnessFailure;

pub fn generateRandomBytes(buffer: []u8) RandomnessError!void {
    crypto.random(buffer);
}

// Optional initialization (if needed)
pub fn init() !void {
    // Initialize system CSPRNG. This is not usually necessary, but useful for early error detection.
     if (std.crypto.random.ptr == null) {
        try std.crypto.init();
    }
}

test "generate random bytes fills buffer" {
    var buffer: [32]u8 = undefined;
    try generateRandomBytes(&buffer);
    std.testing.expect(buffer.len == 32);
    // Simple check. Could add statistical tests for better randomness validation, but not essential
    var allZeroes = true;
    for (buffer) |byte| {
        if (byte != 0) {
            allZeroes = false;
            break;
        }
    }
    std.testing.expect(!allZeroes); // Check that the buffer is not all zeroes (unlikely but possible)
}