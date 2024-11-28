//rng.zig
const std = @import("std");
const crypto = std.crypto;
const Error = @import("error.zig").Error;

pub const RandomnessError = Error.RandomnessFailure;

pub fn generateRandomBytes(buffer: []u8) !void {
    std.crypto.random.bytes(buffer);
}

test "generate random bytes fills buffer" {
    var buffer: [32]u8 = undefined;
    try generateRandomBytes(&buffer); // Now handles potential errors
    try std.testing.expectEqual(@as(usize, 32), buffer.len);
    // Simple check (more robust statistical tests could be added)
    var allZeroes = true;
    for (buffer) |byte| {
        if (byte != 0) {
            allZeroes = false;
            break;
        }
    }
    try std.testing.expect(!allZeroes);
}
