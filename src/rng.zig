//rng.zig
const std = @import("std");
const crypto = std.crypto;
const Error = @import("error.zig").Error;

pub const RandomnessError = Error.RandomnessFailure;

pub fn generateRandomBytes(buffer: []u8) !void {
    // crypto.random doesn't have an error return.  We need to handle potential (rare) failure.
    if (std.crypto.random.ptr == null) { // Check for failure of crypto initialization.
        return RandomnessError;
    }
    std.crypto.random(buffer);
}

// Optional explicit initialization
pub fn init() !void {
    // Initialize system CSPRNG for early error detection (optional).
    try std.crypto.init(); // This function *does* have an error return.
}

test "generate random bytes fills buffer" {
    try init(); // Initialize CSPRNG in tests as well

    var buffer: [32]u8 = undefined;
    try generateRandomBytes(&buffer); // Now handles potential errors
    std.testing.expect(buffer.len == 32);

    // Simple check (more robust statistical tests could be added)
    var allZeroes = true;
    for (buffer) |byte| {
        if (byte != 0) {
            allZeroes = false;
            break;
        }
    }
    std.testing.expect(!allZeroes); 
}