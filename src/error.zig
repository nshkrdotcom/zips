const std = @import("std");

pub const Error = error{
    InvalidParams,
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidCiphertext,
    InvalidSharedSecret,
    DecryptionFailure,
    EncapsulationFailure,
    DecapsulationFailure,
    RandomnessFailure,
    AllocationFailure,
    // ... add other specific errors as needed ...
    SodiumInitFailure, // If you use libsodium for example
};


// Helper functions for printing errors (optional but recommended)
pub fn printError(err: Error, comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ " : ", args);
    std.debug.print("{}\n", .{@errorName(err)});
}