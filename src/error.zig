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
    InvalidInput, // Generic invalid input error
    // ... add other specific errors if needed, but these cover most KEM/crypto cases
} || struct {
    errorCode: u32,
    
    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {

        _ = fmt;
        _ = options;
        try writer.print("Error Code: {}, Error Name: {s}", .{ self.errorCode, @errorName(@This()) });
    }
};

// Helper functions for printing errors (optional but recommended)
pub fn printError(err: anyerror, comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ ": {s}\n", .{@errorName(err)});
}

pub fn panicOnError(err: anyerror, comptime message: []const u8) noreturn {
    printError(err, message, .{});
    std.process.exit(1);
}

test "panic on error test" {
    // Example
    const expected_error = Error.InvalidParams;
    std.testing.expectPanic(
        || panicOnError(expected_error, "Failed to generate keypair"),
        "Failed to generate keypair: InvalidParams", // Check error name matches
    );
}