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
};

// Optional custom error type if needed
pub const CustomError = struct {
    errorCode: u32,
    
    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("Error Code: {}, Error Name: CustomError", .{ self.errorCode });
    }
};

// Helper functions for printing errors (optional but recommended)
pub fn printError(err: anyerror, comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ ": {s}\n", .{@errorName(err)});
    _ = args; // Add this line to suppress the unused parameter warning
}

pub fn panicOnError(err: anyerror, comptime message: []const u8) noreturn {
    printError(err, message, .{});
    std.process.exit(1);
}

test "panic on error test" {
    // Example
    const expected_error = Error.InvalidParams;
    const test_fn = struct {
        fn call() !void {
            panicOnError(expected_error, "Failed to generate keypair");
        }
    }.call;
    
    try std.testing.expectError(expected_error, test_fn());
}