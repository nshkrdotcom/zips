const std = @import("std");
const cbd = @import("cbd.zig");
const params = @import("params.zig");
const expectEqual = std.testing.expectEqual;

test "cbd.samplePolyCBD generates polynomial of correct length and range" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    inline for (.{ params.Params.kem512, params.Params.kem768, params.Params.kem1024 }) |param_set| {
        const pd = param_set.get();
        var polynomial = try cbd.samplePolyCBD(pd, allocator);
        defer allocator.free(polynomial); // Free memory after each test case
        try expectEqual(polynomial.len, pd.n);

        for (polynomial) |coeff| {
            try std.testing.expect(coeff < pd.q); // Check if coefficients are within the range [0, q-1]
        }
    }
}

test "cbd.samplePolyCBD generates different polynomials for different seeds" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    inline for (.{ params.Params.kem512, params.Params.kem768, params.Params.kem1024 }) |param_set| {
        const pd = param_set.get();

        // Generate two different seeds (replace with your actual seed generation)
        var seed1: [pd.eta1 * pd.n]u8 = undefined; 
        var seed2: [pd.eta1 * pd.n]u8 = undefined;

        // Initialize with distinct values to ensure different seeds (example)
        for (seed1, 0..) |*byte, i| {
            byte.* = @intCast(u8, i % 256);
        }
        for (seed2, 0..) |*byte, i| {
            byte.* = @intCast(u8, (i + 1) % 256);
        }

        var polynomial1 = try cbd.samplePolyCBD(pd, allocator);
        defer allocator.free(polynomial1);
        var polynomial2 = try cbd.samplePolyCBD(pd, allocator);
        defer allocator.free(polynomial2);


        try std.testing.expect(!std.mem.eql(u16, polynomial1, polynomial2)); // Polynomials should be different
    }
}

// Statistical Tests (Recommended):
// While the above tests check basic properties, consider adding statistical tests
// to verify the distribution of coefficients more thoroughly.  These tests might 
// involve checking the mean, variance, or frequency distribution of the 
// coefficients against the expected CBD properties.
