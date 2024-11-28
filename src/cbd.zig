//cbd.zig
const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const Error = @import("error.zig").Error;

pub fn samplePolyCBD(pd: params.ParamDetails, allocator: std.mem.Allocator) Error![]u16 {
    // Use a dynamic allocation for bytes instead of a compile-time fixed array
    var bytes = try allocator.alloc(u8, pd.eta1 * pd.n * 2);
    defer allocator.free(bytes);

    try rng.generateRandomBytes(bytes);

    var polynomial = try allocator.alloc(u16, pd.n);

    var i: usize = 0;
    while (i < pd.n) : (i += 1) {
        const x = sumBits(bytes[i * pd.eta1 .. i * pd.eta1 + pd.eta1]);
        const y = sumBits(bytes[pd.n * pd.eta1 + i * pd.eta1 .. pd.n * pd.eta1 + i * pd.eta1 + pd.eta1]);
        polynomial[i] = @rem(@as(u16, x) -% @as(u16, y) +% pd.q, pd.q);
    }
    return polynomial;
}

fn sumBits(bits: []const u8) u16 {
    var sum: u16 = 0;
    for (bits) |bit| {
        sum += bit;
    }
    return sum;
}

const expectEqual = std.testing.expectEqual;

test "samplePolyCBD generates polynomial of correct length" {
    const pd = params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const polynomial = try samplePolyCBD(pd, gpa.allocator());
    defer gpa.allocator().free(polynomial);
    try expectEqual(polynomial.len, pd.n);
}

test "samplePolyCBD generates different polynomials" {
    const pd = params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const p1 = try samplePolyCBD(pd, gpa.allocator());
    defer gpa.allocator().free(p1);

    const p2 = try samplePolyCBD(pd, gpa.allocator());
    defer gpa.allocator().free(p2);
    try std.testing.expect(!std.mem.eql(u16, p1, p2));
}
