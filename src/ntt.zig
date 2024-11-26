//ntt.zig
const std = @import("std");
const mem = std.mem; // Add this line
const crypto = std.crypto;
const params = @import("params.zig");
const utils = @import("utils.zig");
const Error = @import("error.zig").Error;

// Define the type for elements in Rq and Tq (using ParamDetails)
pub fn RqTq(comptime pd: params.ParamDetails) type {
    return [pd.n]u16;
}

pub fn allocOrError(allocator: *mem.Allocator, comptime T: type, size: usize) Error![]T {
    return allocator.alloc(T, size) catch |err| switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
    };
}

// Pre-compute zetas (This should be done only ONCE per parameter set)
fn precomputeZetas(comptime pd: params.ParamDetails, allocator: std.mem.Allocator) ![]u16 {
    const zetas = try allocator.alloc(u16, pd.n / 2);
    for (zetas, 0..) |*zeta, i| {
        zeta.* = utils.computeZeta(@as(u8, @intCast(i + 1)));
    }
    return zetas;
}

// Forward NTT
pub fn ntt(comptime pd: params.ParamDetails, f: *RqTq(pd), zetas: []const u16) void {
    var f_hat = f.*; // operate in-place on f_hat
    var i: u8 = 1;
    var len: u32 = pd.n / 2;

    while (len >= 2) : (len /= 2) {
        var start: u32 = 0;
        while (start < pd.n) : (start += 2 * len) {
            const zeta = zetas[i - 1]; // Access pre-computed zetas
            i += 1;
            var j: u32 = start;
            while (j < start + len) : (j += 1) {
                const t = @as(u16, @mod(@as(u32, zeta) * @as(u32, f_hat[j + len]), pd.q));
                f_hat[j + len] = @as(u16, @mod(@as(i32, f_hat[j]) - @as(i32, t) + pd.q, pd.q));
                f_hat[j] = @as(u16, @mod(@as(u32, f_hat[j]) + @as(u32, t), pd.q));
            }
        }
    }
    f.* = f_hat;
}

// Inverse NTT
pub fn nttInverse(comptime pd: params.ParamDetails, f_hat: *RqTq(pd), zetas: []const u16) void {
    var f = f_hat.*;
    var i: u8 = pd.n / 2 - 1;
    var len: u32 = 2;
    while (len <= pd.n / 2) : (len *= 2) {
        var start: u32 = 0;
        while (start < pd.n) : (start += 2 * len) {
            const zeta = zetas[i]; // Access pre-computed zetas
            i -= 1;
            var j: u32 = start;

            while (j < start + len) : (j += 1) {
                const t = f[j];
                f[j] = @as(u16, @mod(@as(u32, t) + @as(u32, f[j + len]), pd.q));
                f[j + len] = @as(u16, @mod(@as(u32, zeta) * @as(u32, @mod(@as(i32, f[j + len]) - @as(i32, t) + pd.q, pd.q)), pd.q));
            }
        }
    }
    const n_inverse = utils.computeNInverse(pd.n, pd.q);
    for (0..pd.n) |j| {
        f[j] = @as(u16, @mod(@as(u32, f[j]) * @as(u32, n_inverse), pd.q));
    }
    f_hat.* = f;
}

// Test cases (using zigtest)
const expectEqual = std.testing.expectEqual;

test "ntt and nttInverse are inverses" {
    const pd = params.Params.kem768.get(); // Example parameters
    var f = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.n); // Fix allocator
    for (f, 0..) |*x, i| {
        x.* = @as(u16, @intCast(@mod(i, pd.q)));
    }
    const f_copy = f; // Changed to const since it's not modified
    ntt(pd, &f);
    nttInverse(pd, &f);
    try expectEqual(f_copy, f);
}

test "ntt and nttInverse work with zero array" {
    const pd = params.Params.kem768.get(); // Example parameters
    var f = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.n); // Fix allocator
    var f_hat = RqTq(pd){};
    ntt(pd, &f);
    nttInverse(pd, &f_hat);
    try std.testing.expectEqual(f, f_hat);
}
