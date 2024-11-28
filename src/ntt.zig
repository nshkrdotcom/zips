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

pub fn allocOrError(allocator: std.mem.Allocator, comptime T: type, size: usize) Error![]T {
    return allocator.alloc(T, size) catch |err| switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
    };
}

// Pre-compute zetas (This should be done only ONCE per parameter set)
pub fn precomputeZetas(comptime pd: params.ParamDetails, allocator: std.mem.Allocator) ![]u16 {
    const zetas = try allocator.alloc(u16, pd.n / 2);
    for (zetas, 0..) |*zeta, i| {
		const zeta_i = @as(u8, @intCast(i + 1));
        zeta.* = utils.computeZeta(pd, zeta_i);  // TODO: check param 2
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
				const t_a: u16 = @intCast(@mod(@as(u32, zeta) * @as(u32, f_hat[j + len]), pd.q));
                const t = @as(u16, t_a);
				const j_a: u16 = @intCast(@mod(@as(i32, f_hat[j]) - @as(i32, t) + pd.q, pd.q));
                f_hat[j + len] = @as(u16, j_a);
				const j_b: u16 = @intCast(@mod(@as(u32, f_hat[j]) + @as(u32, t), pd.q));
                f_hat[j] = @as(u16, j_b);
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
				const j_a: u16 = @intCast(@mod(@as(u32, t) + @as(u32, f[j + len]), pd.q));               
                f[j] = @as(u16, j_a);
				const j_bb: u32 = @intCast(@mod(@as(i32, f[j + len]) - @as(i32, t) + pd.q, pd.q));
				const j_b: u16 = @intCast(@mod(@as(u32, zeta) * @as(u32, j_bb), pd.q));
                f[j + len] = @as(u16, j_b);
            }
        }
    }
    const n_inverse = utils.computeNInverse(pd.n, pd.q);
    for (0..pd.n) |j| {
		const j_a: u16 = @intCast(@mod(@as(u32, f[j]) * @as(u32, n_inverse), pd.q));
        f[j] = @as(u16, j_a);
    }
    f_hat.* = f;
}

// Test cases (using zigtest)
const expectEqual = std.testing.expectEqual;

test "ntt and nttInverse are inverses" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.testing.allocator;
	var f: [pd.n]u16 = undefined;
	for (0..pd.n) |i| {
		f[i] = @intCast(i % pd.q);
	}
    const zetas = try precomputeZetas(pd, gpa);
    defer gpa.free(zetas);
	var f_copy: [pd.n]u16 = undefined;
	@memcpy(&f_copy, &f);
    ntt(pd, &f_copy, zetas);
    nttInverse(pd, &f_copy, zetas);
    try expectEqual(f, f_copy);
}


test "ntt and nttInverse work with zero array" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.testing.allocator;
	var f: [pd.n]u16 = undefined;
	for (0..pd.n) |i| {
		f[i] = 0;
	}
    const zetas = try precomputeZetas(pd, gpa);
    defer gpa.free(zetas);
	var f_copy: [pd.n]u16 = undefined;
	@memcpy(&f_copy, &f);
    ntt(pd, &f_copy, zetas);
    nttInverse(pd, &f_copy, zetas);
    try expectEqual(f, f_copy);
}