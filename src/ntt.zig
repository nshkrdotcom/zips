const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const utils = @import("utils.zig");
const Error = @import("error.zig").Error;

// Define the type for elements in Rq and Tq (using ParamDetails)
pub fn RqTq(comptime pd: params.ParamDetails) type {
    return [pd.n]u16;
}

// Forward NTT
pub fn ntt(comptime pd: params.ParamDetails, f: *RqTq(pd)) void {
    var f_hat = f.*; // make a copy, operate in-place on f_hat
    // Pre-compute zetas (only needs to be done once per parameter set)
    var zetas: [pd.n / 2]u16 = undefined;
    for (zetas, 0..) |*zeta, i| {
        zeta.* = utils.computeZeta(pd, @intCast(u8, i + 1));
    }
    var i: u8 = 1;
    for (var len: u32 = pd.n / 2; len >= 2; len /= 2) {
        for (var start: u32 = 0; start < pd.n; start += 2 * len) {
            const zeta = zetas[i - 1];
            i += 1;
            var j: u32 = start;
            while (j < start + len) : (j += 1) {
               const t = @as(u16, @mod(@as(u32, zeta) * @as(u32, f_hat[j + len]), pd.q));
               f_hat[j + len] = @as(u16, @mod(@as(i32, f_hat[j]) - @as(i32, t) + pd.q, pd.q)); // Ensure positive result
               f_hat[j] = @as(u16, @mod(@as(u32, f_hat[j]) + @as(u32,t), pd.q));
            }
        }
    }
    f.* = f_hat; // copy calculated values back to f
}

// Inverse NTT
pub fn nttInverse(comptime pd: params.ParamDetails, f_hat: *RqTq(pd)) void {
    var f = f_hat.*;
     // Pre-compute zetas (only needs to be done once per parameter set)
    var zetas: [pd.n / 2]u16 = undefined;
    for (zetas, 0..) |*zeta, i| {
        zeta.* = utils.computeZeta(pd, @intCast(u8, i + 1));

    }
    var i: u8 = pd.n/2 - 1;
    for (var len: u32 = 2; len <= pd.n / 2; len *= 2) {
        for (var start: u32 = 0; start < pd.n; start += 2 * len) {
            const zeta = zetas[i];
            i -= 1;
            var j: u32 = start;
            while (j < start + len) : (j += 1) {
                const t = f[j];
                f[j] = @as(u16, @mod(@as(u32, t) + @as(u32, f[j + len]), pd.q));
				// f[j + len] = @as(u16, @mod(@as(u32, zeta) * @as(u32,f[j + len] - t), pd.q));
                f[j + len] = @as(u16, @mod(@as(u32, zeta) * @as(u32, @mod(@as(i32,f[j + len]) - @as(i32,t) + pd.q, pd.q)), pd.q));
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
    var f = RqTq(pd){};
    for (f, 0..) |*x, i| x.* = @intCast(u16, i % pd.q);

    var f_copy = f; // keep a copy to compare after nttInverse

    ntt(pd, &f);
    nttInverse(pd, &f);


    try expectEqual(f_copy, f);

}

test "ntt and nttInverse work with zero array" {
    const pd = params.Params.kem768.get(); // Example parameters
    var f = RqTq(pd){};
    var f_hat = RqTq(pd){};
    ntt(pd, &f);
    nttInverse(pd, &f_hat);


    try std.testing.expectEqual(f, f_hat);

}
// Add more test cases for different inputs and parameter sets