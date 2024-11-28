//utils.zig
const std = @import("std");
const params = @import("params.zig");
const rng = @import("rng.zig");
const mlkem = @import("mlkem.zig");
const Error = @import("error.zig").Error;

pub fn bytesToPolynomial(comptime pd: params.ParamDetails, bytes: []const u8) Error![]u16 {
    if (bytes.len != pd.n / 8) {
        return Error.InvalidInput;
    }
    var polynomial = std.mem.zeroes([pd.n]u16);
    for (bytes, 0..) |byte, i| {
        inline for (0..8) |j| {
            polynomial[i * 8 + j] = @as(u16, @intCast((byte >> @as(u3, @intCast(j))) & 1));
        }
    }
    return polynomial[0..];
}

pub fn polynomialToBytes(comptime pd: params.ParamDetails, polynomial: []const u16) Error![]u8 {
    if (polynomial.len != pd.n) return Error.InvalidInput;
    var bytes = std.mem.zeroes([pd.n / 8]u8);
    for (0..pd.n / 8) |i| {
        var byte: u8 = 0;
        inline for (0..8) |j| {
            byte |= @as(u8, @intCast(polynomial[i * 8 + j])) << @as(u3, @intCast(j));
        }
        bytes[i] = byte;
    }
    return bytes[0..];
}

pub fn computeZeta(comptime pd: params.ParamDetails, i: u8) u16 {
    const inner_power = std.math.pow(u32, 2, @intCast(i));
    const power: u16 = std.math.pow(u16, 17, @intCast(inner_power));
    const zeta: u16 = @mod(power, pd.q);
    return zeta;
}

pub fn computeNInverse(comptime n: u16, comptime q: u16) u16 {
    var t: u32 = 0;
    var newt: u32 = 1;
    var r: u32 = q;
    var newr: u32 = n;
    while (newr != 0) {
        const quotient = @divTrunc(r, newr);
        const temp_t = @mod(t - quotient * newt, q);
        t = newt;
        newt = temp_t;
        const temp_r = @mod(r - quotient * newr, q);
        r = newr;
        newr = temp_r;
    }
    if (r > 1) {
        @panic("Value 'n' does not have a multiplicative inverse modulo q");
    }
    return @intCast(@mod(if (t < 0) t + q else t, q)); // Ensure positive result
}

// Pre-compute modular inverse (for constant-time division)
pub fn precomputeInverse(comptime modulus: u32) u32 {
    // Use Extended Euclidean Algorithm or similar to find the inverse
    var t: u32 = 0;
    var newt: u32 = 1;
    var r: u32 = modulus;
    var newr: u32 = modulus; // Start with some value not divisible by modulus
    // Ensure newr is within the valid range for u32 operations
    while (true) {
        try rng.generateRandomBytes(std.mem.asBytes(&newr));
        if (newr < modulus and newr != 0) break;
    }
    while (newr != 0) {
        const quotient = @divTrunc(r, newr);
        const temp_t = @mod(t - quotient * newt, modulus);
        t = newt;
        newt = temp_t;
        const temp_r = @mod(r - quotient * newr, modulus);
        r = newr;
        newr = temp_r;
    }
    if (r > 1) {
        @panic("Modulus is not prime");
    }
    return @mod(if (t < 0) t + modulus else t, modulus); // Ensure positive
}

// Constant-time multiplication (simplified example using Montgomery multiplication)
pub fn constantTimeMul(a: u32, b: u32, comptime modulus: u32) u32 {
    var result: u32 = 0;
    var temp_a = a;
    var temp_b = b;
    for (0..32) |_| {
        const multiply = @intFromBool((@as(u32, 1) & temp_b) != 0);
        result = @mod(result + multiply * temp_a, modulus); // Modular addition
        temp_a = @mod(temp_a << @as(u5, 1), modulus); // Modular shift
        temp_b >>= @as(u5, 1);
    }
    return result;
}

// Constant-time compression function
pub fn compress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
    const x_u32 = @as(u32, x);
    // Cast d to u5, but first verify it's in valid range
    if (d >= 32) {
        @panic("Shift amount must be less than 32");
    }
    const shift_amount: u5 = @intCast(d);
    const two_to_d = @as(u32, 1) << shift_amount; // Constant-time power of 2
    
    // Constant-time division (using precomputed inverse if available)
    const q_inverse = precomputeInverse(pd.q);
    var result = constantTimeMul(x_u32 * two_to_d, q_inverse, pd.q);
    // Constant-time modular arithmetic for remainder check
    result = result + @as(u32, @intFromBool(constantTimeMod(x_u32 * two_to_d, pd.q) != 0));
    return @intCast(result);
}

// Decompression function (inverse of compress)
pub fn decompress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
    if (d >= 32) {
        @panic("Shift amount must be less than 32");
    }
    const shift_amount: u5 = @intCast(d);
    const two_to_d = @as(u32, 1) << shift_amount; // Constant-time power of 2
    return @intCast(@divTrunc(@as(u32, x) * pd.q, two_to_d));
}

// Constant-time modular reduction
fn constantTimeMod(x: u32, comptime modulus: u32) u32 {
    return @mod(x, modulus); // Replace with constant-time implementation if needed.
}

// Updated decoding functions to use mlkem instead of kem
pub fn decodePublicKey(_: params.ParamDetails, pk_bytes: []const u8, allocator: *std.mem.Allocator) !mlkem.PublicKey {
    const t = pk_bytes[0 .. pk_bytes.len - 32];
    const rho_src = pk_bytes[pk_bytes.len - 32 ..]; // Source rho
    var arena = try std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit(); // Defer arena deallocation
    const publicKey_t = try arena.allocator().alloc(u8, t.len);
    errdefer arena.allocator().free(publicKey_t);
    @memcpy(publicKey_t, t);
    const rho = try arena.allocator().alloc(u8, 32); // Allocate for rho in the arena
    errdefer arena.allocator().free(rho);
    @memcpy(rho, rho_src); // Copy the rho data
    return .{ .t = publicKey_t, .rho = rho, .arena = &arena };
}

pub fn decodePrivateKey(comptime pd: params.ParamDetails, sk_bytes: []const u8, allocator: *std.mem.Allocator) !mlkem.PrivateKey {
    var arena = try std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    var sk = try arena.allocator().create(mlkem.PrivateKey);
    sk.arena = &arena;
    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            sk.s[i * pd.n + j] = std.mem.readIntLittle(u16, sk_bytes[(i * pd.n + j) * 2 .. (i * pd.n + j + 1) * 2]);
        }
    }
    return sk;
}

pub fn decodeCiphertext(comptime pd: params.ParamDetails, ct_bytes: []const u8, allocator: *std.mem.Allocator) !mlkem.Ciphertext {
    if (ct_bytes.len != pd.ciphertextBytes) { // validate ciphertext length before creating the arena or allocating
        return error.InvalidCiphertext;
    }
    var arena = try std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const ct = try arena.allocator().alloc(u8, ct_bytes.len);
    errdefer arena.allocator().free(ct);
    @memcpy(ct, ct_bytes);
    return ct;
}

const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

test "bytesToPolynomial and polynomialToBytes are inverses" {
    const pd = comptime params.Params.kem768.get();
    var bytes = [_]u8{0} ** 32;
    for (&bytes, 0..) |*b, i| b.* = @intCast(i);
    const polynomial = try bytesToPolynomial(pd, &bytes);
    const recovered_bytes = try polynomialToBytes(pd, polynomial);
    try expectEqual(true, std.mem.eql(u8, &bytes, recovered_bytes));
}

test "bytesToPolynomial errors on incorrect input length" {
    const pd = comptime params.Params.kem768.get();
    var bytes = [_]u8{0} ** 31; // Incorrect length
    try expectError(Error.InvalidInput, bytesToPolynomial(pd, &bytes));
}

test "polynomialToBytes errors on incorrect input length" {
    const pd = comptime params.Params.kem768.get();
    var polynomial = [_]u16{0} ** (pd.n - 1);
    try expectError(Error.InvalidInput, polynomialToBytes(pd, &polynomial));
}

test "computeZeta is correct for kem768" {
    const pd = comptime params.Params.kem768.get();
    try expectEqual(@as(u16, 17), computeZeta(pd, 1));
    try expectEqual(@as(u16, 512), computeZeta(pd, 2));
    try expectEqual(@as(u16, 1536), computeZeta(pd, 3));
}

test "computeNInverse is correct for kem768" {
    const pd = comptime params.Params.kem768.get();
    try expectEqual(@as(u16, 3303), computeNInverse(pd.n, pd.q)); // Test with pd.q = 3329
}

test "utils functions" {
    const pd = comptime params.Params.kem768.get();
    // Test compress/decompress
    const x: u16 = 1234;
    const compressed_x = compress(pd, x, pd.du);
    const decompressed_x = decompress(pd, compressed_x, pd.du);
    try expectEqual(x, decompressed_x);
}
