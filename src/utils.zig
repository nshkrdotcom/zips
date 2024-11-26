//utils.zig
const std = @import("std");
const params = @import("params.zig");
const rng = @import("rng.zig");
const Error = @import("error.zig").Error;

pub fn bytesToPolynomial(comptime pd: params.ParamDetails, bytes: []const u8) Error![]u16 {
    if (bytes.len != pd.n / 8) {
        return Error.InvalidInput;
    }
    var polynomial = std.mem.zeroes([pd.n]u16);
    for (bytes, 0..) |byte, i| {
        for (0..8) |j| {
            polynomial[i * 8 + j] = @intCast(u16, (byte >> j) & 1);
        }
    }
    return polynomial;
}

pub fn polynomialToBytes(comptime pd: params.ParamDetails, polynomial: []const u16) Error![]u8 {
    if (polynomial.len != pd.n) return Error.InvalidInput;
    var bytes = std.mem.zeroes([pd.n / 8]u8);
    for (0..pd.n / 8) |i| {
        var byte: u8 = 0;
        for (0..8) |j| {
            byte |= @intCast(u8, polynomial[i * 8 + j]) << j;
        }
        bytes[i] = byte;
    }
    return bytes;
}

pub fn computeZeta(comptime pd: params.ParamDetails, i: u8) u16 {
    var zeta: u16 = 17;
    var power: u16 = std.math.pow(u16, 17, @intCast(u16, std.math.pow(u32, 2, @intCast(u32, i))));
    zeta = @mod(power, pd.q);
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
    return @intCast(u16, @mod(if (t < 0) t + q else t, q)); // Ensure positive result
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
        if (newr < modulus and newr !=0) break;
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
    return if (t < 0) t + modulus else t; // Ensure positive
}

// Constant-time multiplication (example using Montgomery multiplication)
// (This is a simplified example. A real-world implementation would use optimized assembly or specialized libraries)
pub fn constantTimeMul(a: u32, b: u32, comptime modulus: u32) u32 {
    _ = modulus;
    var result: u32 = 0;
    var temp_a = a;
    var temp_b = b;
    for (0..32) |_| {
        const multiply = @boolToInt((@as(u32, 1) & temp_b) !=0);
        result = @as(u32, result + multiply * temp_a);
        temp_a <<= @as(u5, 1);
        temp_b >>= @as(u5, 1);
    }
    return result; // No final reduction needed for Montgomery multiplication, in normal implementation
}

// Constant-time compression function (adjust data types as needed)
//fn compress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
//    const x_u32 = @as(u32, x);
//    const two_to_d = std.math.pow(u32, 2, @intCast(u32, d));
//    var result = @as(u32, @divTrunc(x_u32 * two_to_d , pd.q));
//    result = result + @as(u32, @boolToInt(@mod(x_u32 * two_to_d, pd.q) !=0));
//    return @intCast(u16, result);
//}
//fn compress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
//    const x_u32 = @as(u32, x);
//    const two_to_d = @as(u32, 1) << d; // Constant-time power of 2
//    // Replace @divTrunc with a constant-time division implementation. Example using pre-computed inverse:
//    const q_inverse = precomputeInverse(pd.q); // Function to pre-compute inverse (in utils.zig)
//    var result = constantTimeMul(x_u32 * two_to_d, q_inverse); // Constant-time multiplication function
//    result = result + @as(u32, @boolToInt(constantTimeMod(x_u32 * two_to_d, pd.q) !=0)); // constant time mod
//    return @intCast(u16, result);
//}
// Constant-time compression function
pub fn compress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
    const x_u32 = @as(u32, x);
    const two_to_d = @as(u32, 1) << d; // Constant-time power of 2

    // Constant-time division (using precomputed inverse if available)
    const q_inverse = precomputeInverse(pd.q);
    var result = constantTimeMul(x_u32 * two_to_d, q_inverse, pd.q);

    // Constant-time modular arithmetic for remainder check
    result = result + @as(u32, @boolToInt(constantTimeMod(x_u32 * two_to_d, pd.q) != 0));

    return @intCast(u16, result);
}

// Decompression function (inverse of compress)
pub fn decompress(comptime pd: params.ParamDetails, x: u16, d: u8) u16 {
    const two_to_d = @as(u32, 1) << d; // Constant-time power of 2
    return @intCast(u16, @divTrunc(@as(u32, x) * pd.q, two_to_d));
}

// Constant-time modular multiplication (Montgomery multiplication - simplified example)
pub fn constantTimeMul(a: u32, b: u32, comptime modulus: u32) u32 {
    var result: u32 = 0;
    var temp_a = a;
    var temp_b = b;

    for (0..32) |_| {
        const multiply = @boolToInt((@as(u32, 1) & temp_b) != 0);
        result = @as(u32, @mod(result + multiply * temp_a, modulus)); // Modular addition
        temp_a = @mod(temp_a << @as(u5, 1), modulus);            // Modular shift
        temp_b >>= @as(u5, 1);
    }
    return result;
}

// Constant-time modular reduction
fn constantTimeMod(x: u32, comptime modulus: u32) u32 {
    return @mod(x, modulus); // Replace with constant-time implementation if needed.
}

// Pre-compute modular inverse for constant-time division
pub fn precomputeInverse(comptime modulus: u32) u32 {
     var t: u32 = 0;
    var newt: u32 = 1;
    var r: u32 = modulus;
    var newr: u32 = modulus; // Start with some value not divisible by modulus
    // Ensure newr is within the valid range for u32 operations
    while (true) {
        try rng.generateRandomBytes(std.mem.asBytes(&newr));
        if (newr < modulus and newr !=0) break;
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
    return @mod(if (t < 0) t + modulus else t,modulus); // Ensure positive
}

// In utils.zig
pub fn decodePublicKey(comptime pd: params.ParamDetails, hex_string: []const u8) !kem.PublicKey {
    var pk_bytes = try std.fmt.hexToSlice(u8, hex_string);
    // ... (Decode pk_bytes into the components of a PublicKey struct)
    // ... (This will depend on how you've structured your PublicKey)
    const t = pk_bytes[0..pk_bytes.len - 32];
    const rho = pk_bytes[pk_bytes.len - 32..];
    var arena = try std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var publicKey_t = try arena.allocator().alloc(u8, t.len);
    errdefer arena.allocator().free(publicKey_t);
    std.mem.copy(u8, publicKey_t, t);
    return .{ .t = publicKey_t, .rho = rho, .arena = &arena };
}

pub fn decodePrivateKey(comptime pd: params.ParamDetails, hex_string: []const u8) !kem.PrivateKey {
    _ = pd;
    var sk_bytes = try std.fmt.hexToSlice(u8, hex_string);
    var arena = try std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var s = try arena.allocator().alloc(u16, pd.n * pd.k);
    errdefer arena.allocator().free(s);
    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            s[i*pd.n + j] = std.mem.readIntLittle(u16, sk_bytes[(i * pd.n + j)*2..(i*pd.n + j + 1) * 2 ]);
        }
    }
    return kem.PrivateKey{ .s = s, .arena = &arena };
}

pub fn decodeCiphertext(comptime pd: params.ParamDetails, hex_string: []const u8) !kem.Ciphertext {
    _ = pd;
    var ct_bytes = try std.fmt.hexToSlice(u8, hex_string);
    var arena = try std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var ct = try arena.allocator().alloc(u8, ct_bytes.len);
     errdefer arena.allocator().free(ct);
    std.mem.copy(u8, ct, ct_bytes);
    return ct;
}

const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

test "bytesToPolynomial and polynomialToBytes are inverses" {
    const pd = params.Params.kem768.get(); // Example parameter set
    var bytes: [32]u8 = undefined;
    for (bytes, 0..) |*b, i| b.* = @intCast(u8, i);
    const polynomial = try bytesToPolynomial(pd, &bytes);
    const recovered_bytes = try polynomialToBytes(pd, &polynomial);
    try expectEqual(bytes, recovered_bytes);
}

test "bytesToPolynomial errors on incorrect input length" {
    const pd = params.Params.kem768.get(); // Example parameter set
    var bytes: [31]u8 = undefined; // Incorrect length
    try expectError(Error.InvalidInput, bytesToPolynomial(pd, &bytes));

}

test "polynomialToBytes errors on incorrect input length" {
    const pd = params.Params.kem768.get(); // Example parameter set
    var polynomial = [_]u16{0} ** (pd.n-1);
    try expectError(Error.InvalidInput, polynomialToBytes(pd, &polynomial));
}

test "computeZeta is correct for kem768" {
    const pd = params.Params.kem768.get();
    try expectEqual(@as(u16, 17), computeZeta(pd, 1));
    try expectEqual(@as(u16, 512), computeZeta(pd, 2));
    try expectEqual(@as(u16, 1536), computeZeta(pd, 3));
}

test "computeNInverse is correct for kem768" {
    const pd = params.Params.kem768.get();
    try expectEqual(@as(u16, 3303), computeNInverse(pd.n, pd.q)); // Test with pd.q = 3329
}

test "precomputeInverse is correct" {
    // Test with known inverses (for small values)
    try expectEqual(@as(u32, 1), precomputeInverse(3329));
    try expectEqual(@as(u32, 1), constantTimeMul(3329, precomputeInverse(3329),3329));
    try expectEqual(@as(u32, 1), constantTimeMul(1, precomputeInverse(3329),3329));
    try expectEqual(@as(u32, 0), constantTimeMul(0, precomputeInverse(3329),3329));
    try expectEqual(@as(u32, 1), constantTimeMul(10, precomputeInverse(3329) * 10,3329));
}

test "utils functions" {
    const pd = params.Params.kem768.get();
    // ... your existing utils tests
    // Test compress/decompress
    const x: u16 = 1234;
    const compressed_x = compress(pd, x, pd.du);
    const decompressed_x = decompress(pd, compressed_x, pd.du);
	expectEqual(x, decompressed_x);
    // ... add tests for other utility functions
}