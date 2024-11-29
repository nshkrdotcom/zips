//mlkem.zig
const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const Error = @import("error.zig").Error;

// Define ML-KEM key and ciphertext types
pub const PublicKey = kpke.PublicKey;
pub const PrivateKey = kpke.PrivateKey;
pub const Ciphertext = kpke.Ciphertext;

const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,
};

const EncapsResult = struct {
    ciphertext: Ciphertext,
    shared_secret: [32]u8, // Use a fixed-size byte array instead of the undefined SharedSecret
};

inline fn secureZero(comptime T: type, slice: []volatile T) void {
    for (slice) |*elem| {
        elem.* = 0;
        asm volatile ("" ::: "memory"); // Prevent optimizations
    }
}

pub fn keygen(comptime pd: params.ParamDetails, allocator: std.mem.Allocator, seed_d: [32]u8, seed_z: [32]u8) !KeyPair {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const kpkeKeyPair = try kpke.keygen(pd, arena.allocator()); // Keygen uses its own arena

    const publicKey = PublicKey{
        .t = try allocator.dupe(u8, kpkeKeyPair.publicKey.t),
        .rho = kpkeKeyPair.publicKey.rho,
    };
    errdefer allocator.free(publicKey.t); // Free t if allocation fails

    const s_copy = try allocator.alloc([]const u16, pd.k);
    errdefer allocator.free(s_copy);

    for (0..pd.k) |i| {
        s_copy[i] = try allocator.dupe(u16, kpkeKeyPair.privateKey.s[i]);
        errdefer allocator.free(s_copy[i]);
    }

    const privateKey = PrivateKey{
        .s = s_copy,
        .t = try allocator.dupe(u8, publicKey.t), // Duplicate t for the private key
        .h = H(publicKey.t),                  // Compute h = H(t)
        .z = seed_z,
    };
    errdefer {
        allocator.free(privateKey.t);
        for (privateKey.s) |slice| {
			allocator.free(slice);
		}
        allocator.free(privateKey.s);
    }


    return KeyPair{
        .publicKey = publicKey,
        .privateKey = privateKey,
    };
}

pub fn encaps(comptime params: params.Params, pk: PublicKey, allocator: std.mem.Allocator) !EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var m: [32]u8 = undefined;
    try rng.generateRandomBytes(&m);
    defer std.crypto.secureZero(u8, &m); // Zero m after use

    const result = try encaps_internal(params, pk, m, arena.allocator());
    const ciphertext_copy = try allocator.dupe(u8, result.ciphertext.data); // Copy outside arena
    const ciphertext = Ciphertext { .data = ciphertext_copy}; // ciphertext owns the copied slice
    return EncapsResult{ .ciphertext = ciphertext, .shared_secret = result.shared_secret };
}


pub fn decaps(comptime params: params.Params, pk: PublicKey, sk: PrivateKey, ct: Ciphertext, allocator: std.mem.Allocator) !SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    return try decaps_internal(params, pk, sk, ct, arena.allocator());
}

fn encaps_internal(comptime params: params.Params, pk: PublicKey, m: [32]u8, allocator: std.mem.Allocator) !EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const pd = params.get();

    const hash_input = try arena.allocator().alloc(u8, m.len + pk.t.len);
    errdefer arena.allocator().free(hash_input);

    @memcpy(hash_input[0..m.len], &m);
    @memcpy(hash_input[m.len..], pk.t);

    var K_r: [64]u8 = undefined;
    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_r, .{});
    const K = K_r[0..32].*;
    var r = K_r[32..].*;

    const ciphertext = try kpke.encrypt(pd, pk, &m, arena.allocator()); // Use arena's allocator

    std.crypto.secureZero(u8, &r); // Zero out r
    std.crypto.secureZero(u8, &m); // Zero out m

    // Ciphertext is already a copy returned by kpke.encrypt, so we don't need to make another copy
    return EncapsResult{
        .ciphertext = ciphertext,
        .shared_secret = K,
    };
}

fn decaps_internal(comptime params: params.Params, pk: PublicKey, sk: PrivateKey, ct: Ciphertext, allocator: std.mem.Allocator) !SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const pd = params.get();

    const m_prime = try kpke.decrypt(pd, sk, ct, arena.allocator()); // Use arena allocator
    defer std.crypto.secureZero(u8, m_prime);  // Securely zero m_prime *after* decryption but *before* return or further processing

    const hash_input = try arena.allocator().alloc(u8, m_prime.len + sk.h.len);
    errdefer arena.allocator().free(hash_input);
    @memcpy(hash_input[0..m_prime.len], m_prime);
    @memcpy(hash_input[m_prime.len..], &sk.h);

    var K_prime_r_prime: [64]u8 = undefined;
    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_prime_r_prime, .{});
    var K_prime = K_prime_r_prime[0..32].*;
    const r_prime = K_prime_r_prime[32..].*;

    const c_prime_struct = try kpke.encrypt(pd, pk, m_prime, arena.allocator());
    const c_prime = c_prime_struct.data; //Access data directly since c_prime is allocated inside the arena


    const sameCiphertexts = std.mem.eql(u8, ct.data, c_prime);

    var K: SharedSecret = undefined;
    if (sameCiphertexts) {
        K = K_prime;
        std.crypto.secureZero(u8, &r_prime); // Zero out r_prime if not used for K
    } else {
        K = J(sk.z, ct.data, arena.allocator()); // Use arena's allocator
        std.crypto.secureZero(u8, &K_prime); // Zero out K_prime if not used for K
        std.crypto.secureZero(u8, &r_prime);      // Zero out r_prime
    }
	std.crypto.secureZero(u8, m_prime);
    arena.allocator().free(m_prime);

    return K;
}

// J helper function (using arena allocator)
fn J(z: [32]u8, c: []const u8, allocator: std.mem.Allocator) SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const hash_input = try arena.allocator().alloc(u8, z.len + c.len);
    errdefer arena.allocator().free(hash_input); // Free on error

    @memcpy(hash_input[0..z.len], &z);
    @memcpy(hash_input[z.len..], c);

    var K: SharedSecret = undefined;
    crypto.hash.shake256.Shake256.hash(hash_input, &K, .{});  // SHAKE256 for variable output

    return K;
}

// H helper function (no allocation, no allocator needed)
fn H(data: []const u8) [32]u8 {
    var h: [32]u8 = undefined;
    crypto.hash.sha3.Sha3_256.hash(data, &h, .{}); // SHA3-256
    return h;
}

pub fn destroyCiphertext(ct: []u8) void {
    secureZero(u8, ct);
}

const expectError = std.testing.expectError;

test "mlkem keygen generates keys" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var keypair = try keygen(pd, allocator);
}

test "mlkem encaps and decaps work" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var keypair = try keygen(pd, allocator);
    var encaps_result = try encaps(pd, keypair.public_key, allocator);
    defer destroyCiphertext(encaps_result.ciphertext);
    const ss = try decaps(pd, keypair.public_key, keypair.private_key, encaps_result.ciphertext, allocator);
    try std.testing.expectEqualSlices(u8, &encaps_result.shared_secret, &ss);
}
