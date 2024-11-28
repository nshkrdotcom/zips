//mlkem.zig
const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const Error = @import("error.zig").Error;
const mem = std.mem;

// Define ML-KEM key and ciphertext types
pub const PublicKey = kpke.PublicKey; // Reuse kpke's PublicKey
pub const PrivateKey = kpke.PrivateKey; // Reuse kpke's PrivateKey
pub const Ciphertext = []u8; // Ciphertext will be a byte array

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

// Key Generation
pub fn keygen(comptime pd: params.ParamDetails, allocator: mem.Allocator) Error!KeyPair {
    const key_pair = try kpke.keygen(pd, allocator);
    return .{ .public_key = key_pair[0], .private_key = key_pair[1] };
    //return .{ .public_key = key_pair.publicKey, .private_key = key_pair.privateKey };
}

// ML-KEM Encapsulation
pub fn encaps(comptime pd: params.ParamDetails, pk: PublicKey, allocator: mem.Allocator) Error!EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator) catch return Error.AllocationFailure;
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Generate random bytes m
    var m: [32]u8 = undefined;
    rng.generateRandomBytes(&m) catch return Error.RandomnessFailure;
    defer secureZero(u8, &m); // Securely zero out m after use

    // 2. Compute K and r (using SHAKE256 as specified in FIPS 203)
    var K_r: [64]u8 = undefined;
    const hash_input_size = 32 + pk.t.len;
    if (hash_input_size > 50000) return error.InvalidInput; // prevent massive stack allocations.
    var hash_input = try arena_allocator.alloc(u8, hash_input_size);
    defer arena_allocator.free(hash_input);
    errdefer secureZero(u8, hash_input);
    std.mem.copy(u8, hash_input, &m);
    //std.mem.copy(u8, hash_input[0..m_prime.len], m_prime); // m_prime is already a slice
    std.mem.copy(u8, hash_input[32..], pk.t);
    crypto.hash.sha3.Sha3_512.hash(hash_input, K_r, .{}) catch return Error.RandomnessFailure;
    const K = K_r[0..32].*;
    _ = K_r[32..]; // Explicitly mark r as unused to suppress unused variable warning

    // 3. Encrypt m using K-PKE
    const c = try kpke.encrypt(pd, pk, m, arena_allocator);
    defer arena_allocator.free(c);
    const ciphertext = try arena_allocator.alloc(u8, c.len);
    errdefer arena_allocator.free(ciphertext);
    std.mem.copy(u8, ciphertext, c);
    return .{
        .ciphertext = ciphertext,
        .shared_secret = K,
    };
}

// ML-KEM Decapsulation
pub fn decaps(comptime pd: params.ParamDetails, sk: PrivateKey, ct: Ciphertext, allocator: mem.Allocator) Error![32]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator) catch return Error.AllocationFailure;
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Decrypt the ciphertext ct under sk to obtain m'
    const m_prime = try kpke.decrypt(pd, sk, ct, &arena_allocator);
    defer {
        secureZero(u8, m_prime);
        arena_allocator.free(m_prime);
    }

    // 2. Compute K' from m'
    var K_prime_r_prime: [64]u8 = undefined;
    const hash_input_size = 32 + sk.s.len * @sizeOf(u16);
    if (hash_input_size > 50000) return error.InvalidInput; // prevent massive stack allocations.
    var hash_input = try arena_allocator.alloc(u8, hash_input_size);
    defer arena_allocator.free(hash_input);
    errdefer secureZero(u8, hash_input);
    std.mem.copy(u8, hash_input[0..32], m_prime); // Fix std.mem.copy usage
    const publicKey = blk: {
        const key_pair = try kpke.keygen(pd, allocator);
        defer kpke.destroyPublicKey(&key_pair.publicKey);
        break :blk key_pair.publicKey;
    };
    crypto.hash.sha3.Sha3_256.hash(publicKey.t, hash_input[32..], .{}) catch return Error.RandomnessFailure;
    crypto.hash.sha3.Sha3_512.hash(hash_input, K_prime_r_prime, .{}) catch return Error.RandomnessFailure;
    const K_prime = K_prime_r_prime[0..32].*;
    _ = K_prime_r_prime[32..];

    // 3. Re-encrypt m' under pk derived from sk to obtain c'
    const c_prime = try kpke.encrypt(pd, publicKey, m_prime, arena_allocator);
    defer arena_allocator.free(c_prime);

    // 4. Compare c and c' (constant-time comparison is crucial here)
    const sameCiphertexts = std.mem.eql(u8, ct, c_prime);

    // 5. Return K' if c == c', otherwise derive K' from a hash of c
    var K: [32]u8 = undefined;
    if (sameCiphertexts) {
        std.mem.copy(u8, &K, &K_prime);
    } else {
        try crypto.random(&K);
    }
    return K;
}

pub fn destroyPrivateKey(sk: *PrivateKey) void {
    kpke.destroyPrivateKey(sk);
}

pub fn destroyPublicKey(pk: *PublicKey) void {
    kpke.destroyPublicKey(pk);
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
    defer destroyPrivateKey(&keypair.private_key);
    defer destroyPublicKey(&keypair.public_key);
}

test "mlkem encaps and decaps work" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var keypair = try keygen(pd, allocator);
    var encaps_result = try encaps(pd, keypair.public_key, allocator);
    defer destroyCiphertext(encaps_result.ciphertext);
    const ss = try decaps(pd, keypair.private_key, encaps_result.ciphertext, allocator);
    try std.testing.expectEqualSlices(u8, &encaps_result.shared_secret, &ss);
    destroyPrivateKey(&keypair.private_key);
    destroyPublicKey(&keypair.public_key);
}
