//mlkem.zig
const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const ntt = @import("ntt.zig");
const Error = @import("error.zig").Error;
const mem = std.mem;

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

// Key Generation
pub fn keygen(comptime pd: params.ParamDetails, allocator: mem.Allocator) Error!KeyPair {
    const key_pair = try kpke.keygen(pd, allocator);
    return KeyPair{
        .public_key = key_pair.publicKey,
        .private_key = key_pair.privateKey,
    };
}

// ML-KEM Encapsulation
pub fn encaps(comptime pd: params.ParamDetails, pk: PublicKey, allocator: mem.Allocator) Error!EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Generate random bytes m
    var m: [32]u8 = undefined;
    rng.generateRandomBytes(&m) catch return Error.RandomnessFailure;
    defer secureZero(u8, &m);

    // 2. Compute K and r (using SHA3-512)
    var K_r: [64]u8 = undefined;
    const hash_input_size = 32 + pk.t.len;
    if (hash_input_size > 50000) return error.InvalidInput;
    const hash_input = arena_allocator.alloc(u8, hash_input_size) catch |err| {
        std.debug.print("Allocation failed: {}\n", .{err}); // Or other error handling
        return Error.AllocationFailure; // Or return the error, etc.
    };
    defer arena_allocator.free(hash_input);
    errdefer secureZero(u8, hash_input);
    @memcpy(hash_input, &m);
    @memcpy(hash_input[32..], pk.t);
    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_r, .{});
    const K = K_r[0..32].*;

	const zetas = try ntt.precomputeZetas(pd, arena_allocator);
	errdefer arena_allocator.free(zetas);

    // 3. Encrypt m using K-PKE
    const c = try kpke.encrypt(pd, pk, &m, arena_allocator); // Pass arena_allocator
    //defer arena_allocator.free(c);
	
	const ciphertext = try arena_allocator.dupe(u8, c); // Copy ciphertext before freeing c
	defer arena_allocator.free(ciphertext);
	arena_allocator.free(c);
	
	
    //const ciphertext = try arena_allocator.alloc(u8, c.len);
    defer arena_allocator.free(ciphertext);
    @memcpy(ciphertext, c);
    return EncapsResult{
        .ciphertext = ciphertext,
        .shared_secret = K,
    };
}

// ML-KEM Decapsulation
pub fn decaps(comptime pd: params.ParamDetails, pk: PublicKey, sk: PrivateKey, ct: Ciphertext, allocator: mem.Allocator) Error![32]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Decrypt the ciphertext ct under sk to obtain m'
    const m_prime = try kpke.decrypt(pd, sk, ct, &arena_allocator, &arena);
    defer {
        secureZero(u8, m_prime);
        arena_allocator.free(m_prime);
    }
	
	const zetas = try ntt.precomputeZetas(pd, arena_allocator);
	defer arena_allocator.free(zetas);

    // 2. Compute K' from m'
    var K_prime_r_prime: [64]u8 = undefined;
    const hash_input_size = 32 + sk.s.len * @sizeOf(u16);
    if (hash_input_size > 50000) return error.InvalidInput;
    const hash_input = arena_allocator.alloc(u8, hash_input_size) catch |err| {
        std.debug.print("Hash input allocation failed: {}\n", .{err});
        return Error.AllocationFailure;
    };
    defer arena_allocator.free(hash_input);
    errdefer secureZero(u8, hash_input);
    @memcpy(hash_input[0..32], m_prime);
    const publicKey = pk;
    var hash_output: [32]u8 = undefined; // Create a separate output array
    crypto.hash.sha3.Sha3_256.hash(publicKey.t, &hash_output, .{});
    //@memcpy(hash_input[32..], &hash_output); // Copy to hash_input if necessary
    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_prime_r_prime, .{}); // Fix: &K_prime_r_prime
    const K_prime = K_prime_r_prime[0..32].*;

    // 3. Re-encrypt m' under pk derived from sk to obtain c'
    const c_prime = try kpke.encrypt(pd, publicKey, m_prime, arena_allocator);
    defer arena_allocator.free(c_prime);

    // 4. Compare c and c' (constant-time comparison is crucial here)
    const sameCiphertexts = std.mem.eql(u8, ct, c_prime);

    // 5. Return K' if c == c', otherwise derive K' from a hash of c (or other appropriate action)
    var K: [32]u8 = undefined;
    if (sameCiphertexts) {
        @memcpy(&K, &K_prime);
    } else {
        crypto.random.bytes(&K);
    }
    return K;
}

//pub fn destroyPrivateKey(sk: *PrivateKey) void {
//    kpke.destroyPrivateKey(sk);
//}

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
    //defer destroyPrivateKey(&keypair.private_key);
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
    const ss = try decaps(pd, keypair.public_key, keypair.private_key, encaps_result.ciphertext, allocator);
    try std.testing.expectEqualSlices(u8, &encaps_result.shared_secret, &ss);
    //destroyPrivateKey(&keypair.private_key);
    destroyPublicKey(&keypair.public_key);
}
