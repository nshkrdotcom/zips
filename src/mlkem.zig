const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const Error = @import("error.zig").Error;

// Define ML-KEM key and ciphertext types
pub const PublicKey = kpke.PublicKey;    // Reuse kpke's PublicKey
pub const PrivateKey = kpke.PrivateKey; // Reuse kpke's PrivateKey
pub const Ciphertext = []u8;           // Ciphertext will be a byte array

// Key Generation
pub fn keygen(comptime pd: params.ParamDetails, allocator: *mem.Allocator) Error!{PublicKey, PrivateKey} {
    return try kpke.keygen(pd, allocator);
}

//Be sure to review the exact FO transform requirements in the standard to ensure your implementation is perfectly compliant. Pay close attention to constant-time operations when implementing the comparison of ciphertexts ( c and c' ), as this comparison should not leak timing information. Thorough testing is essential, so continue to expand your test cases with different inputs, parameter sets, and known answer tests (KATs). The current encaps and decaps functions and accompanying test cases are a great starting point, but might need refinement to perfectly match all the details and security considerations of FIPS 203.
// ML-KEM Encapsulation
pub fn encaps(comptime pd: params.ParamDetails, pk: PublicKey, allocator: *mem.Allocator) Error!{Ciphertext, [32]u8} {
    var arena = try std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Generate random bytes m
    var m: [32]u8 = undefined;
    rng.generateRandomBytes(&m) catch return Error.RandomnessFailure;

    // 2. Compute K and r
    var K_r: [64]u8 = undefined;
    var hash_input = try arena_allocator.alloc(u8, 32 + pk.t.len); // Check size
    defer arena_allocator.free(hash_input);
    std.mem.copy(u8, hash_input[0..32], &m);
    crypto.hash.sha3.Sha3_256.hash(pk.t, hash_input[32..], .{}); // Hash public key bytes
    crypto.hash.sha3.Sha3_512.hash(hash_input, K_r, .{});
    const K = K_r[0..32].*;
    const r = K_r[32..].*;

    // 3. Encrypt m using K-PKE
    const c = try kpke.encrypt(pd, pk, m, arena_allocator);

    return .{
        .ciphertext = c,
        .shared_secret = K,
    };
}

// ML-KEM Decapsulation
pub fn decaps(comptime pd: params.ParamDetails, sk: PrivateKey, ct: Ciphertext, allocator: *mem.Allocator) Error![32]u8 {
    var arena = try std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Decrypt the ciphertext ct under sk to obtain m'
    var m_prime = try kpke.decrypt(pd, sk, ct, arena_allocator);

    // 2. Compute K' from m'
    var K_prime_r_prime: [64]u8 = undefined;
    var hash_input = try arena_allocator.alloc(u8, 32 + sk.s.len * @sizeOf(u16));
    defer arena_allocator.free(hash_input);
    std.mem.copy(u8, hash_input[0..32], &m_prime);
        var publicKey = blk: {
        const key_pair = try kpke.keygen(pd, allocator);
        defer kpke.destroyPublicKey(&key_pair.publicKey);
        break :blk key_pair.publicKey;
    };
    crypto.hash.sha3.Sha3_256.hash(publicKey.t, hash_input[32..], .{});
    crypto.hash.sha3.Sha3_512.hash(hash_input, K_prime_r_prime, .{});
    const K_prime = K_prime_r_prime[0..32].*;
    const r_prime = K_prime_r_prime[32..].*;

    // 3. Re-encrypt m' under pk derived from sk to obtain c'
    const c_prime = try kpke.encrypt(pd, publicKey, m_prime, arena_allocator);

    // 4. Compare c and c'
    const sameCiphertexts = std.mem.eql(u8, ct, c_prime);

    // 5. Return K' if c == c', otherwise derive K' from a hash of c
    var K: [32]u8 = undefined;
    if (sameCiphertexts) {
        std.mem.copy(u8, &K, &K_prime);
    } else {
        // ... (Hash c and potentially a seed to produce K)
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

pub fn destroyCiphertext(ct: *Ciphertext) void {
    std.crypto.secureZero(u8, ct.*);
    ct.arena.deinit();
}

const expectError = std.testing.expectError;

test "mlkem keygen generates keys" {
    const pd = params.Params.kem768.get(); // Example
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const keypair = try keygen(pd, allocator);
    defer destroyPrivateKey(&keypair.privateKey);
    defer destroyPublicKey(&keypair.publicKey);
    // Basic test: Just check if the keys were generated without errors. Add more detailed tests later.
}

test "mlkem encaps and decaps work" {
    const pd = params.Params.kem768.get(); // Example
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const keypair = try keygen(pd, allocator);
    const encaps_result = try encaps(pd,keypair.publicKey, allocator);
    defer destroyCiphertext(&encaps_result.ciphertext);
    const ss = try decaps(pd, keypair.privateKey, encaps_result.ciphertext, allocator);
    try std.testing.expectEqualSlices(u8, &encaps_result.shared_secret, &ss);
    destroyPrivateKey(&keypair.privateKey);
    destroyPublicKey(&keypair.publicKey);
}
