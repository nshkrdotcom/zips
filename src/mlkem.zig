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
// mlkem.zig (Revised keygen function)

const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const ntt = @import("ntt.zig");
const Error = @import("error.zig").Error;

// ... (PublicKey, PrivateKey, Ciphertext, KeyPair structs as before)

pub fn keygen(comptime params: params.Params, allocator: mem.Allocator) Error!KeyPair {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // 1. Generate random bytes d and z
    var d: [32]u8 = undefined;
    try rng.generateRandomBytes(&d);
    var z: [32]u8 = undefined;
    try rng.generateRandomBytes(&z);


    const pd = params.get();

    // 2. Generate K-PKE key pair (using the arena)
    const kpkeKeyPair = try kpke.keygen(pd, arena.allocator());

    // 3. Create ML-KEM keys (copying data from the arena using the provided allocator)
    const publicKey = try PublicKey.init(allocator, kpkeKeyPair.public_key.t, kpkeKeyPair.public_key.rho);
    errdefer publicKey.deinit(); // Free public key resources if PrivateKey init fails.

    const privateKey = try PrivateKey.init(allocator, kpkeKeyPair.private_key.s, publicKey.t, H(publicKey.t), z); // Streamlined Private Key initialization
    errdefer privateKey.deinit(); // Free private key resources on error

    return KeyPair{
        .public_key = publicKey,
        .private_key = privateKey,
    };
}

// ML-KEM Encapsulation
// mlkem.zig (Revised encaps function)
const std = @import("std");
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const kpke = @import("kpke.zig");
const Error = @import("error.zig").Error;

// ... (PublicKey, PrivateKey, Ciphertext, EncapsResult structs as before)


pub fn encaps(comptime params: params.Params, pk: PublicKey, allocator: mem.Allocator) Error!EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // 1. Generate random bytes m
    var m: [32]u8 = undefined;
    try rng.generateRandomBytes(&m);
    defer std.crypto.secureZero(u8, &m); // Zero-out m when done

    const pd = params.get();

    // 2. Compute K and r (using SHA3-512)
    var K_r: [64]u8 = undefined;

	// Correctly allocate enough space for the hash input
    const hash_input = try arena.allocator().alloc(u8, m.len + pk.t.len);
    errdefer arena.allocator().free(hash_input);
    @memcpy(hash_input[0..m.len], &m);
    @memcpy(hash_input[m.len..], pk.t);


    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_r, .{});
    const K = K_r[0..32].*;
    const r = K_r[32..].*;

    // 3. Encrypt m using K-PKE (using the arena's allocator)
    const c = try kpke.encrypt(pd, pk, &m, arena.allocator());

    // 4. Create the Ciphertext object, copying data out of the arena
    const ciphertext = try Ciphertext.init(allocator, c.data);  // copies the data into an arena owned by ciphertext itself
    errdefer ciphertext.deinit();

    return EncapsResult{
        .ciphertext = ciphertext,
        .shared_secret = K,
    };
}

// ML-KEM Decapsulation
pub fn decaps(comptime params: params.Params, pk: PublicKey, sk: PrivateKey, ct: Ciphertext, allocator: mem.Allocator) Error!SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const pd = params.get();

    // 1. Decrypt the ciphertext ct under sk to obtain m'
    const m_prime = try kpke.decrypt(pd, sk, ct, arena.allocator()); // Use arena's allocator
    defer std.crypto.secureZero(u8, m_prime); // Securely zero m_prime when no longer needed
    errdefer arena.allocator().free(m_prime);

    // 2. Compute K' from m'  (using H(pk) from the private key)
    var K_prime_r_prime: [64]u8 = undefined;
    
    const hash_input = try arena.allocator().alloc(u8, m_prime.len + sk.h.len);  // Use sk.h directly
    errdefer arena.allocator().free(hash_input);

    @memcpy(hash_input[0..m_prime.len], m_prime);
    @memcpy(hash_input[m_prime.len..], sk.h); // Use sk.h (hash of pk)

    crypto.hash.sha3.Sha3_512.hash(hash_input, &K_prime_r_prime, .{});
    var K_prime = K_prime_r_prime[0..32].*;
    const r_prime = K_prime_r_prime[32..].*;

    // 3. Re-encrypt m' under pk to obtain c' (using the arena allocator)
    var c_prime_struct = try kpke.encrypt(pd, pk, m_prime, arena.allocator());
	const c_prime = c_prime_struct.data;

    defer c_prime_struct.deinit();

    // 4. Compare c and c' in constant time
    const sameCiphertexts = std.mem.eql(u8, ct.data, c_prime); // Constant-time comparison

    // 5. Return K' if c == c', otherwise derive K from r (using J)
    var K: SharedSecret = undefined;
    if (sameCiphertexts) {
        K = K_prime;
    } else {        
        K = J(sk.z, ct.data); // Use sk.z (random value from private key) and ct.data, Use arena.allocator()
    }

    return K ;

}

// Helper function for J (make sure this handles allocation correctly, using the provided or arena allocator)
// mlkem.zig (J helper function implementation)
fn J(z: [32]u8, c: []const u8, allocator: std.mem.Allocator) SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const hash_input = try arena.allocator().alloc(u8, z.len + c.len);
    errdefer arena.allocator().free(hash_input);
    @memcpy(hash_input[0..z.len], &z);
    @memcpy(hash_input[z.len..], c);

    var K: SharedSecret = undefined; // Or [32]u8 if SharedSecret is a type alias for that
    crypto.hash.shake256.Shake256.hash(hash_input, &K, .{}); //  SHAKE256 for variable output
    return K;
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
