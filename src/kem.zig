const std = @import("std");
const mlkem = @import("mlkem.zig");
const params = @import("params.zig");
const rng = @import("rng.zig");
const error = @import("error.zig");

// Error Handling
pub const Error = error.Error;

// Parameter Sets
pub const Params = params.Params;

pub fn getParams(param_set: Params) params.ParamDetails {
    return params.getParams(param_set);
}

// Key Types
pub const PublicKey = mlkem.PublicKey;
pub const PrivateKey = mlkem.PrivateKey;
pub const Ciphertext = mlkem.Ciphertext;
pub const SharedSecret = [32]u8;

// Key Generation
pub fn keygen(params: Params, allocator: *mem.Allocator) Error!{PublicKey, PrivateKey} {
    return mlkem.keygen(params, allocator);
}

// Encapsulation
pub fn encaps(pk: PublicKey, params: Params, allocator: *mem.Allocator) Error!{Ciphertext, SharedSecret} {
    return mlkem.encaps(pk, params, allocator);
}

// Decapsulation
pub fn decaps(sk: PrivateKey, ct: Ciphertext, params: Params) Error!SharedSecret {
    return mlkem.decaps(sk, ct, params);
}

// Secure Key Destruction
pub fn destroyPrivateKey(sk: *PrivateKey) void {
    mlkem.destroyPrivateKey(sk);
}

pub fn destroyPublicKey(pk: *PublicKey) void {
    mlkem.destroyPublicKey(pk);
}

pub fn destroyCiphertext(ct: *Ciphertext) void {
    mlkem.destroyCiphertext(ct);
}


// Authenticated Encryption (AEAD) - Example using AES-GCM
pub fn encrypt(
    key: SharedSecret,
    nonce: [12]u8,
    plaintext: []const u8,
    additional_data: ?[]const u8,
    allocator: *mem.Allocator,
) Error![]u8 {
    var ciphertext = try allocator.alloc(u8, plaintext.len + 16); // Allocate for tag
    const gcm = std.crypto.aead.aes_gcm.Aes256Gcm; // Or another AEAD from std.crypto
    gcm.encrypt(ciphertext, plaintext, additional_data, nonce, key, {}); // Using std.crypto.aead
    return ciphertext;
}

// Authenticated Decryption (AEAD)
pub fn decrypt(
    key: SharedSecret,
    nonce: [12]u8,
    ciphertext: []const u8,
    additional_data: ?[]const u8,
) Error![]u8 {

    if (ciphertext.len < 16) return error.InvalidCiphertext; // Check for minimum length


    var plaintext = try allocator.alloc(u8, ciphertext.len - 16);
    const gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    try gcm.decrypt(plaintext, ciphertext, additional_data, nonce, key, {});
    return plaintext;
}



// Random Number Generation (using std.crypto.random)
pub fn generateRandomBytes(buffer: []u8) !void {
    std.crypto.random(buffer);
}


// --- Optional additions for a more complete interface: ---

// Key Derivation Function (KDF) - If needed (std.crypto.kdf might suffice)
// ...

// Test Vectors (KATs) access - for testing and verification
// ...