//kern.zig
const std = @import("std");
const mlkem = @import("mlkem.zig");
const paramsModule = @import("params.zig");
const rng = @import("rng.zig");

const Error = @import("error.zig").Error;

const KeyPair = struct {
    public_key: PublicKey,
    private_key: PrivateKey,
};

const EncapsResult = struct {
    ciphertext: Ciphertext,
    shared_secret: SharedSecret,
};

// Parameter Sets
pub const Params = paramsModule.Params;

pub fn getParams(param_set: Params) paramsModule.ParamDetails {
    return paramsModule.getParams(param_set);
}

// Key Types
pub const PublicKey = mlkem.PublicKey;
pub const PrivateKey = mlkem.PrivateKey;
pub const Ciphertext = []u8;  // Ciphertext is a byte slice
pub const SharedSecret = [32]u8;

// Key Generation
pub fn keygen(comptime param_set: Params, allocator: *std.mem.Allocator) Error!KeyPair {
    return try mlkem.keygen(param_set, allocator);
}

// Encapsulation
pub fn encaps(comptime param_set: Params, pk: PublicKey, allocator: *std.mem.Allocator) Error!EncapsResult {
    return try mlkem.encaps(param_set, pk, allocator);
}

// Decapsulation
pub fn decaps(comptime param_set: Params, sk: PrivateKey, ct: Ciphertext, allocator: *std.mem.Allocator) Error!SharedSecret {
    return try mlkem.decaps(param_set, sk, ct, allocator);
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
pub fn aeadEncrypt(
    key: SharedSecret,
    nonce: [12]u8,
    plaintext: []const u8,
    additional_data: ?[]const u8,
    allocator: *std.mem.Allocator,
) Error![]u8 {
    var ciphertext = try allocator.alloc(u8, plaintext.len + 16); // Allocate for tag
    var tag: [16]u8 = undefined;
    const gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    gcm.encrypt(
        ciphertext[0..plaintext.len], 
        &tag, 
        plaintext, 
        additional_data orelse &[_]u8{}, 
        nonce, 
        key
    );
    // Append tag to ciphertext
    @memcpy(ciphertext[plaintext.len..], &tag);
    return ciphertext;
}

// Authenticated Decryption (AEAD)
//pub fn aeadDecrypt(
//    key: SharedSecret,
//    nonce: [12]u8,
//    ciphertext: []const u8,
//    additional_data: ?[]const u8,
//) Error![]u8 {
//    if (ciphertext.len < 16) return error.InvalidCiphertext; // Check for minimum length
//
//    const allocator = std.heap.page_allocator; // Use const allocator
//    const plaintext = try allocator.alloc(u8, ciphertext.len - 16);
//    const gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
//    try gcm.decrypt(plaintext, ciphertext, additional_data, nonce, key, {});
//    return plaintext;
//}
pub fn aeadDecrypt(
    key: SharedSecret,
    nonce: [12]u8,
    ciphertext: []const u8,
    additional_data: ?[]const u8,
    allocator: *std.mem.Allocator, // Add allocator parameter
) Error![]u8 {
    if (ciphertext.len < 16) return error.InvalidCiphertext;
    const plaintext_len = ciphertext.len - 16;
    var plaintext = try allocator.alloc(u8, plaintext_len);
    errdefer allocator.free(plaintext);
    const tag = ciphertext[plaintext_len..]; // Extract tag
	
    const gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    gcm.decrypt(
		plaintext[0..ciphertext.len], 
		ciphertext, 
		tag, 
		additional_data orelse &[_]u8{}, 
		nonce, 
		key
	);
	//) catch |err| {
    //    switch(err) {
    //        error.AuthenticationFailed => {
    //            allocator.free(plaintext); // Free plaintext on auth failure before returning to prevent leak
    //            return Error.DecryptionFailure;
    //        },
    //        else => |e| return e, // consider adding additional checks here and return other possible errors from your Error set
    //    }
    //};
    return plaintext;
}

// Random Number Generation (using std.crypto.random)
pub fn generateRandomBytes(buffer: []u8) !void {
    std.crypto.random(buffer);
}
 
 
 
// --- Optional additions for a more complete interface: ---
// Key Derivation Function (KDF) - If needed (std.crypto.kdf might suffice)
// ...

 

// TODO:
//https://github.com/post-quantum-cryptography/KAT/*

//Thorough Testing:

//mlkem_test.zig: Expand the test cases in mlkem_test.zig. This is the most crucial aspect at this stage.

//Known Answer Tests (KATs): The most important tests are the KATs. Obtain the official NIST KATs for FIPS 203 and create test cases that verify your mlkem.keygen, mlkem.encaps, and mlkem.decaps functions against those test vectors. This is essential for validating compliance with the standard.

//Create a test_vectors.zig module to store these test vectors. Write comprehensive test functions in mlkem_test.zig, kpke_test.zig and potentially other modules to verify your implementation against these KATs. Ensure that you test all parameter sets (512, 768, 1024). If your implementation doesn't pass the KATs, carefully review the FIPS 203 specification and debug your code until it matches the expected output. This is the most critical step in validating your implementation. Example of a KAT test in mlkem_test.zig:
 
// Example test function (you'll need to implement or remove/modify as needed)
//test "ML-KEM KAT - KEM-768" {
//    const pd = Params.kem768.get();
//    const kat = test_vectors.kem768_kats[0]; // Example: Accessing the first KAT from test_vectors.zig

    // Note: You'll need to implement or import these decode functions
    // var pk = try decodePublicKey(pd, kat.pk);
    // var sk = try decodePrivateKey(pd, kat.sk);
    // var ct = try decodeCiphertext(pd, kat.ct);
    // const ss = try mlkem.decaps(pd, sk, ct, allocator);
    // try std.testing.expectEqualSlices(u8, kat.ss, &ss);
//}
 
 
 
//Edge Cases and Invalid Inputs: Test your library with invalid inputs (e.g., incorrect ciphertext length, corrupted public key) to ensure it handles errors correctly and doesn't crash or exhibit undefined behavior.

//Edge Cases: Test with edge cases and invalid inputs (e.g., incorrect ciphertext lengths, invalid public keys) to ensure robust error handling.

//Fuzz Testing: Use a fuzzing tool like libFuzzer if possible.


//Parameter Sets: Test with all three parameter sets (ML-KEM-512, ML-KEM-768, ML-KEM-1024) to confirm that your implementation works correctly across all configurations.

//Fuzzing: If possible, use a fuzzing tool (e.g., libFuzzer) to test your library with random inputs. Fuzzing can often uncover unexpected edge cases and potential vulnerabilities.

//kpke_test.zig: Ensure that the tests in kpke_test.zig are comprehensive and cover edge cases. This is important because mlkem relies on kpke.

//Other modules: Review and update the tests in other modules (ntt, cbd, utils) as needed to ensure everything works correctly.

//Benchmarking: Create benchmarks to measure the performance of your ML-KEM implementation. This will help you identify potential areas for optimization. Zig's std.time module can be used for benchmarking.

// Benchmark example
test "benchmark mlkem keygen" {
    const pd = Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var timer = try std.time.Timer.start();

    var i: usize = 0;
    while (i < 1000) : (i += 1) { // Benchmark over 1000 iterations
        const keypair = try keygen(pd, allocator);
        destroyPrivateKey(&keypair.private_key);
        destroyPublicKey(&keypair.public_key);
    }

    const elapsed = timer.read();
    std.debug.print("Average keygen time: {}ns\n", .{elapsed / 1000});
}


//Benchmarking: Create benchmarks to measure the performance of keygen, encaps, and decaps for all parameter sets. This data is essential for evaluating the efficiency of your implementation and identifying potential bottlenecks.

//Documentation:

//kem.zig Docstrings: Add comprehensive docstrings to the public functions in kem.zig. Explain the purpose of each function, its parameters, return values, and any potential error conditions. Use Zig's built-in documentation generator to create documentation from these docstrings.  Explain parameters, return values, error conditions, and usage examples

//README.md: Update the README.md file with complete instructions for building, testing, and using your library. Include example code demonstrating the key ML-KEM operations. Add a section on how to update the test dependency hash as you did before.

//Code Comments: Add clear and concise comments to your code to explain complex logic or non-obvious implementation details.

//Code Review and Refinement: Review your code for potential improvements:

//Error Handling: Ensure consistent and informative error handling throughout the library.

//Memory Management: Double-check that all allocated memory is properly freed and that sensitive data is securely zeroed out. Use arena allocators wherever possible.

//Constant-Time Operations: Review all operations involving secret data to ensure they have constant-time execution to prevent timing side-channel attacks. Use specialized constant-time arithmetic libraries or assembly implementations if needed for high-security contexts.

//Code Style and Clarity: Apply consistent code formatting and improve variable names or function names to enhance readability.

//Security Audit (Highly Recommended): If possible, have a qualified security expert perform a security audit of your code. This is especially important for cryptographic libraries, where even minor vulnerabilities can have significant security implications.
