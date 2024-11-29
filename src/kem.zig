//kern.zig
const std = @import("std");
const mlkem = @import("mlkem.zig");
const kpke = @import("kpke.zig");
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
pub const ParamDetails = paramsModule.ParamDetails;

pub fn getParams(param_set: Params) paramsModule.ParamDetails {
    return paramsModule.getParams(param_set);
}

// Key Types (using simplified structures from kpke.zig)
pub const PublicKey = kpke.PublicKey;    // []u8
pub const PrivateKey = kpke.PrivateKey; // struct
pub const Ciphertext = kpke.Ciphertext;  // []u8
pub const SharedSecret = [32]u8;

pub fn keygen(comptime params: Params, allocator: std.mem.Allocator) !KeyPair {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var d: [32]u8 = undefined;
    var z: [32]u8 = undefined;
    try rng.generateRandomBytes(&d);
    errdefer std.crypto.secureZero(u8, &d);
    try rng.generateRandomBytes(&z);
    errdefer std.crypto.secureZero(u8, &z);

    const kp = try mlkem.keygen(params.get(), arena.allocator(), d, z);

    // Duplicate key data *outside* the arena using the main allocator
    const pk = try allocator.dupe(u8, kp.publicKey);
    errdefer allocator.free(pk);

    const s_copy = try allocator.alloc([]const u16, kp.privateKey.s.len);
    errdefer allocator.free(s_copy);
    for (kp.privateKey.s, 0..) |slice, i| {
        s_copy[i] = try allocator.dupe(u16, slice);
        errdefer allocator.free(s_copy[i]);
    }
    const h_copy = try allocator.dupe(u8, kp.privateKey.h);
    errdefer allocator.free(h_copy);


    const sk = PrivateKey{
        .s = s_copy,
        .h = h_copy,
        .z = kp.privateKey.z, // z is already a fixed-size array, no need to dupe
    };

    errdefer {
        for (sk.s) |slice| {
			allocator.free(slice);
		}
		allocator.free(sk.s);
		allocator.free(sk.h);
    }
    return KeyPair{ .publicKey = pk, .privateKey = sk };
}

pub fn encaps(comptime params: Params, pk: PublicKey, allocator: std.mem.Allocator) !EncapsResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    var m: [32]u8 = undefined;
    try rng.generateRandomBytes(&m);
    defer std.crypto.secureZero(u8, &m);

    const result = try mlkem.encaps_internal(params, pk, m, arena.allocator());

    const ct = try allocator.dupe(u8, result.ciphertext); // Caller owns and frees ct
    errdefer allocator.free(ct);
    return EncapsResult{ .ciphertext = ct, .shared_secret = result.shared_secret };
}

pub fn decaps(comptime params: Params, pk: PublicKey, sk: PrivateKey, ct: Ciphertext, allocator: std.mem.Allocator) !SharedSecret {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    return mlkem.decaps_internal(params, pk, sk, ct, arena.allocator()); // No allocation here
}

pub fn destroyCiphertext(ct: *Ciphertext) void {
    mlkem.destroyCiphertext(ct);
}


// Random Number Generation (using std.crypto.random)
pub fn generateRandomBytes(buffer: []u8) !void {
    try std.crypto.random.bytes(buffer);
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
// const ss = try mlkem.decaps(pd, pk, sk, ct, allocator);
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
//test "benchmark mlkem keygen" {
//    const pd = Params.kem768; // Fix parameter type
//    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//    defer _ = gpa.deinit();
    //const allocator = gpa.allocator();

//    var timer = try std.time.Timer.start();

    //var i: usize = 0;
	//TODO: REDO THIS TEST
    //while (i < 1000) : (i += 1) { // Benchmark over 1000 iterations
    //    var keypair = try keygen(pd, allocator);
    //}

//    const elapsed = timer.read();
//    std.debug.print("Average keygen time: {}ns\n", .{elapsed / 1000});
//}

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
