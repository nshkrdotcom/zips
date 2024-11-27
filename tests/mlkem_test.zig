//mlkem_test.zig
const std = @import("std");
const kem = @import("kem");
const mlkem = @import("mlkem.zig");
const testing = std.testing;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const test_vectors = @import("test_vectors.zig");
const utils = @import("utils.zig");
const params = @import("params.zig");

const kat_vectors_512 = @import("vectors/kat_vectors_512_small.zig").kat_vectors_512;
const kat_vectors_768 = @import("vectors/kat_vectors_768_small.zig").kat_vectors_768;
const kat_vectors_1024 = @import("vectors/kat_vectors_1024_small.zig").kat_vectors_1024;

fn test_kats(comptime param_set: params.Params, kat_vectors: anytype) !void {
    const pd = param_set.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator(); // Use arena allocator as before
    for (kat_vectors) |kat| {
        var publicKey = try utils.decodePublicKey(pd, kat.pk);
        defer publicKey.arena.deinit();
        var privateKey = try utils.decodePrivateKey(pd, kat.sk);
        defer privateKey.arena.deinit();
        var ciphertext = try utils.decodeCiphertext(pd, kat.ct);
        defer ciphertext.arena.deinit();
        const sharedSecret = try mlkem.decaps(pd, privateKey, ciphertext, allocator);
        try expectEqual(kat.ss.len, sharedSecret.len);
        try expectEqualSlices(u8, kat.ss, &sharedSecret);
        // Test keygen and encapsulate too for the same KAT since you're not doing key validation tests
        var generatedKeyPair = try kem.keygen(param_set, allocator);
        defer kem.destroyPrivateKey(&generatedKeyPair.privateKey);
        defer kem.destroyPublicKey(&generatedKeyPair.publicKey);
        var encapsResult = try kem.encaps(param_set, publicKey, allocator);
        try expectEqual(kat.ct.len, encapsResult.ciphertext.len);
        try expectEqualSlices(u8, kat.ct, encapsResult.ciphertext);
        kem.destroyCiphertext(&encapsResult.ciphertext);
    }
}

test "ML-KEM-512 KATs (Small)" {
    try test_kats(params.Params.kem512, kat_vectors_512);
}

test "ML-KEM-768 KATs (Small)" {
    try test_kats(params.Params.kem768, kat_vectors_768);
}

test "ML-KEM-1024 KATs (Small)" {
    try test_kats(params.Params.kem1024, kat_vectors_1024);
}