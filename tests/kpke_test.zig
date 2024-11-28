//kpke_test.zig
const std = @import("std");
const kpke = @import("kpke.zig");
const params = @import("params.zig");
const utils = @import("utils.zig");
const expectEqual = std.testing.expectEqual;


const kat_vectors_512 = @import("vectors/kat_vectors_512_small.zig").kat_vectors_512;
const kat_vectors_768 = @import("vectors/kat_vectors_768_small.zig").kat_vectors_768;
const kat_vectors_1024 = @import("vectors/kat_vectors_1024_small.zig").kat_vectors_1024;

fn test_kpke_kats(comptime param_set: params.Params, kat_vectors: anytype) !void {
    const pd = param_set.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    for (kat_vectors) |kat| {
        var arena = std.heap.ArenaAllocator.init(allocator); // Arena per KAT vector
        defer arena.deinit();

        // No defer for publicKey.arena.deinit() needed; the loop's arena handles it.
        var publicKey = try utils.decodePublicKey(pd, kat.pk, arena.allocator());
        var privateKey = try utils.decodePrivateKey(pd, kat.sk, arena.allocator());
        var ciphertext = try utils.decodeCiphertext(pd, kat.ct, arena.allocator());
        
		const decryptedMessage = try kpke.decrypt(pd, privateKey, ciphertext, &allocator, &arena);
		defer arena.allocator().free(decryptedMessage);
        var decodedMsg = try utils.bytesToPolynomial(pd, kat.msg, arena.allocator());  // Use arena
        var msgBytes = try utils.polynomialToBytes(pd, &decodedMsg, arena.allocator()); // Use arena

        try expectEqualSlices(u8, msgBytes, decryptedMessage);

        var keypair = try kpke.keygen(pd, allocator); // keygen uses its own arena internally

        const encryptedMessage = try kpke.encrypt(pd, keypair.PublicKey, kat.msg, arena.allocator());  // Use arena
        defer arena.allocator().free(encryptedMessage);
        try expectEqualSlices(u8, encryptedMessage, ciphertext);\
    }
}



test "K-PKE-512 KATs (Small)" {
    try test_kpke_kats(params.Params.kem512, kat_vectors_512);
}

test "K-PKE-768 KATs (Small)" {
    try test_kpke_kats(params.Params.kem768, kat_vectors_768);
}

test "K-PKE-1024 KATs (Small)" {
    try test_kpke_kats(params.Params.kem1024, kat_vectors_1024);
}
