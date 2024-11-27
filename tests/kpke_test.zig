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
        var publicKey = try utils.decodePublicKey(pd, kat.pk);
        defer publicKey.arena.deinit();

        var privateKey = try utils.decodePrivateKey(pd, kat.sk);
        defer privateKey.arena.deinit();
        var ciphertext = try utils.decodeCiphertext(pd, kat.ct);
        defer ciphertext.arena.deinit();

        const decryptedMessage = try kpke.decrypt(pd, privateKey, ciphertext, allocator);
        defer allocator.free(decryptedMessage);

        // The KAT msg field needs to be decoded to match the decrypted message format.
        var decodedMsg = try utils.bytesToPolynomial(pd, kat.msg);

        // Convert decodedMsg (polynomial) to bytes to match decryptedMessage format.
        var msgBytes = try utils.polynomialToBytes(pd, &decodedMsg);
        defer allocator.free(msgBytes);

        try expectEqualSlices(u8, msgBytes, decryptedMessage); // Ensure decryptedMessage are equal to the original message


        var keypair = try kpke.keygen(pd, allocator);
        defer kpke.destroyPrivateKey(&keypair.privateKey);
        defer kpke.destroyPublicKey(&keypair.publicKey);


        // Encrypt the original message using the generated keypair
        const encryptedMessage = try kpke.encrypt(pd, keypair.publicKey, kat.msg, allocator);
        defer allocator.free(encryptedMessage);

        try expectEqualSlices(u8, encryptedMessage, ciphertext);

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
