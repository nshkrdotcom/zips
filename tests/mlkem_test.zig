const std = @import("std");
const kem = @import("kem");
const testing = std.testing;
const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;
const test_vectors = @import("test_vectors.zig");
const utils = @import("utils.zig");
const params = @import("params.zig");

test "ML-KEM KATs" {
    // Loop through each parameter set
    inline for (.{params.Params.kem512, params.Params.kem768, params.Params.kem1024}) |param_set| {
        const pd = param_set.get();
        // Loop through the KATs for the current parameter set
         const kats = switch (param_set) {
			params.Params.kem512 => test_vectors.kat_kem512,
			params.Params.kem768 => test_vectors.kat_kem768,
			params.Params.kem1024 => test_vectors.kat_kem1024,
        };
        for (kats, 0..) |kat, i| {
            testing.log_level = .debug;
            std.debug.print("\nStarting KAT {d}\n", .{i});
            // Convert hex strings to appropriate Zig types
            const z = try std.fmt.hexToSlice(u8, kat.z);
            const d = try std.fmt.hexToSlice(u8, kat.d);
            const msg = try std.fmt.hexToSlice(u8, kat.msg);
            _ = msg;
            const seed = try std.fmt.hexToSlice(u8, kat.seed);
            _ = seed;

            var pk = try utils.decodePublicKey(pd, kat.pk);
            var sk = blk: {
                var privateKey = try utils.decodePrivateKey(pd, kat.sk);
                break :blk privateKey;
            };
            var ct = try utils.decodeCiphertext(pd, kat.ct);
            const ss = try kem.decaps(pd, sk, ct, allocator);

            try testing.expectEqualSlices(u8, try std.fmt.hexToSlice(u8, kat.ss), &ss);
            // Test keygen - decode kat public and secret keys
            const keypair = try kem.keygen(pd, allocator);
        }
    }
}

// ... (other test functions)