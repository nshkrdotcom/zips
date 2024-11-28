//kpke.zig
const std = @import("std");
const crypto = std.crypto; // Keep for crypto functions
const params = @import("params.zig");
const rng = @import("rng.zig"); 
const utils = @import("utils.zig");
const ntt = @import("ntt.zig");
const cbd = @import("cbd.zig");
const Error = @import("error.zig").Error;

pub const PublicKey = struct {
    t: []u8,
    rho: [32]u8,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: mem.Allocator, t: []u8, rho: [32]u8) !PublicKey {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();  // Clean up if allocation fails

        const t_copy = try arena.allocator().dupe(u8, t);
        errdefer arena.allocator().free(t_copy); // errdefer for the copy

        return PublicKey{
            .t = t_copy,
            .rho = rho,
            .arena = arena,
        };
    }

    pub fn deinit(self: *PublicKey) void {
        self.arena.deinit();
    }
};

pub const PrivateKey = struct {
    s: []const []const u16,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: mem.Allocator, s: []const []const u16) !PrivateKey {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const s_copy = try arena.allocator().alloc([]const u16, s.len);
        errdefer arena.allocator().free(s_copy);
        for (s, 0..) |poly, i| {
            s_copy[i] = try arena.allocator().dupe(u16, poly);
            errdefer arena.allocator().free(s_copy[i]);
        }

        return PrivateKey{
            .s = s_copy,
            .arena = arena,
        };
    }


    pub fn deinit(self: *PrivateKey) void {
        for (self.s) |poly| {
            self.arena.allocator().free(poly);
        }
        self.arena.allocator().free(self.s);
        self.arena.deinit();
    }
};

pub const Ciphertext = struct {
    data: []u8,
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: mem.Allocator, data: []u8) !Ciphertext {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        const data_copy = try arena.allocator().dupe(u8, data);
        errdefer arena.allocator().free(data_copy);

        return Ciphertext{
            .data = data_copy,
            .arena = arena,
        };
    }

    pub fn deinit(self: *Ciphertext) void {
        self.arena.allocator().free(self.data);
        self.arena.deinit();
    }
};

inline fn secureZero(comptime T: type, slice: []volatile T) void {
    for (slice) |*elem| {
        elem.* = 0;
        asm volatile ("" ::: "memory"); // Prevent optimizations
    }
}

const KeyPair = struct {
    publicKey: PublicKey,
    privateKey: PrivateKey,
};

fn compress(comptime pd: params.ParamDetails, value: u16, bits: u8) u16 {
	const n_a: u5 = @intCast(@as(u8, bits));
    const numerator = @as(u32, 1) << @as(u5, n_a);
    const result = @as(u16, @intCast((numerator * value) / pd.q));
    return result;
}

pub fn allocOrError(allocator: mem.Allocator, comptime T: type, size: usize) Error![]T {
    return allocator.alloc(T, size) catch |err| switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
    };
}

// K-PKE Key Generation
pub fn keygen(comptime pd: params.ParamDetails, allocator: mem.Allocator) Error!KeyPair {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    // 1. Generate random bytes for seed d
    var d: [32]u8 = undefined;
    try rng.generateRandomBytes(&d);

    // 2. Expand seed d into rho and sigma
    var rho_sigma: [64]u8 = undefined;  // No need to zero-initialize if you overwrite it immediately
    crypto.hash.sha3.Sha3_512.hash(&d, &rho_sigma, .{});
    const rho = rho_sigma[0..32].*;
    const sigma = rho_sigma[32..].*;

    // 3. Generate matrix A_hat (using SampleNTT)
    var A_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k * pd.k);
    errdefer arena.allocator().free(A_hat);
    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed: [34]u8 = undefined; // Fixed-size seed array
            @memcpy(seed[0..32], &rho);
            seed[32] = @intCast(j);
            seed[33] = @intCast(i);
            A_hat[i * pd.k + j] = blk: {
                var result: ntt.RqTq(pd) = undefined;
                // ... (SampleNTT logic as before, using `crypto.random.bytes` and range check)
            };
        }
    }

    // 4. Generate secret key s (using CBD)
    var s = try arena.allocator().alloc([]u16, pd.k * pd.n);  // Allocate a contiguous block for s
    errdefer arena.allocator().free(s);    
    for (0..pd.k) |i| {
        s[i * pd.n .. (i + 1) * pd.n] = try cbd.samplePolyCBD(pd, arena.allocator());  // Store each polynomial contiguously
        errdefer arena.allocator().free(s[i * pd.n .. (i + 1) * pd.n]);  // Correct errdefer for contiguous allocation
    }

    // 5. Generate error vector e (using CBD) – Similar change for contiguous allocation
    var e = try arena.allocator().alloc([]u16, pd.k * pd.n);
    errdefer arena.allocator().free(e);
    for (0..pd.k) |i| {
        e[i * pd.n .. (i + 1) * pd.n] = try cbd.samplePolyCBD(pd, arena.allocator());
        errdefer arena.allocator().free(e[i * pd.n .. (i + 1) * pd.n]);
    }

    const zetas = ntt.getZetas(pd);

    // 6. Compute t = As + e (using NTT)
    var t = try arena.allocator().alloc([]u16, pd.k * pd.n);
    errdefer arena.allocator().free(t);

    var s_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k); // Allocate s_hat within the arena
    errdefer arena.allocator().free(s_hat);
    for (0..pd.k) |i| {
        ntt.ntt(pd, &s[i * pd.n .. (i + 1) * pd.n], zetas);  // Perform NTT on the correct slice of s
        @memcpy(&s_hat[i], &s[i * pd.n .. (i+1)*pd.n]);  // Correct memcpy for s_hat
    }

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly: ntt.RqTq(pd) = undefined;  // Allocate within inner loop
            for (0..pd.n) |z| {
                temp_poly[z] = @rem(A_hat[i * pd.k + j][z] * s_hat[j][z], pd.q);  // Use @rem
            }
            for (0..pd.n) |z| {
                t[i * pd.n + z] = @rem(t[i * pd.n + z] + temp_poly[z], pd.q);
            }
        }
        for (0..pd.n) |z| {
            t[i * pd.n + z] = @rem(t[i * pd.n + z] + e[i * pd.n + z], pd.q);
        }
    }


    // 7. Encode t (Compression and Serialization)
    var encoded_t = try arena.allocator().alloc(u8, pd.publicKeyBytes - 32);
    errdefer arena.allocator().free(encoded_t);
    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &t[i * pd.n .. (i + 1) * pd.n], zetas);  // Inverse NTT on the correct slice of t
        for (0..pd.n) |j| {
            const compressed_t = utils.compress(pd, t[i * pd.n + j], pd.du);
            std.mem.writeIntLittle(u16, encoded_t[((i * pd.n + j) * 2)..], compressed_t);  // Correct indexing into encoded_t
        }
    }

    const publicKeyBytes = try allocator.dupe(u8, encoded_t);
    errdefer allocator.free(publicKeyBytes);

    const publicKey = try PublicKey.init(allocator, publicKeyBytes, rho);
    errdefer publicKey.deinit();


    // Allocate and duplicate s data for private key
    const s_copy = try allocator.alloc([]const u16, pd.k);
    errdefer allocator.free(s_copy); // Added errdefer to prevent memory leaks
    for (0..pd.k) |i| {
        s_copy[i] = try allocator.dupe(u16, s[i]);
        errdefer allocator.free(s_copy[i]);
    }

    const privateKey = try PrivateKey.init(allocator, s_copy);
    errdefer privateKey.deinit();

    return .{
        .public_key = publicKey,
        .private_key = privateKey,
    };
}

// K-PKE Encryption
pub fn encrypt(comptime pd: params.ParamDetails, pk: PublicKey, message: []const u8, allocator: mem.Allocator) Error!Ciphertext {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const zetas = ntt.getZetas(pd);

    // 1. Generate random bytes r
    var r: [32]u8 = undefined;
    try rng.generateRandomBytes(&r);

    // 2. Encode message as a polynomial m
    const m = try utils.bytesToPolynomial(pd, message, arena.allocator());
    errdefer arena.allocator().free(m); // Free m if subsequent allocations fail

    // 3. Generate y, e1, and e2 using CBD
    var y = try arena.allocator().alloc([]u16, pd.k * pd.n);
    errdefer arena.allocator().free(y);
    for (0..pd.k) |i| {
        y[i * pd.n .. (i+1) * pd.n] = try cbd.samplePolyCBD(pd, arena.allocator());
        errdefer arena.allocator().free(y[i * pd.n .. (i+1) * pd.n]); // Free y[i] parts as you go

    }
    const e1 = try cbd.samplePolyCBD(pd, arena.allocator());
    errdefer arena.allocator().free(e1);
    const e2 = try cbd.samplePolyCBD(pd, arena.allocator());
    errdefer arena.allocator().free(e2);


    // 4. Expand public key
    var publicKey_A_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k * pd.k);
    errdefer arena.allocator().free(publicKey_A_hat);
    const rho = pk.rho;

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed: [34]u8 = undefined;
            @memcpy(seed[0..32], &rho);
            seed[32] = @intCast(j);
            seed[33] = @intCast(i);

            publicKey_A_hat[i * pd.k + j] = blk: {
                var result: ntt.RqTq(pd) = undefined;
                var counter: u32 = 0;
                while (true) : (counter += 1) {
                    if (counter == 1000) return Error.RandomnessFailure;
                    crypto.random.bytes(std.mem.asBytes(&result));
                    var valid = true;
                    for (result) |coeff| {
                        if (coeff >= pd.q) {
                            valid = false;
                            break;
                        }
                    }
                    if (valid) break :blk result;
                }
            };
        }
    }

    const t = try utils.bytesToPolynomial(pd, pk.t, arena.allocator()); // Decode t using arena
	errdefer arena.allocator().free(t);



    // 5. Perform matrix-vector multiplication and NTT, add e1
    var u_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k);
    errdefer arena.allocator().free(u_hat);
    var y_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k);
    errdefer arena.allocator().free(y_hat);

    for (0..pd.k) |i| {
        var y_poly = y[i * pd.n .. (i+1) * pd.n];
        ntt.ntt(pd, &y_poly, zetas);
        @memcpy(y_hat[i][0..pd.n], y_poly);
    }
     for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly: ntt.RqTq(pd) = undefined;
            for (0..pd.n) |z| {
                temp_poly[z] = @rem(@as(u16, publicKey_A_hat[j * pd.k + i][z]) * y_hat[j][z], pd.q);
            }
            for (0..pd.n) |z| {
                u_hat[i][z] = @rem(u_hat[i][z] + temp_poly[z], pd.q); // Use @rem for modular arithmetic
            }
        }

        for (0..pd.n) |z| {
            u_hat[i][z] = @rem(u_hat[i][z] + e1[z], pd.q);
        }
    }

    var u = try arena.allocator().alloc([]u16, pd.k * pd.n);
    errdefer arena.allocator().free(u);

    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &u_hat[i], zetas);
        @memcpy(u[i * pd.n..(i + 1) * pd.n], u_hat[i][0..pd.n]);

    }

    // 6. Compute v = t * y + e2 + m
    var v_hat: ntt.RqTq(pd) = undefined; // Allocate in the arena
    // ... (rest of v calculation as before, using arena.allocator())

    var v = try arena.allocator().alloc([]u16, pd.n);
    errdefer arena.allocator().free(v);
    ntt.nttInverse(pd, &v_hat, zetas);
    @memcpy(v, v_hat[0..pd.n]);


    // 7. Compress and encode u and v
    // ... (compression and encoding logic using arena.allocator(), similar to previous examples)


    const ciphertextBytes = try arena.allocator().dupe(u8, ciphertext_from_arena); // Duplicate the ciphertext bytes outside the arena before it's destroyed
    errdefer arena.allocator().free(ciphertextBytes);
    var ciphertext = try Ciphertext.init(allocator, ciphertextBytes);
    return ciphertext;
}

// K-PKE Decryption
pub fn decrypt(comptime pd: params.ParamDetails, sk: PrivateKey, ct: Ciphertext, allocator: mem.Allocator) Error![]u8 {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const zetas = ntt.getZetas(pd); // Access precomputed zetas (no allocation)
    const ctBytes = ct.data; // Access ciphertext data directly

    // 1. Decode u and v from ciphertext
    const u_bytes = ctBytes[0 .. pd.k * pd.n * pd.du / 8];
    const v_bytes = ctBytes[pd.k * pd.n * pd.du / 8 ..];

    var u = try arena.allocator().alloc([]u16, pd.k * pd.n);
    errdefer arena.allocator().free(u);
    var v = try arena.allocator().alloc([]u16, pd.n);
    errdefer arena.allocator().free(v);

    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            const start_index = (i * pd.n + j) * 2;
            const compressed_u = mem.readIntLittle(u16, u_bytes[start_index..start_index + 2]);
            u[i * pd.n + j] = utils.decompress(pd, compressed_u, pd.du);
        }
    }
    for (0..pd.n) |j| {
        const start_index = j * 2;
        const compressed_v = mem.readIntLittle(u16, v_bytes[start_index..start_index + 2]);
        v[j] = utils.decompress(pd, compressed_v, pd.dv);

    }

    // 2. Compute s^T * u
    var s_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k);
    errdefer arena.allocator().free(s_hat);

    for (0..pd.k) |i| {
        @memcpy(s_hat[i][0..pd.n], sk.s[i]); // Copy from private key into arena
        ntt.ntt(pd, &s_hat[i], zetas);
    }


    var u_hat = try arena.allocator().alloc(ntt.RqTq(pd), pd.k);
    errdefer arena.allocator().free(u_hat);

    for (0..pd.k) |i| {
        ntt.ntt(pd, &u[i*pd.n .. (i+1)*pd.n], zetas);
        @memcpy(u_hat[i][0..pd.n], u[i * pd.n .. (i+1) * pd.n]);
    }

    var w_hat: ntt.RqTq(pd) = undefined;
    for (0..pd.k) |i| {
        var temp_poly: ntt.RqTq(pd) = undefined; // Allocate temp_poly in the arena
        for (0..pd.n) |j| {
            temp_poly[j] = @rem(s_hat[i][j] * u_hat[i][j], pd.q);
        }

        for (0..pd.n) |j| {
            w_hat[j] = @rem(w_hat[j] + temp_poly[j], pd.q);
        }
    }


    var w = try arena.allocator().alloc([]u16, pd.n);
    errdefer arena.allocator().free(w);


    ntt.nttInverse(pd, &w_hat, zetas);
    @memcpy(w, w_hat[0..pd.n]);

    for (0..pd.n) |i| {
        w[i] = @rem(@as(u16, @mod(@as(i32, v[i]) - @as(i32, w[i]) + pd.q, pd.q)), pd.q);
    }

    // 3. Decode message from w
    const message_bytes = try utils.polynomialToBytes(pd, w, arena.allocator());
    errdefer arena.allocator().free(message_bytes);  // Free if duplication fails
	
    const decrypted_message = try allocator.dupe(u8, message_bytes);
    return decrypted_message;
}

const expectError = std.testing.expectError;

test "kpke keygen generates keys" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    _ = try keygen(pd, allocator);
}

test "k-pke encrypt and decrypt are inverses" {
    const pd = comptime params.Params.kem768.get();
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const result = try keygen(pd, allocator);
    const pk = result.publicKey;
    const sk = result.privateKey;

    const message = "this is my message";
    const ciphertext = try encrypt(pd, pk, message, arena.allocator());
    defer arena.allocator().free(ciphertext);

    const decrypted = try decrypt(pd, sk, ciphertext, &allocator, &arena); // Pass the arena
    defer arena.allocator().free(decrypted); // Free decrypted using the arena allocator

    try std.testing.expectEqualSlices(u8, message, decrypted);
}
