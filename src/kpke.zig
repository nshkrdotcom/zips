//kpke.zig
const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const params = @import("params.zig");
const rng = @import("rng.zig");
const utils = @import("utils.zig");
const ntt = @import("ntt.zig");
const cbd = @import("cbd.zig");
const Error = @import("error.zig").Error;

// Define key types using opaque structs
pub const PublicKey = struct {
    t: []u8,
    rho: [32]u8,
	allocator: mem.Allocator, // The allocator used (important for freeing)
	zetas: []u16,
};

pub const PrivateKey = struct {
    s: []const []const u16, // A slice of k polynomial slices (each of length 256 when NTT'd)
    allocator: mem.Allocator, // The allocator used (important for freeing)
	zetas: []u16,
};

pub const Ciphertext = []u8; // Ciphertext will be a byte array

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
    const numerator = @as(u32, @intCast(1 << bits)); //2^bits; use shifts as multiply by power of 2
    const result = @as(u16, @intCast((numerator * value) / pd.q)); // Integer division, rounds down
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
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Generate random bytes for seed d
    var d: [32]u8 = undefined;
    try rng.generateRandomBytes(&d);

    // 2. Expand seed d into rho and sigma
    var rho_sigma = std.mem.zeroes([64]u8);
    crypto.hash.sha3.Sha3_512.hash(&d, &rho_sigma, .{});
    const rho = rho_sigma[0..32].*;
    const sigma = rho_sigma[32..].*;
    _ = sigma; // Unused, but keep to prevent unused variable warning

    // 3. Generate matrix A (using NTT and SampleNTT)
    var A_hat = try arena_allocator.alloc(ntt.RqTq(pd), pd.k * pd.k);
    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed = [_]u8{0} ** 34;
            @memcpy(seed[0..32].ptr, &rho);
            seed[32] = @as(u8, @intCast(j));
            seed[33] = @as(u8, @intCast(i));
            A_hat[i * pd.k + j] = blk: {
                var result: ntt.RqTq(pd) = undefined;
                for (result[0..]) |*item| {
                    item.* = 0;
                }
                var counter: u32 = 0;
                while (true) : (counter += 1) {
                    if (counter == 1000) return Error.RandomnessFailure; // reasonable upper bound per FIPS 203 recommendation.
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

    // 4. Generate secret key s (using CBD)
	//var s = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
	var s = try arena_allocator.alloc([]u16, pd.k);  // Allocate a slice to hold *k* polynomial
	for (0..pd.k) |i| {
		s[i] = try cbd.samplePolyCBD(pd, arena_allocator);
	}

    // 5. Generate error vector e (using CBD)
	var e = try arena_allocator.alloc([]u16, pd.k);
	for (0..pd.k) |i| {
		e[i] = try cbd.samplePolyCBD(pd, arena_allocator);
	}

	// In keygen, precompute zetas
	const zetas = try ntt.precomputeZetas(pd, arena_allocator);
	defer allocator.free(zetas);

    // 6. Compute t = As + e
    var t = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
    var s_hat = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
	for (0..pd.k) |i| {
		var s_array: ntt.RqTq(pd) = undefined;
		@memcpy(&s_array, s[i][0..256]);
		ntt.ntt(pd, &s_array, zetas);
		@memcpy(&s_hat[i], &s_array);
		arena_allocator.free(s[i]);
	}
	arena_allocator.free(s);

	for (0..pd.k) |i| {
		var t_array: ntt.RqTq(pd) = undefined;
		@memcpy(&t_array, t[i][0..pd.n]);
		ntt.ntt(pd, &t_array, zetas);
		@memcpy(&t[i], &t_array);
		arena_allocator.free(t[i]);
	}

	
    // Initialize t to zeroes
	//std.mem.zeroes(t);
    //for (0..pd.k) |i| {
	//	@memset(t[i], 0);
    //}
	

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly: ntt.RqTq(pd) = undefined;
			@memset(&temp_poly, 0);
            for (0..pd.n) |z| {
				const z_a: u16 = @intCast(@mod(@as(u32, A_hat[i * pd.k + j][z]) * @as(u32, s_hat[j][z]), pd.q));
                temp_poly[z] = @as(u16, z_a);
            }
            for (0..pd.n) |z| {
				const iz_a: u16 = @intCast(@mod(t[i][z] + temp_poly[z], pd.q));
                t[i][z] = @as(u16, iz_a);
            }
        }
        for (0..pd.n) |z| {
			const iz_b: u16 = @intCast(@mod(@as(u32, t[i][z]) + @as(u32, e[i][z]), pd.q));
            t[i][z] = @as(u16, iz_b);
        }
    }	
	for (0..pd.k) |i| {
		arena_allocator.free(e[i]);
		arena_allocator.free(s_hat[i]);
	}
	arena_allocator.free(s_hat);
	arena_allocator.free(e);

    var encoded_t = try arena_allocator.alloc(u8, pd.publicKeyBytes - 32);
    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &t[i], zetas);
        var current_index: usize = i * pd.n * 2;
        for (0..pd.n) |j| {				
            const compressed_t: u16 = compress(pd, t[i][j], pd.du);
			const lsb: u8 = @intCast(@as(u16, compressed_t));
			const msb: u8 = @intCast(@as(u16, compressed_t >> 8));
			encoded_t[current_index] = msb;
			encoded_t[current_index+1] = lsb;
            current_index += 2;
        }
    }

	for (0..pd.k) |i| {
		arena_allocator.free(t[i]);
	}
	arena_allocator.free(t);
	
    // 7. Create PublicKey and PrivateKey structs
    const pk = PublicKey{ .t = encoded_t, .rho = rho, .allocator = arena_allocator, .zetas = zetas};
    const sk = PrivateKey{ .s = s, .allocator = arena_allocator, .zetas = zetas};
    return KeyPair{ .publicKey = pk, .privateKey = sk };
}

// K-PKE Encryption
pub fn encrypt(comptime pd: params.ParamDetails, pk: PublicKey, message: []const u8, allocator: mem.Allocator) Error![]u8 {
    var publicKey_A_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k * pd.k);
    defer allocator.free(publicKey_A_hat);
    var r_bytes: [32]u8 = undefined;
    try rng.generateRandomBytes(&r_bytes);
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    // 2. Encode message as a polynomial
    var m = try utils.bytesToPolynomial(pd, message);

    // 3. Generate y, e1, and e2 using CBD
    //var y = try cbd.samplePolyCBD(pd, allocator);
	var y = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
    const e1 = try cbd.samplePolyCBD(pd, allocator);
    const e2 = try cbd.samplePolyCBD(pd, allocator);

    // ... (Rest of encryption - expand public key, matrix-vector multiplication, NTT, encoding ciphertext)
    // ... (randomness generation, message encoding, CBD sampling - as before)

    // 4. Expand public key (assuming pk contains the byte representation of t and rho)
    // ... (This part depends on the exact structure of your PublicKey.  Example below)
    const tBytes = pk.t;
    const publicKey_t = try utils.bytesToPolynomial(pd, tBytes);
    const rho = pk.rho;
    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed = [_]u8{0} ** 34;
            @memcpy(seed[0..32], &rho);
            seed[32] = @as(u8, @intCast(j));
            seed[33] = @as(u8, @intCast(i));
            publicKey_A_hat[i * pd.k + j] = blk: {
                var result: ntt.RqTq(pd) = undefined;
                for (result[0..]) |*item| {
                    item.* = 0;
                }
                var counter: u32 = 0;

                while (true) : (counter += 1) {
                    if (counter == 1000) return Error.RandomnessFailure; // reasonable upper bound per FIPS 203 recommendation.
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

    // Perform matrix-vector multiplication (A^T * y) and add e1
    var u_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u_hat);

    // Initialize u_hat to zeroes (important!)
	//std.mem.zeroes(u_hat);

    const y_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(y_hat);
	
	const zetas = pk.zetas;
	
    for (0..pd.k) |i| {
		ntt.ntt(pd, &y[i], zetas);
		}

    @memcpy(y_hat, y);

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly: ntt.RqTq(pd) = undefined;
			@memset(&temp_poly, 0);
            for (0..pd.n) |k| {
				const k_a: u16 = @intCast(@mod(@as(u32, publicKey_A_hat[j * pd.k + i][k]) * @as(u32, y_hat[j][k]), pd.q));
                temp_poly[k] = @as(u16, k_a);
            }

            for (0..pd.n) |k| {
				const u_hat_a: u16 = @intCast(@mod(@as(u32, u_hat[i][k]) + @as(u32, temp_poly[k]), pd.q));
                u_hat[i][k] = @as(u16, u_hat_a);
            }
        }
        for (0..pd.n) |k| {
			//const u_hat_b: u16 = @intCast(@mod(@as(u32, u_hat[i][k]) + e1[i][k], pd.q));
			const u_hat_b: u16 = @intCast(@mod(@as(u32, u_hat[i][k]) + e1[k], pd.q)); // was e1[i][k]
			u_hat[i][k] = @as(u16, u_hat_b);
		}
    }

    var u = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u);
    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &u_hat[i], zetas);
        @memcpy(std.mem.asBytes(&u[i]), std.mem.asBytes(&u_hat[i]));
    }
    // Compute v
    // t * y + e2 + encode(message)

    // perform ntt on publicKey_t and m

    var publicKey_t_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(publicKey_t_hat);
	// @memcpy(publicKey_t_hat, publicKey_t.ptr);
	for (0..pd.n) |j| {
		publicKey_t_hat[j] = publicKey_t;
	}
	

    for (0..pd.k) |i| ntt(pd, &publicKey_t_hat[i]);

    var m_hat: ntt.RqTq(pd) = undefined;
	@memset(&m_hat, 0);
    @memcpy(&m_hat, &m);
    ntt(pd, &m_hat);

    var v_hat: ntt.RqTq(pd) = undefined;
	@memset(&v_hat, 0);

    for (0..pd.k) |j| {
        var temp_poly: ntt.RqTq(pd) = undefined;
		@memset(&temp_poly, 0);

        for (0..pd.n) |k| {
            temp_poly[k] = @as(u16, @mod(@as(u32, publicKey_t_hat[j][k]) * @as(u32, y_hat[j][k]), pd.q));
        }

        for (0..pd.n) |k| {
            v_hat[k] = @as(u16, @mod(@as(u32, v_hat[k]) + @as(u32, temp_poly[k]), pd.q));
        }
    }

    for (0..pd.n) |k| {
        v_hat[k] = @as(u16, @mod(@as(u32, v_hat[k]) + @as(u32, e2[k]), pd.q));
        v_hat[k] = @as(u16, @mod(@as(u32, v_hat[k]) + @as(u32, m_hat[k]), pd.q));
    }

    var v = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.n);
    ntt.nttInverse(pd, &v_hat, zetas);
    @memcpy(std.mem.asBytes(&v), std.mem.asBytes(&v_hat));

    // Compress and encode u and v
    var c1 = try allocOrError(std.heap.page_allocator, u8, pd.k * pd.n * pd.du / 8);
    defer allocator.free(c1);

    var c2 = try allocOrError(std.heap.page_allocator, u8, pd.n * pd.dv / 8);
    defer allocator.free(c2);

    // COMPRESSION AND ENCODING (using constant-time operations where appropriate)
    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            const compressed_u = compress(pd, u[i][j], pd.du); // Implement compress function
            std.mem.writeIntLittle(u16, c1[(i * pd.n + j) * 2 .. (i * pd.n + j + 1) * 2], compressed_u);
        }
    }
    for (0..pd.n) |j| {
        const compressed_v = compress(pd, v[j], pd.dv);
        std.mem.writeIntLittle(u16, c2[j * 2 .. (j + 1) * 2], compressed_v);
    }
    var ciphertext = try allocOrError(std.heap.page_allocator, u8, c1.len + c2.len);
    defer allocator.free(ciphertext);
    @memcpy(ciphertext, c1);
    @memcpy(ciphertext[c1.len..], c2);
    return ciphertext;
}

// K-PKE Decryption
pub fn decrypt(comptime pd: params.ParamDetails, sk: PrivateKey, ciphertext: Ciphertext, allocator: *const mem.Allocator, arena: *std.heap.ArenaAllocator) Error![]u8 {
    const u_bytes = ciphertext[0 .. pd.k * pd.n * pd.du / 8];
    const v_bytes = ciphertext[pd.k * pd.n * pd.du / 8 ..];
    var u = try arena.allocator().alloc(ntt.RqTq(pd), pd.k);
    defer allocator.free(u);
    var v = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.n);
    // Decode u
	for (0..pd.k) |i| {
		for (0..pd.n) |j| {
				const start_index = (i * pd.n + j) * 2;
				const two_bytes: [2]u8 = .{ u_bytes[start_index], u_bytes[start_index + 2] };
				u[i][j] = mem.readInt(u16, &two_bytes, .little);
		}
	}
    // Decode v
	for (0..pd.n) |j| {
		for (0..256) |i| { 
			const start_index = (j * 256 + i) * 2;
			const two_bytes: [2]u8 = .{ v_bytes[start_index], v_bytes[start_index + 1] };
			v[j][i] = mem.readInt(u16, &two_bytes, .little);
		}
	}

	const zetas = sk.zetas;

    // 2. Compute s^T * u
    var s_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(s_hat);
    for (0..pd.k) |i| {
		@memcpy(&s_hat[i], sk.s[i]);
        ntt.ntt(pd, &s_hat[i], zetas);
    }
    var u_hat = try allocOrError(std.heap.page_allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u_hat);
    for (0..pd.k) |i| {
        @memcpy(&u[i], zetas);
        @memcpy(&u_hat[i], &u[i]);
    }
	var w_hat: ntt.RqTq(pd) = undefined;
	@memset(&w_hat, 0);
    for (0..pd.k) |i| {
		var temp:  ntt.RqTq(pd) = undefined;
		@memset(&temp, 0);
        for (0..pd.n) |j| {
            temp[j] = @as(u16, @intCast(@mod(@as(u32, s_hat[i][j]) * @as(u32, u_hat[i][j]), pd.q)));
        }
        for (0..pd.n) |j| {
            w_hat[j] = @as(u16, @intCast(@mod(@as(u32, w_hat[j]) + @as(u32, temp[j]), pd.q)));
        }
    }
	var w: ntt.RqTq(pd) = undefined;
	@memset(&w, 0);
    ntt.nttInverse(pd, &w_hat, zetas);
    @memcpy(&w, &w_hat);
    for (0..pd.n) |i| {
		// TODO: This line is wrong, it was originally using v[i], not v[0][i]:
        w[i] = @as(u16, @intCast(@mod(@as(i32, v[0][i]) - @as(i32, w[i]) + pd.q, pd.q)));
    }

    // 3. Decode message from w
    const message_bytes = try utils.polynomialToBytes(pd, &w);
    return message_bytes;
}

// Secure Key Destruction
pub fn destroyPrivateKey(sk: *PrivateKey) void {
    for (sk.s) |poly| {
        sk.allocator.free(poly);
    }
    sk.allocator.free(sk.s);
}

pub fn destroyPublicKey(pk: *PublicKey) void {
	pk.allocator.free(pk.t);
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
    var sk = result.privateKey;
    defer destroyPrivateKey(&sk);

    const message = "this is my message";
    const ciphertext = try encrypt(pd, pk, message, arena.allocator());
    defer arena.allocator().free(ciphertext);

    const decrypted = try decrypt(pd, sk, ciphertext, &allocator, &arena); // Pass the arena
    defer arena.allocator().free(decrypted); // Free decrypted using the arena allocator

    try std.testing.expectEqualSlices(u8, message, decrypted);
}
