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
    pub fn init(t: []u8, rho: [32]u8) PublicKey {
        return .{ .t = t, .rho = rho };
    }
};

pub const PrivateKey = struct {
    s: []u16,
    arena: *std.heap.ArenaAllocator,
};

fn allocOrError(allocator: *mem.Allocator, comptime T: type, size: usize) Error![]T {
    return allocator.alloc(T, size) catch |err| switch (err) {
        error.OutOfMemory => Error.OutOfMemory,
    };
}

inline fn secureZero(comptime T: type, slice: []volatile T) void {
    for (slice) |*elem| {
        elem.* = 0;
        asm volatile ("" : : : "memory"); // Prevent optimizations
    }
}

// Compress function (assumed to be implemented elsewhere)
fn compress(comptime pd: params.ParamDetails, value: u16, bits: u8) u16 {
    // Placeholder implementation - replace with actual compression logic
    _ = pd;
    _ = bits;
    return value;
}

// K-PKE Key Generation
pub fn keygen(comptime pd: params.ParamDetails, allocator: mem.Allocator) Error!struct{PublicKey, PrivateKey} {
    var arena = try std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    // 1. Generate random bytes for seed d
    var d: [32]u8 = undefined;
    try rng.generateRandomBytes(&d);

    // 2. Expand seed d into rho and sigma
    var rho_sigma = std.mem.zeroes([64]u8);
    crypto.hash.sha3.Sha3_512.hash(d, &rho_sigma, .{});
    var rho = rho_sigma[0..32].*;
    const sigma = rho_sigma[32..].*;
    _ = sigma; // Unused, but keep to prevent unused variable warning
	
    // 3. Generate matrix A (using NTT and SampleNTT)
    var A_hat = try arena_allocator.alloc(ntt.RqTq(pd), pd.k * pd.k);
    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed = [_]u8{0} ** 34;
            std.mem.copy(u8, &seed, &rho);
			seed[32] = @as(u8, @intCast(j));
			seed[33] = @as(u8, @intCast(i));
            A_hat[i * pd.k + j] = blk: {
                var result = ntt.RqTq(pd){};
                var counter: u32 = 0;
                while (true) : (counter += 1) {
                    if (counter == 1000) return Error.RandomnessFailure; // reasonable upper bound per FIPS 203 recommendation.
                    try crypto.random(std.mem.asBytes(&result));
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
    var s = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
    for (0..pd.k) |i| {
        s[i] = try cbd.samplePolyCBD(pd, arena_allocator);
    }

    // 5. Generate error vector e (using CBD)
    var e = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);

    for (0..pd.k) |i| {
        e[i] = try cbd.samplePolyCBD(pd, arena_allocator);
    }

    // 6. Compute t = As + e
    var t = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
    var s_hat = try arena_allocator.alloc(ntt.RqTq(pd), pd.k);
    for (0..pd.k) |i| {
       ntt.ntt(pd, &s[i]); // calculate ntt of s once instead of repeatedly
       std.mem.copy(ntt.RqTq(pd), &s_hat[i], &s[i]);
    }
    // Initialize t to zeroes
    @memset(t, ntt.RqTq(pd){});

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly = ntt.RqTq(pd){};
            for (0..pd.n) |z| {
                temp_poly[z] = @as(u16, @mod(@as(u32, A_hat[i * pd.k + j][z]) * @as(u32, s_hat[j][z]), pd.q));
            }
            for (0..pd.n) |z| {
                t[i][z] = @as(u16, @mod(t[i][z] + temp_poly[z], pd.q));
            }
        }
        for (0..pd.n) |z| {
            t[i][z] = @as(u16, @mod(@as(u32, t[i][z]) + @as(u32, e[i][z]), pd.q));
        }
    }
    var encoded_t = try arena_allocator.alloc(u8, pd.publicKeyBytes - 32);
    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &t[i]);
        var current_index: usize = i * pd.n * 2;
        for (0..pd.n) |j| {
            const compressed_t = compress(pd, t[i][j], pd.du);
            std.mem.writeIntLittle(u16, encoded_t[current_index..current_index + 2], compressed_t);
            current_index +=2;
        }
    }

    // 7. Create PublicKey and PrivateKey structs
    const pk = PublicKey{ .t = encoded_t, .rho = rho };
    const sk = PrivateKey{ .s = s, .arena = &arena };
    return .{ pk, sk };
}


// K-PKE Encryption
pub fn encrypt(comptime pd: params.ParamDetails, pk: PublicKey, message: []const u8, allocator: mem.Allocator) Error![]u8 {
//pub fn encrypt(comptime pd: params.ParamDetails, pk: PublicKey, message: []const u8, allocator: *const mem.Allocator) Error![]u8 {
    //_ = pd;
    //_ = pk;
    //_ = message;
    //_ = allocator;
	// 1. Generate randomness r
    var r_bytes: [32]u8 = undefined;
    try rng.generateRandomBytes(&r_bytes);

    // 2. Encode message as a polynomial
	var m = try utils.bytesToPolynomial(pd, message);

    // 3. Generate y, e1, and e2 using CBD
	var y = try cbd.samplePolyCBD(pd, allocator);
    const e1 = try cbd.samplePolyCBD(pd, allocator);
	const e2 = try cbd.samplePolyCBD(pd, allocator);

    // ... (Rest of encryption - expand public key, matrix-vector multiplication, NTT, encoding ciphertext)
	// ... (randomness generation, message encoding, CBD sampling - as before)

    // 4. Expand public key (assuming pk contains the byte representation of t and rho)
    // ... (This part depends on the exact structure of your PublicKey.  Example below)
    const tBytes = pk.t;
    const publicKey_t = try utils.bytesToPolynomial(pd, tBytes);
	var publicKey_A_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k * pd.k);
    defer allocator.free(publicKey_A_hat);
    var rho = pk.rho;
    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var seed = [_]u8{0} ** 34;
            std.mem.copy(u8, &seed, &rho);
			seed[32] = @as(u8, @intCast(j));
			seed[33] = @as(u8, @intCast(i));
            publicKey_A_hat[i * pd.k + j] = blk: {
                var result = ntt.RqTq(pd){};
                var counter: u32 = 0;

                while (true) : (counter += 1) {
                if (counter == 1000) return Error.RandomnessFailure; // reasonable upper bound per FIPS 203 recommendation.
				try crypto.random(std.mem.asBytes(&result));
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
    var u_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u_hat);

    // Initialize u_hat to zeroes (important!)
    std.mem.zeroes(u_hat);

    const y_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(y_hat);

    for (0..pd.k) |i| ntt.ntt(pd, &y[i]);
	
	std.mem.copy(ntt.RqTq(pd), y_hat, y);

    for (0..pd.k) |i| {
        for (0..pd.k) |j| {
            var temp_poly = ntt.RqTq(pd){};
            for (0..pd.n) |k| {
                temp_poly[k] = @as(u16, @mod(@as(u32,publicKey_A_hat[j * pd.k + i][k]) * @as(u32,y_hat[j][k]), pd.q));
            }

            for (0..pd.n) |k| {
                u_hat[i][k] = @as(u16, @mod(@as(u32,u_hat[i][k]) + @as(u32, temp_poly[k]), pd.q));
            }
        }
        for (0..pd.n) |k| u_hat[i][k] = @as(u16, @mod(@as(u32, u_hat[i][k]) +  @as(u32, e1[i][k]), pd.q));
    }

    var u = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u);
    for (0..pd.k) |i| {
        ntt.nttInverse(pd, &u_hat[i]);
        std.mem.copy(u8, std.mem.asBytes(&u[i]), std.mem.asBytes(&u_hat[i]));
    }
    // Compute v
    // t * y + e2 + encode(message)

    // perform ntt on publicKey_t and m

    var publicKey_t_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(publicKey_t_hat);
    std.mem.copy(ntt.RqTq(pd), publicKey_t_hat, &publicKey_t);

    for (0..pd.k) |i| ntt.ntt(pd, &publicKey_t_hat[i]);

    var m_hat = ntt.RqTq(pd){};
    std.mem.copy(ntt.RqTq(pd), &m_hat, &m);
    ntt.ntt(pd, &m_hat);

    var v_hat = ntt.RqTq(pd){};

    for (0..pd.k) |j| {
		var temp_poly = ntt.RqTq(pd){};

		for (0..pd.n) |k| {
			temp_poly[k] = @as(u16, @mod(@as(u32,publicKey_t_hat[j][k]) * @as(u32,y_hat[j][k]), pd.q));
		}

		for (0..pd.n) |k| {
			v_hat[k] = @as(u16, @mod(@as(u32,v_hat[k]) + @as(u32, temp_poly[k]), pd.q));
		}
    }

    for (0..pd.n) |k| {
		v_hat[k] = @as(u16, @mod(@as(u32,v_hat[k]) + @as(u32, e2[k]), pd.q));
		v_hat[k] = @as(u16, @mod(@as(u32, v_hat[k]) + @as(u32, m_hat[k]), pd.q));
    }

    //var v = ntt.RqTq(pd){};
	var v = try allocOrError(allocator, ntt.RqTq(pd), pd.n);
    ntt.nttInverse(pd, &v_hat);
    std.mem.copy(u8, std.mem.asBytes(&v), std.mem.asBytes(&v_hat));

    // Compress and encode u and v
    var c1 = try allocOrError(allocator, u8, pd.k * pd.n * pd.du/8);
    defer allocator.free(c1);

    var c2 = try allocOrError(allocator, u8, pd.n * pd.dv/8);
    defer allocator.free(c2);

    // COMPRESSION AND ENCODING (using constant-time operations where appropriate)
    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            const compressed_u = compress(pd, u[i][j], pd.du); // Implement compress function
            std.mem.writeIntLittle(u16, c1[(i * pd.n + j) * 2 .. (i * pd.n + j + 1) * 2 ], compressed_u);
        }
    }
    for (0..pd.n) |j| {
        const compressed_v = compress(pd, v[j], pd.dv);
        std.mem.writeIntLittle(u16, c2[j * 2.. (j+1) * 2], compressed_v);
    }
    var ciphertext = try allocOrError(allocator, u8, c1.len + c2.len);
    defer allocator.free(ciphertext);
    std.mem.copy(u8, ciphertext, c1);
    std.mem.copy(u8, ciphertext[c1.len..], c2);

    return ciphertext;
}

// K-PKE Decryption
pub fn decrypt(comptime pd: params.ParamDetails, sk: PrivateKey, ciphertext: []const u8, allocator: *mem.Allocator) Error![]u8 {
    // Decode ciphertext
    const u_bytes = ciphertext[0..pd.k * pd.n * pd.du/8];
    const v_bytes = ciphertext[pd.k * pd.n * pd.du/8..];

    var u = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u);

    //var v = ntt.RqTq(pd){};
	var v = try allocOrError(allocator, ntt.RqTq(pd), pd.n);

    // Decode u
    for (0..pd.k) |i| {
        for (0..pd.n) |j| {
            u[i][j] = std.mem.readIntLittle(u16, u_bytes[(i * pd.n + j) * 2 .. (i * pd.n + j + 1) * 2]);
        }
    }

    // Decode v
    for (0..pd.n) |j| {
        v[j] = std.mem.readIntLittle(u16, v_bytes[j * 2 .. (j+1) * 2]);
    }

    // 2. Compute s^T * u
    var s_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(s_hat);
    for (0..pd.k) |i| {
        std.mem.copy(ntt.RqTq(pd), &s_hat[i], &sk.s[i]);
        ntt.ntt(pd, &s_hat[i]);
    }
	var u_hat = try allocOrError(allocator, ntt.RqTq(pd), pd.k);
    defer allocator.free(u_hat);
    for (0..pd.k) |i| {
        ntt.ntt(pd, &u[i]);
        std.mem.copy(ntt.RqTq(pd), &u_hat[i], &u[i]);
    }
    var w_hat = ntt.RqTq(pd){};
    for (0..pd.k) |i| {
        var temp = ntt.RqTq(pd){};
        for (0..pd.n) |j| {
            temp[j] = @as(u16, @intCast(@mod(@as(u32, s_hat[i][j]) * @as(u32, u_hat[i][j]), pd.q)));
        }
        for (0..pd.n) |j| {
            w_hat[j] = @as(u16, @intCast(@mod(@as(u32, w_hat[j]) + @as(u32, temp[j]), pd.q)));
        }
    }
    var w = ntt.RqTq(pd){};
    ntt.nttInverse(pd, &w_hat);
    std.mem.copy(u16, &w, &w_hat);
    for (0..pd.n) |i| {
        w[i] = @as(u16, @intCast(@mod(@as(i32,v[i]) - @as(i32, w[i]) + pd.q, pd.q)));
    }

    // 3. Decode message from w
    const message_bytes = try utils.polynomialToBytes(pd, &w);
    return message_bytes;
}

// Secure Key Destruction
pub fn destroyPrivateKey(sk: *PrivateKey) void {
    // ... securely zero out and deallocate private key data
	// Securely zero out the private key polynomial
    secureZero(u16, sk.s);
    sk.arena.deinit(); // Free all memory allocated by the arena, including sk.s
    // Zero out other sensitive data if needed
}

pub fn destroyPublicKey(pk: *PublicKey) void {
	secureZero(u8, pk.t);       // Zero out the sensitive polynomial t
	//pk.arena.deinit();  // Free the memory occupied by t (and the arena itself)
}

const expectError = std.testing.expectError;

test "kpke keygen generates keys" {
    // Use a compile-time known parameter instead of a runtime value
    const pd = comptime params.Params.kem768.get(); // Use comptime
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    _ = try keygen(pd, allocator);
}

test "k-pke encrypt and decrypt are inverses" {
    // Use comptime here as well
    const pd = comptime params.Params.kem768.get(); // Use comptime
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const result = try keygen(pd, allocator);
    const pk = result[0];
    var sk = result[1];
    defer destroyPrivateKey(&sk);
    
    const message = "this is my message";
    const ciphertext = try encrypt(pd, pk, message, allocator);
    defer allocator.free(ciphertext);
    
    const decrypted = try decrypt(pd, sk, ciphertext, allocator);
    defer allocator.free(decrypted);
    
    try std.testing.expectEqualSlices(u8, message, decrypted);
}