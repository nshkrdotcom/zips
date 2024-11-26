//params.zig
const std = @import("std");

pub const Params = enum {
    kem512,
    kem768,
    kem1024,

    pub fn get(self: Params) ParamDetails {
        return switch (self) {
            .kem512 => .{
                .k = 2,
                .eta1 = 3,
                .eta2 = 2,
                .du = 10,
                .dv = 4,
                .n = 256,
                .q = 3329, // Add n and q
                .publicKeyBytes = 800, .privateKeyBytes = 1632, .ciphertextBytes = 768,
            },
            .kem768 => .{
                .k = 3,
                .eta1 = 2,
                .eta2 = 2,
                .du = 10,
                .dv = 4,
                 .n = 256,
                .q = 3329,
                .publicKeyBytes = 1184, .privateKeyBytes = 2400, .ciphertextBytes = 1088,
            },
            .kem1024 => .{
                .k = 4,
                .eta1 = 2,
                .eta2 = 2,
                .du = 11,
                .dv = 5,
                 .n = 256,
                .q = 3329,
                .publicKeyBytes = 1568, .privateKeyBytes = 3168, .ciphertextBytes = 1568,
            },
        };
    }
};

pub const ParamDetails = struct {
    k: u8,
    eta1: u8,
    eta2: u8,
    du: u8,
    dv: u8,
    n: u16,     // Add n
    q: u16,     // Add q
    publicKeyBytes: usize,
    privateKeyBytes: usize,
    ciphertextBytes: usize,
};

// Test cases (for TDD)
const expect = std.testing.expect;
test "params.kem512" {
    const params = Params.kem512.get();
    try expect(params.k == 2);
    try expect(params.eta1 == 3);
    try expect(params.eta2 == 2);
    try expect(params.du == 10);
    try expect(params.dv == 4);
    try expect(params.n == 256);
    try expect(params.q == 3329);
    try expect(params.publicKeyBytes == 800);
    try expect(params.privateKeyBytes == 1632);
    try expect(params.ciphertextBytes == 768);
}

test "params.kem768" {
     const params = Params.kem768.get();
    try expect(params.k == 3);
    try expect(params.eta1 == 2);
    try expect(params.eta2 == 2);
    try expect(params.du == 10);
    try expect(params.dv == 4);
    try expect(params.n == 256);
    try expect(params.q == 3329);
    try expect(params.publicKeyBytes == 1184);
    try expect(params.privateKeyBytes == 2400);
    try expect(params.ciphertextBytes == 1088);
}

test "params.kem1024" {
     const params = Params.kem1024.get();
    try expect(params.k == 4);
    try expect(params.eta1 == 2);
    try expect(params.eta2 == 2);
    try expect(params.du == 11);
    try expect(params.dv == 5);
    try expect(params.n == 256);
    try expect(params.q == 3329);
    try expect(params.publicKeyBytes == 1568);
    try expect(params.privateKeyBytes == 3168);
    try expect(params.ciphertextBytes == 1568);
}