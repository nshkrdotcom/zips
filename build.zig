const std = @import("std");
const Builder = std.build.Builder;

pub fn build(b: *Builder) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Executable - Example Usage
    const example = b.addExecutable("mlkem_example", "example.zig");
    example.setTarget(target);
    example.setOptimize(optimize);
    example.addPackagePath("kem", .{ .path = "src/kem.zig" });
    example.linkLibC(); // Link libc if needed

    // Library - ML-KEM
    const libkem = b.addStaticLibrary("kem", "src/kem.zig");
    libkem.setTarget(target);
    libkem.setOptimize(optimize);

    // Add source files to the library (order matters for dependencies)
    libkem.addSourceFile("src/mlkem.zig");
    libkem.addSourceFile("src/kpke.zig");
    libkem.addSourceFile("src/ntt.zig");
    libkem.addSourceFile("src/cbd.zig");
    libkem.addSourceFile("src/utils.zig"); // Might be smaller now
    libkem.addSourceFile("src/params.zig");
    libkem.addSourceFile("src/rng.zig"); // Minimal for error handling
    libkem.addSourceFile("src/error.zig");


    // Link the library to the example
    example.addDependency(libkem);

    // Tests
    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{
        "test/mlkem_test.zig",
        "test/kpke_test.zig",
        "test/ntt_test.zig",
        "test/cbd_test.zig",
        "test/utils_test.zig", // If still applicable
        // ... other tests ...
    };

    for (test_files) |test_file| {
        const test = b.addTest(test_file);
        test.setTarget(target);
        test.setOptimize(optimize);
        test.addPackagePath("kem", .{ .path = "src/kem.zig" });
        test_step.addTest(test);
    }

     // Install Header (Optional)
    // const install_header_step = b.step("install_header", "Install the header file to the zig std path so other packages can easily depend on it.");
    // const zig_lib_path = std.zig.getZigLibDir();
    // // Create the std/kem directory and parent std directory if they don't exist.
    // // See https://github.com/ziglang/zig/issues/14895.
    // try std.fs.cwd().makePath(zig_lib_path ++ "/std");
    // try std.fs.cwd().makePath(zig_lib_path ++ "/std/kem");

    // const install_header = b.addInstallArtifact(
    //     "kem_h",
    //     .{ .path = "src/kem.zig", .mode = .0644 },
    // );
    // install_header.setDestinationPath(zig_lib_path ++ "/std/kem/kem.zig");
    // install_header_step.dependOn(&install_header.step);



    // Generate documentation
    const doc_step = b.step("doc", "Generate documentation for kem library");
    const kem_doc = b.addDocTest("src/kem.zig");
    kem_doc.setTarget(target);
    doc_step.dependOn(&kem_doc.step);


}