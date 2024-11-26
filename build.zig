//build.zig
const std = @import("std");

const test_targets = [_]std.Target.Query{
    .{}, // native
    // .{
    //     .cpu_arch = .x86_64,
    //     .os_tag = .linux,
    // },
    // .{
    //     .cpu_arch = .aarch64,
    //     .os_tag = .macos,
    // },
};

pub fn build(b: *std.Build) void {
    // Standard target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
	
    const zips = b.addStaticLibrary(.{
        .name = "zips",
        .root_source_file = b.path("src/kem.zig"),
        .target = target,
		.optimize = optimize,
    });
    //zips.linkLibC();

    if (b.option(bool, "enable-demo", "install the demo too") orelse false) {
	    const zipsexample = b.addExecutable(.{
			.name = "zipsexample",
			.root_source_file = b.path("example.zig"),
			.target = target,
			.optimize = optimize,
		});
		zipsexample.linkLibrary(zips);
		b.installArtifact(zipsexample);
    }

	if (b.release_mode == .off) {
        if (b.option(bool, "test-deps", "Fetch test dependencies") orelse false) {
		    const test_step = b.step("test", "Run unit tests");
			for (test_targets) |test_target| {
				const unit_tests = b.addTest(.{
					.root_source_file = b.path("kem.zig"),
					.target = b.resolveTargetQuery(test_target),
				});
				const run_unit_tests = b.addRunArtifact(unit_tests);
				run_unit_tests.skip_foreign_checks = true;
				test_step.dependOn(&run_unit_tests.step);
			}
        } else {
			std.debug.print("Not fetching or running tests because '-Dtest-deps' was not provided.\n", .{});
		}
	} else {
		std.debug.print("Building in Release Mode.\n", .{});
	}

    // Generate documentation
    //const doc_step = b.step("doc", "Generate documentation for kem library");
    //const kem_doc = b.addDocTest("src/kem.zig");
    //kem_doc.setTarget(target);
    //doc_step.dependOn(&kem_doc.step);
	
	std.debug.print("Build complete.\n", .{});
}