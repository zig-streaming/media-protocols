const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const media = b.dependency("media", .{ .target = target, .optimize = optimize });

    const rtp = b.addModule("rtp", .{
        .root_source_file = b.path("src/rtp/rtp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "media", .module = media.module("media") },
        },
    });

    const sdp = b.addModule("sdp", .{
        .root_source_file = b.path("src/sdp/sdp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const rtsp = b.addModule("rtsp", .{
        .root_source_file = b.path("src/rtsp/rtsp.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "rtp", .module = rtp },
        },
    });

    const mod = b.addModule("protocols", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "rtp", .module = rtp },
            .{ .name = "sdp", .module = sdp },
            .{ .name = "rtsp", .module = rtsp },
        },
    });

    {
        const rtp_tests = b.addTest(.{ .root_module = rtp });
        const run_rtp_tests = b.addRunArtifact(rtp_tests);

        const sdp_tests = b.addTest(.{ .root_module = sdp });
        const run_sdp_tests = b.addRunArtifact(sdp_tests);

        const rtsp_tests = b.addTest(.{ .root_module = rtsp });
        const run_rtsp_tests = b.addRunArtifact(rtsp_tests);

        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&run_rtp_tests.step);
        test_step.dependOn(&run_sdp_tests.step);
        test_step.dependOn(&run_rtsp_tests.step);
    }

    {
        const bench_step = b.step("bench", "Run all benchmarks");

        const benches = .{
            .{ .name = "rtp_packet", .src = "bench/rtp/packet.zig" },
            .{ .name = "sdp_session", .src = "bench/sdp/session.zig" },
        };

        inline for (benches) |bench| {
            const bench_exe = b.addExecutable(.{
                .name = bench.name,
                .root_module = b.createModule(.{
                    .root_source_file = b.path(bench.src),
                    .target = target,
                    .optimize = .ReleaseFast,
                    .imports = &.{
                        .{ .name = "rtp", .module = rtp },
                        .{ .name = "sdp", .module = sdp },
                    },
                }),
            });

            const run = b.addRunArtifact(bench_exe);
            const single_step = b.step("bench-" ++ bench.name, "Run " ++ bench.name ++ " benchmark");
            single_step.dependOn(&run.step);
            bench_step.dependOn(&run.step);
        }
    }
}
