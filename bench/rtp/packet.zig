const std = @import("std");
const Packet = @import("rtp").Packet;

// Basic RTP packet (no CSRC, no extension, no padding)
const basic_packet = [_]u8{
    0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF,
    0x22, 0x54, 0xA7, 0xD4, 0xF3, 0x01, 0x02,
    0x03, 0x04,
};

// Packet with 3 CSRC entries
const csrc_packet = [_]u8{
    0x83, 0x6F, 0x41, 0xFF, 0xD2,
    0x14, 0x8B, 0xBA, 0x37, 0xB8,
    0x30, 0x7F, 0x37, 0xB8, 0x30,
    0x7F, 0x37, 0xB8, 0x30, 0x7E,
    0x37, 0xB8, 0x30, 0x73, 0x00,
    0x00, 0x05, 0x00, 0x09,
};

// Packet with header extension
const extension_packet = [_]u8{
    0x90, 0x6F, 0x41, 0xFF, 0xD2, 0x14,
    0x8B, 0xBA, 0x37, 0xB8, 0x30, 0x7F,
    0xBD, 0xDE, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x09,
};

// Packet with padding
const padding_packet = [_]u8{
    0xB3, 0x6F, 0x41, 0xFF, 0xD2, 0x14, 0x8B,
    0xBA, 0x37, 0xB8, 0x30, 0x7F, 0x37, 0xB8,
    0x30, 0x7F, 0x37, 0xB8, 0x30, 0x7E, 0x37,
    0xB8, 0x30, 0x73, 0xBD, 0xDE, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04,
};

const iterations = 1_000_000;

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);

    try stdout.interface.writeAll("\x1b[1;36m┌──────────────────────────┐\x1b[0m\n");
    try stdout.interface.writeAll("\x1b[1;36m│   RTP Packet Benchmarks  │\x1b[0m\n");
    try stdout.interface.writeAll("\x1b[1;36m└──────────────────────────┘\x1b[0m\n\n");

    // Warm-up: one pass to bring code/data into cache.
    for (0..iterations) |_| {
        const packet = try Packet.parse(&basic_packet);
        std.mem.doNotOptimizeAway(packet);
    }

    const fixtures = [_]struct {
        name: []const u8,
        data: []const u8,
    }{
        .{ .name = "Basic", .data = &basic_packet },
        .{ .name = "With CSRC", .data = &csrc_packet },
        .{ .name = "With Extension", .data = &extension_packet },
        .{ .name = "With Padding", .data = &padding_packet },
    };

    for (fixtures) |fixture| {
        try benchMark(fixture.name, fixture.data, &stdout.interface);
    }

    try stdout.interface.flush();
}

fn benchMark(name: []const u8, data: []const u8, writer: *std.Io.Writer) !void {
    var timer = try std.time.Timer.start();

    for (0..iterations) |_| {
        const packet = try Packet.parse(data);
        std.mem.doNotOptimizeAway(packet);
    }

    const elapsed_ns = timer.read();
    const ns_per_op = elapsed_ns / iterations;
    const ops_per_sec = @as(u64, std.time.ns_per_s) / @max(ns_per_op, 1);

    try writer.print("\x1b[1;33mRTP Packet {s}\x1b[0m\n" ++
        "  iterations : {d}\n" ++
        "  total time : {d} ms\n" ++
        "  ns/op      : {d}\n" ++
        "  ops/sec    : {d}\n\n", .{
        name,
        iterations,
        elapsed_ns / std.time.ns_per_ms,
        ns_per_op,
        ops_per_sec,
    });
}
