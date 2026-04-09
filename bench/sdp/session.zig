const std = @import("std");
const Session = @import("sdp").Session;

// Minimal SDP session (no media)
const minimal_sdp =
    \\v=0
    \\o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
    \\s=SDP Seminar
    \\t=0 0
    \\
;

// Full SDP session with connection, attributes, and multiple media descriptions
const full_sdp =
    \\v=0
    \\o=jdoe 3724394400 3724394405 IN IP4 198.51.100.1
    \\s=Call to John Smith
    \\i=SDP Offer #1
    \\u=http://www.jdoe.example.com/home.html
    \\e=Jane Doe <jane@jdoe.example.com>
    \\p=+1 617 555-6011
    \\c=IN IP4 198.51.100.1
    \\t=0 0
    \\a=candidate:0 1 UDP 2113667327 203.0.113.1 54400 typ host
    \\a=recvonly
    \\m=audio 49170 RTP/AVP 0
    \\m=audio 49180 RTP/AVP 0
    \\m=video 51372 RTP/AVP 99
    \\c=IN IP6 2001:db8::2
    \\a=rtpmap:99 h263-1998/90000
    \\
;

const iterations = 1_000_000;

pub fn main() !void {
    var buffer: [1024]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);

    try stdout.interface.writeAll("\x1b[1;36m┌──────────────────────────────┐\x1b[0m\n");
    try stdout.interface.writeAll("\x1b[1;36m│  SDP Session Parse Benchmarks│\x1b[0m\n");
    try stdout.interface.writeAll("\x1b[1;36m└──────────────────────────────┘\x1b[0m\n\n");

    // Warm-up: one pass to bring code/data into cache.
    for (0..iterations) |_| {
        const session = try Session.parse(minimal_sdp);
        std.mem.doNotOptimizeAway(session);
    }

    const fixtures = [_]struct {
        name: []const u8,
        data: []const u8,
    }{
        .{ .name = "Minimal (no media)", .data = minimal_sdp },
        .{ .name = "Full (3 media)", .data = full_sdp },
    };

    for (fixtures) |fixture| {
        try benchMark(fixture.name, fixture.data, &stdout.interface);
    }

    try stdout.interface.flush();
}

fn benchMark(name: []const u8, data: []const u8, writer: *std.Io.Writer) !void {
    var timer = try std.time.Timer.start();

    for (0..iterations) |_| {
        const session = try Session.parse(data);

        var attr_iter = session.attributeIterator();
        while (try attr_iter.next()) |attr| {
            std.mem.doNotOptimizeAway(attr);
        }

        var media_iter = session.mediaIterator();
        while (try media_iter.next()) |media| {
            var media_attr_iter = media.attributeIterator();
            while (try media_attr_iter.next()) |attr| {
                std.mem.doNotOptimizeAway(attr);
            }
        }
    }

    const elapsed_ns = timer.read();
    const ns_per_op = elapsed_ns / iterations;
    const ops_per_sec = @as(u64, std.time.ns_per_s) / @max(ns_per_op, 1);

    try writer.print("\x1b[1;33mSDP Session {s}\x1b[0m\n" ++
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
