const std = @import("std");
const zbench = @import("zbench");
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

fn parseMinimal(allocator: std.mem.Allocator) void {
    _ = allocator;
    parseSDP(minimal_sdp) catch unreachable;
}

fn parseFull(allocator: std.mem.Allocator) void {
    _ = allocator;
    parseSDP(full_sdp) catch unreachable;
}

fn parseSDP(data: []const u8) !void {
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

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const stdout: std.Io.File = .stdout();

    var bench = zbench.Benchmark.init(init.gpa, .{});
    defer bench.deinit();

    try bench.add("Parse Minimal SDP", parseMinimal, .{});
    try bench.add("Parse Full SDP", parseFull, .{});
    try bench.run(io, stdout);
}
