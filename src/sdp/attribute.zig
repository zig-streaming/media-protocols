const std = @import("std");
const Reader = std.Io.Reader;

const Self = @This();

key: []const u8,
value: ?[]const u8,

/// An iterator over the attributes in an SDP message or media description.
/// Each attribute is represented as a key-value pair, where the key is the attribute name and
/// the value is the attribute value (if present).
pub const AttributeIterator = struct {
    reader: Reader,

    pub fn next(self: *AttributeIterator) !?Self {
        const line = self.reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => return null,
            else => return error.InvalidAttribute,
        };

        const trimmed_line = std.mem.trimEnd(u8, line, "\r\n")[2..]; // skip "a="
        if (std.mem.indexOfScalar(u8, trimmed_line, ':')) |idx| {
            return Self{
                .key = trimmed_line[0..idx],
                .value = trimmed_line[idx + 1 ..],
            };
        } else {
            return Self{
                .key = trimmed_line,
                .value = null,
            };
        }
    }
};

/// RTP mapping information, as specified in RFC 4566 section 6.
pub const RtpMap = struct {
    payload_type: u8,
    encoding: []const u8,
    clock_rate: u32,
    params: ?[]const u8,
};

/// Format parameters.
pub const Fmtp = struct {
    payload_type: u8,
    packetization_mode: ?u8 = null,
    profile_level_id: ?[]const u8 = null,
    sprop_parameter_sets: ?[]const u8 = null,
};

/// Check if this attribute is an "rtpmap" attribute.
pub fn isRtpMap(self: *const Self) bool {
    return std.mem.eql(u8, self.key, "rtpmap");
}

/// Check if this attribute is an "fmtp" attribute.
pub fn isFmtp(self: *const Self) bool {
    return std.mem.eql(u8, self.key, "fmtp");
}

/// Parse this attribute as an "rtpmap" attribute.
pub fn parseRtpMap(self: *const Self) !RtpMap {
    if (self.value == null) {
        return error.InvalidRtpMap;
    }

    const value = self.value.?;

    const idx = std.mem.indexOfScalar(u8, value, ' ') orelse return error.InvalidRtpMap;
    const payload_type = std.fmt.parseInt(u8, value[0..idx], 10) catch return error.InvalidRtpMap;

    var iterator = std.mem.splitScalar(u8, std.mem.trim(u8, value[idx + 1 ..], " \t"), '/');
    var part: []const u8 = undefined;

    const encoding = iterator.next() orelse return error.InvalidRtpMap;

    part = iterator.next() orelse return error.InvalidRtpMap;
    const clock_rate = std.fmt.parseInt(u32, part, 10) catch return error.InvalidRtpMap;
    const params = iterator.next();

    return RtpMap{
        .payload_type = payload_type,
        .encoding = encoding,
        .clock_rate = clock_rate,
        .params = params,
    };
}

/// Parse this attribute as an "fmtp" attribute.
pub fn parseFmtp(self: *const Self) !Fmtp {
    if (self.value == null) {
        return error.InvalidFmtp;
    }

    if (std.mem.indexOfScalar(u8, self.value.?, ' ')) |idx| {
        const payload_type = std.fmt.parseInt(u8, self.value.?[0..idx], 10) catch return error.InvalidFmtp;
        const params = self.value.?[idx + 1 ..];

        var result = Fmtp{
            .payload_type = payload_type,
        };

        var iterator = std.mem.splitScalar(u8, params, ';');
        while (iterator.next()) |key_value| {
            if (std.mem.indexOfScalar(u8, key_value, '=')) |param_idx| {
                const key = std.mem.trimStart(u8, key_value[0..param_idx], " ");
                const value = key_value[param_idx + 1 ..];

                if (std.mem.eql(u8, key, "profile-level-id")) {
                    result.profile_level_id = value;
                } else if (std.mem.eql(u8, key, "sprop-parameter-sets")) {
                    result.sprop_parameter_sets = value;
                } else if (std.mem.eql(u8, key, "packetization-mode")) {
                    result.packetization_mode = std.fmt.parseInt(u8, value, 10) catch return error.InvalidFmtp;
                }
            }
        }

        return result;
    }

    return error.InvalidFmtp;
}

test "attribute parsing" {
    const input =
        \\a=rtpmap:96 opus/48000/2
        \\a=sendrecv
        \\a=fmtp:96 minptime=10;useinbandfec=1
        \\
    ;
    var iter = AttributeIterator{ .reader = Reader.fixed(input) };

    var part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("rtpmap", part.?.key);
    try std.testing.expectEqualStrings("96 opus/48000/2", part.?.value.?);

    part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("sendrecv", part.?.key);
    try std.testing.expect(part.?.value == null);

    part = try iter.next();
    try std.testing.expect(part != null);
    try std.testing.expectEqualStrings("fmtp", part.?.key);
    try std.testing.expectEqualStrings("96 minptime=10;useinbandfec=1", part.?.value.?);

    part = try iter.next();
    try std.testing.expect(part == null);
}

test "parse RtmMap" {
    const attribute = Self{
        .key = "rtpmap",
        .value = "96 opus/48000/2",
    };

    const rtpmap = try attribute.parseRtpMap();
    try std.testing.expect(rtpmap.payload_type == 96);
    try std.testing.expectEqualStrings("opus", rtpmap.encoding);
    try std.testing.expect(rtpmap.clock_rate == 48000);
    try std.testing.expect(rtpmap.params != null);
    try std.testing.expectEqualStrings("2", rtpmap.params.?);
}

test "parse invalid RtmMap" {
    const attribute = Self{
        .key = "rtpmap",
        .value = "97 opus/4800q/2",
    };

    try std.testing.expectError(error.InvalidRtpMap, attribute.parseRtpMap());
}

test "parse Fmtp" {
    const attribute = Self{
        .key = "fmtp",
        .value = "96 packetization-mode=1; profile-level-id=458723; level-asymmetry-allowed=1",
    };

    const fmtp = try attribute.parseFmtp();
    try std.testing.expect(fmtp.payload_type == 96);

    try std.testing.expect(fmtp.profile_level_id != null);
    try std.testing.expectEqualStrings("458723", fmtp.profile_level_id.?);

    try std.testing.expect(fmtp.packetization_mode != null);
    try std.testing.expect(fmtp.packetization_mode.? == 1);
}
