//! Describes an RTP packet.
const std = @import("std");

const Reader = std.Io.Reader;
const Self = @This();

pub const Error = error{EndOfStream};

/// Describes an RTP header.
pub const Header = packed struct {
    ssrc: u32,
    timestamp: u32,
    sequence_number: u16,
    payload_type: u7,
    marker: bool,
    csrc_count: u4 = 0,
    extension: bool,
    padding: bool,
    version: u2 = 2,
};

/// Describes an RTP Extension
pub const Extension = struct {
    profile: u16,
    data: []const u8,

    fn parse(reader: *Reader) !Extension {
        const profile = reader.takeInt(u16, .big) catch return error.EndOfStream;
        const extension_size = (reader.takeInt(u16, .big) catch return error.EndOfStream) * 4;
        const ext_data = reader.take(extension_size) catch return error.EndOfStream;

        return .{
            .profile = profile,
            .data = ext_data,
        };
    }
};

header: Header,
csrc_list: []align(1) const u32 = &.{},
extension: ?Extension = null,
payload: []const u8,
padding_size: u8 = 0,

/// Parses RTP Packet from slice
pub fn parse(data: []const u8) Error!Self {
    var reader = std.Io.Reader.fixed(data);
    var packet: Self = .{
        .header = undefined,
        .payload = &.{},
    };

    packet.header = reader.takeStruct(Header, .big) catch return error.EndOfStream;
    const csrc_count = reader.take(@as(usize, packet.header.csrc_count) * 4) catch return error.EndOfStream;
    packet.csrc_list = std.mem.bytesAsSlice(u32, csrc_count);

    if (packet.header.extension) packet.extension = try .parse(&reader);

    if (packet.header.padding) {
        if (reader.seek >= data.len or data[data.len - 1] + reader.seek > data.len) {
            @branchHint(.unlikely);
            return error.EndOfStream;
        }

        packet.padding_size = data[data.len - 1];
    }
    packet.payload = data[reader.seek .. reader.end - packet.padding_size];

    return packet;
}

pub fn format(self: Self, writer: *std.Io.Writer) !void {
    try writer.writeAll("RTP Packet:\n");
    try writer.writeAll("\tVersion: ");
    try writer.print("{d}\n", .{self.header.version});
    try writer.writeAll("\tMarker: ");
    try writer.print("{}\n", .{self.header.marker});
    try writer.writeAll("\tPayload Type: ");
    try writer.print("{d}\n", .{self.header.payload_type});
    try writer.writeAll("\tSequence Number: ");
    try writer.print("{d}\n", .{self.header.sequence_number});
    try writer.writeAll("\tTimestamp: ");
    try writer.print("{d}\n", .{self.header.timestamp});
    try writer.writeAll("\tSSRC: ");
    try writer.print("{d}\n", .{self.header.ssrc});
    try writer.writeAll("\tPayload Size: ");
    try writer.print("{d} bytes\n", .{self.payload.len});
}

test "parse packet" {
    const rtp_packet: [16]u8 = [_]u8{
        0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF,
        0x22, 0x54, 0xA7, 0xD4, 0xF3, 0x01, 0x02,
        0x03, 0x04,
    };

    const packet = try Self.parse(rtp_packet[0..]);

    try std.testing.expect(packet.header.version == 2);
    try std.testing.expect(!packet.header.padding);
    try std.testing.expect(!packet.header.extension);
    try std.testing.expect(packet.header.csrc_count == 0);
    try std.testing.expect(packet.header.marker);
    try std.testing.expect(packet.header.payload_type == 96);
    try std.testing.expect(packet.header.sequence_number == 0x51A4);
    try std.testing.expect(packet.header.timestamp == 0x000DDF22);
    try std.testing.expect(packet.header.ssrc == 0x54A7D4F3);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04 }, packet.payload);
}

test "packet too short" {
    const short_packet: [10]u8 = [_]u8{ 0x80, 0xE0, 0x51, 0xA4, 0x00, 0x0D, 0xDF, 0x22, 0x54, 0xA7 };

    const result = Self.parse(short_packet[0..]);
    try std.testing.expectError(Error.EndOfStream, result);
}

test "packet with csrc" {
    const packet = [_]u8{
        0x83, 0x6F, 0x41, 0xFF, 0xD2,
        0x14, 0x8B, 0xBA, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30,
        0x7F, 0x37, 0xB8, 0x30, 0x7E,
        0x37, 0xB8, 0x30, 0x73, 0x00,
        0x00, 0x05, 0x00, 0x09,
    };

    const csrc_list: []align(1) const u32 = std.mem.bytesAsSlice(u32, packet[12..24]);

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.csrc_count == 3);

    for (csrc_list, parsed_packet.csrc_list) |csrc, parsed_csrc| {
        try std.testing.expect(csrc == parsed_csrc);
    }
}

test "packet with extension" {
    const packet = [_]u8{
        0x90, 0x6F, 0x41, 0xFF, 0xD2, 0x14,
        0x8B, 0xBA, 0x37, 0xB8, 0x30, 0x7F,
        0xBD, 0xDE, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x09,
    };

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.extension);
    try std.testing.expect(parsed_packet.extension.?.profile == 0xBDDE);
    try std.testing.expectEqualSlices(u8, packet[16..28], parsed_packet.extension.?.data);
}

test "packet with padding" {
    const packet = [_]u8{
        0xB3, 0x6F, 0x41, 0xFF, 0xD2, 0x14, 0x8B,
        0xBA, 0x37, 0xB8, 0x30, 0x7F, 0x37, 0xB8,
        0x30, 0x7F, 0x37, 0xB8, 0x30, 0x7E, 0x37,
        0xB8, 0x30, 0x73, 0xBD, 0xDE, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x09, 0x00, 0x00, 0x00, 0x04,
    };

    const parsed_packet = try Self.parse(packet[0..]);
    try std.testing.expect(parsed_packet.header.padding);
    try std.testing.expect(parsed_packet.padding_size == 4);
}
