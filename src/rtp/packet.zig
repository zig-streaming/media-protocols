const std = @import("std");

const Reader = std.Io.Reader;
const Self = @This();

pub const Error = error{EndOfStream};

/// RTP Packet Structure
pub const Header = struct {
    version: u2,
    padding: bool,
    extension: bool,
    csrc_count: u4,
    marker: bool,
    payload_type: u7,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    csrc_list: []align(1) const u32,
    extension_profile: ?u16 = null,
    extensions: ?[]const u8 = null,
    padding_size: u8 = 0,
    size: usize,

    /// Parse RTP Header from byte slice
    pub fn parse(data: []const u8) Reader.Error!Header {
        var reader = Reader.fixed(data);
        const bytes = try reader.take(2);

        var header: Header = .{
            .version = @intCast(bytes[0] >> 6),
            .padding = bytes[0] & 0x20 != 0,
            .marker = bytes[1] & 0x80 != 0,
            .payload_type = @intCast(bytes[1] & 0x7F),
            .extension = bytes[0] & 0x10 != 0,
            .sequence_number = try reader.takeInt(u16, .big),
            .timestamp = try reader.takeInt(u32, .big),
            .ssrc = try reader.takeInt(u32, .big),
            .csrc_count = @intCast(bytes[0] & 0x0F),
            .csrc_list = undefined,
            .size = 0,
        };

        header.csrc_list = std.mem.bytesAsSlice(u32, try reader.take(@as(usize, header.csrc_count) * 4));

        if (header.extension) {
            header.extension_profile = try reader.takeInt(u16, .big);
            const extension_size = try reader.takeInt(u16, .big) * 4;
            header.extensions = try reader.take(extension_size);
        }

        header.size = reader.seek;
        return header;
    }
};

header: Header,
payload: []const u8,

/// Parses RTP Packet from slice
pub fn parse(data: []const u8) Error!Self {
    var header = Header.parse(data) catch |err| switch (err) {
        error.EndOfStream => return error.EndOfStream,
        else => unreachable,
    };

    if (header.padding) {
        if (header.size >= data.len or data[data.len - 1] + header.size > data.len) {
            @branchHint(.unlikely);
            return error.EndOfStream;
        }

        header.padding_size = data[data.len - 1];
    }

    return .{
        .header = header,
        .payload = data[header.size .. data.len - header.padding_size],
    };
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

    for (csrc_list, parsed_packet.header.csrc_list) |csrc, parsed_csrc| {
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
    try std.testing.expect(parsed_packet.header.extension_profile == 0xBDDE);
    try std.testing.expectEqualSlices(u8, packet[16..28], parsed_packet.header.extensions.?);
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
    try std.testing.expect(parsed_packet.header.padding_size == 4);
}
