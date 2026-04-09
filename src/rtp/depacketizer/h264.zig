const std = @import("std");

const Self = @This();
const Writer = std.Io.Writer;

const annexb_start_code = @import("core").h264.annexb_start_code;
const fu_header_size: usize = 2;
const stapa_length_size: usize = 2;

pub const PacketType = enum { annexb, avc };

pub const Error = error{ ShortBuffer, UnsupportedNalType, InvalidFUAPacket, InvalidStapAPacket, UnsupportedPacketType };

packet_type: PacketType = .annexb,
fu_started: bool = false,
fu_offset: usize = 0,

/// Initializes a new H264 depacketizer with the specified packet type.
pub fn init(packet_type: PacketType) Self {
    return .{ .packet_type = packet_type };
}

/// Depacketizes an H264 RTP packet and writes it to the destination buffer.
///
/// Returns the number of bytes written in case the whole NAL units is written, null if more packets needed
/// or an error if the packet is invalid or the buffer is too small.
pub fn depacketize(self: *Self, payload: []const u8, dest: []u8) !?usize {
    switch (payload[0] & 0x1F) {
        // Single NAL Unit Packet
        1...21 => {
            if (dest.len < payload.len + annexb_start_code.len) {
                return Error.ShortBuffer;
            }
            self.writePrefix(dest, payload.len);
            @memcpy(dest[annexb_start_code.len .. annexb_start_code.len + payload.len], payload);
            return payload.len + annexb_start_code.len;
        },
        // STAP-A Packet
        24 => {
            @branchHint(.unlikely);
            var slice = payload[1..];
            var offset: usize = 0;

            while (slice.len > 0) {
                if (slice.len < stapa_length_size) {
                    return error.InvalidStapAPacket;
                }

                const nal_size = std.mem.readInt(u16, slice[0..stapa_length_size], .big);
                slice = slice[stapa_length_size..];
                if (slice.len < nal_size) return error.InvalidStapAPacket;
                if (dest.len < offset + nal_size + annexb_start_code.len) return Error.ShortBuffer;

                self.writePrefix(dest[offset .. offset + annexb_start_code.len], nal_size);
                offset += annexb_start_code.len;
                @memcpy(dest[offset .. offset + nal_size], slice[0..nal_size]);
                offset += nal_size;

                slice = slice[nal_size..];
            }

            return offset;
        },
        // FU-A Packet
        28 => {
            @branchHint(.likely);
            const start_bit = payload[1] & 0x80 != 0;
            const end_bit = payload[1] & 0x40 != 0;

            if (start_bit and self.fu_started or end_bit and !self.fu_started) return error.InvalidFUAPacket;
            const expected_size = blk: {
                const size = payload.len - fu_header_size;
                if (start_bit) {
                    self.fu_started = true;
                    self.fu_offset = annexb_start_code.len + 1;
                    break :blk size + annexb_start_code.len + 1;
                }
                break :blk size;
            };

            if (dest.len < self.fu_offset + expected_size) return error.ShortBuffer;
            @memcpy(dest[self.fu_offset .. self.fu_offset + payload.len - fu_header_size], payload[fu_header_size..]);
            self.fu_offset += payload.len - fu_header_size;

            if (end_bit) {
                const nri = (payload[0] >> 5) & 0x03;
                self.writePrefix(dest[0..], self.fu_offset - annexb_start_code.len);
                dest[annexb_start_code.len] = (nri << 5) | (payload[1] & 0x1F);

                const result = self.fu_offset;
                self.fu_started = false;
                self.fu_offset = 0;
                return result;
            }

            return null;
        },
        else => return error.UnsupportedNalType,
    }
}

fn writePrefix(self: *Self, slice: []u8, nal_size: usize) void {
    switch (self.packet_type) {
        .annexb => @memcpy(slice[0..annexb_start_code.len], &annexb_start_code),
        .avc => std.mem.writeInt(u32, slice[0..annexb_start_code.len], @intCast(nal_size), .big),
    }
}

test "Depacketize Single NAL Unit Packet" {
    var depacketizer: Self = .init(.annexb);

    const nal_unit: [5]u8 = [_]u8{ 0x65, 0x88, 0x84, 0x21, 0xA0 };
    const expected = [_]u8{ 0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0 };
    var buffer: [1024]u8 = undefined;

    const written = try depacketizer.depacketize(&nal_unit, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expectEqual(9, written.?);
    try std.testing.expectEqualSlices(u8, &expected, buffer[0..written.?]);
}

test "Depacketize StapA" {
    var buffer: [1024]u8 = undefined;
    var depacketizer: Self = .init(.annexb);

    const stap_a_packet: [13]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x05, // NALU 1 size
        0x65, 0x88, 0x84, 0x21, 0xA0, // NALU 1 (IDR frame)
        0x00, 0x03, // NALU 2 size
        0x41, 0x9A, 0x22, // NALU 2 (non-IDR frame)
    };

    const expected = &[_]u8{
        0x00, 0x00, 0x00, 0x01, 0x65, 0x88, 0x84, 0x21, 0xA0,
        0x00, 0x00, 0x00, 0x01, 0x41, 0x9A, 0x22,
    };

    // Alloc
    const written = try depacketizer.depacketize(&stap_a_packet, &buffer);

    try std.testing.expect(written != null);
    try std.testing.expectEqual(expected.len, written.?);
    try std.testing.expectEqualSlices(u8, expected, buffer[0..written.?]);
}

test "Invalid StapA packet" {
    var buffer: [1024]u8 = undefined;
    var depacketizer: Self = .init(.annexb);

    const invalid_stap_a_packet: [12]u8 = [_]u8{
        24, // STAP-A NAL unit type
        0x00, 0x05, // NALU size (5 bytes)
        0x65, 0x88, 0x84, 0x21, 0xA0, // NALU 1 (IDR frame)
        0x00, 0x03, // NALU 2 size
        0x41, 0x9A, // Wrong size
    };

    const written = depacketizer.depacketize(&invalid_stap_a_packet, &buffer);
    try std.testing.expectError(Error.InvalidStapAPacket, written);
}
