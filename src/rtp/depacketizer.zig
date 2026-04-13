const std = @import("std");
const media = @import("media");
const Packet = @import("packet.zig");

const Depacketizer = @This();
const initial_capacity = 8192;

allocator: std.mem.Allocator,
impl: *anyopaque,
vtable: *const VTable,
buffer: []u8,

last_timestamp: ?u32 = null,
offset: usize = 0,

pub const InitOptions = struct {
    initial_capacity: usize = initial_capacity,
};

const Error = error{Err};

pub const VTable = struct {
    depacketize: *const fn (*anyopaque, []const u8, []u8) anyerror!?usize,
};

pub fn init(allocator: std.mem.Allocator, impl: anytype, init_options: InitOptions) !Depacketizer {
    const T = std.meta.Child(@TypeOf(impl));

    return .{
        .impl = impl,
        .allocator = allocator,
        .buffer = try allocator.alloc(u8, init_options.initial_capacity),
        .vtable = &.{
            .depacketize = @ptrCast(&@field(T, "depacketize")),
        },
    };
}

pub fn deinit(self: *Depacketizer) void {
    self.allocator.free(self.buffer);
}

pub fn depacketize(self: *Depacketizer, rtp: Packet) !?media.Packet {
    while (true) {
        const written = self.vtable.depacketize(self.impl, rtp.payload, self.buffer[self.offset..]) catch |err| switch (err) {
            error.ShortBuffer => {
                self.buffer = try self.allocator.realloc(self.buffer, self.buffer.len * 2);
                continue;
            },
            else => return err,
        };

        if (written) |size| self.offset += size;

        if (rtp.header.marker) {
            const media_packet: media.Packet = .{
                .data = self.buffer[0..self.offset],
                .dts = rtp.header.timestamp,
                .pts = rtp.header.timestamp,
            };

            self.offset = 0;
            return media_packet;
        }

        break;
    }

    return null;
}
