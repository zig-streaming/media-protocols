const std = @import("std");
const Connection = @import("connection.zig");
const AttributeIterator = @import("attribute.zig").AttributeIterator;
const Io = std.Io;

const Media = @This();

pub const MediaType = enum {
    audio,
    video,
    text,
    application,
};

pub const PortRange = struct {
    port: u16,
    count: u16,
};

media_type: MediaType,
port_range: PortRange,
protocol: []const u8,
formats: []const u8,
connection: ?Connection = null,
attributes: ?[]const u8 = null,

/// Get an iterator over the media attributes.
pub fn attributeIterator(self: *const Media) Media.AttributeIterator {
    return AttributeIterator{
        .reader = Io.Reader.fixed(self.attributes orelse ""),
    };
}
