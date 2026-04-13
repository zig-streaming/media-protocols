const std = @import("std");

const Self = @This();

pub const NetType = enum { in };
pub const AddrType = enum { ip4, ip6 };

net_type: NetType,
addr_type: AddrType,
address: []const u8,

/// Parses a connection string in the format: "<net_type> <addr_type> <address>"
pub fn parse(buffer: []const u8) !Self {
    var parts = std.mem.splitAny(u8, buffer, " ");

    const net_type_str = parts.next() orelse return error.InvalidConnection;
    const addr_type_str = parts.next() orelse return error.InvalidConnection;
    const address_str = parts.next() orelse return error.InvalidConnection;

    const net_type = try parseNetType(net_type_str);
    const addr_type = try parseAddrType(addr_type_str);

    return Self{
        .net_type = net_type,
        .addr_type = addr_type,
        .address = address_str,
    };
}

pub fn parseNetType(input: []const u8) !NetType {
    if (std.mem.eql(u8, "IN", input)) {
        return .in;
    } else {
        return error.InvalidNetType;
    }
}

pub fn parseAddrType(input: []const u8) !AddrType {
    if (std.mem.eql(u8, "IP4", input)) {
        return .ip4;
    } else if (std.mem.eql(u8, "IP6", input)) {
        return .ip6;
    } else {
        return error.InvalidAddrType;
    }
}

test "parseNetType: valid IN" {
    const result = try parseNetType("IN");
    try std.testing.expectEqual(NetType.in, result);
}

test "parseNetType: invalid returns error" {
    try std.testing.expectError(error.InvalidNetType, parseNetType("OUT"));
    try std.testing.expectError(error.InvalidNetType, parseNetType(""));
    try std.testing.expectError(error.InvalidNetType, parseNetType("in"));
}

test "parseAddrType: valid IP4" {
    const result = try parseAddrType("IP4");
    try std.testing.expectEqual(AddrType.ip4, result);
}

test "parseAddrType: valid IP6" {
    const result = try parseAddrType("IP6");
    try std.testing.expectEqual(AddrType.ip6, result);
}

test "parseAddrType: invalid returns error" {
    try std.testing.expectError(error.InvalidAddrType, parseAddrType("IP5"));
    try std.testing.expectError(error.InvalidAddrType, parseAddrType(""));
    try std.testing.expectError(error.InvalidAddrType, parseAddrType("ip4"));
}

test "parse: IPv4 connection" {
    const result = try parse("IN IP4 192.168.1.1");
    try std.testing.expectEqual(NetType.in, result.net_type);
    try std.testing.expectEqual(AddrType.ip4, result.addr_type);
    try std.testing.expectEqualStrings("192.168.1.1", result.address);
}

test "parse: IPv6 connection" {
    const result = try parse("IN IP6 ::1");
    try std.testing.expectEqual(NetType.in, result.net_type);
    try std.testing.expectEqual(AddrType.ip6, result.addr_type);
    try std.testing.expectEqualStrings("::1", result.address);
}

test "parse: missing fields returns error" {
    try std.testing.expectError(error.InvalidConnection, parse("IN IP4"));
    try std.testing.expectError(error.InvalidConnection, parse("IN"));
    try std.testing.expectError(error.InvalidConnection, parse(""));
}

test "parse: invalid net_type returns error" {
    try std.testing.expectError(error.InvalidNetType, parse("OUT IP4 192.168.1.1"));
}

test "parse: invalid addr_type returns error" {
    try std.testing.expectError(error.InvalidAddrType, parse("IN IP5 192.168.1.1"));
}
