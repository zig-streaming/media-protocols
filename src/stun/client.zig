const std = @import("std");
const stun = @import("stun.zig");

const Client = @This();
const IpAddress = std.Io.net.IpAddress;

const max_attempts = 7;
const base_rto = 200; // milliseconds

const Transaction = struct {
    id: u96,
    attempt: u8,
    msg: []const u8,
    deadline: i64,
};

pub const Message = struct {
    from: *const IpAddress,
    to: *const IpAddress,
    data: []const u8,
};

pub const Event = union(enum) {
    out_message: Message,
    in_message: stun.Message,
    timeout: struct { u96, []const u8 },
};

pub const Config = struct {
    local_addr: IpAddress,
    remote_addr: IpAddress,
};

local_addr: IpAddress,
remote_addr: IpAddress,
transactions: std.AutoHashMap(u96, Transaction),
events_out: std.Deque(Event),

pub fn init(allocator: std.mem.Allocator, config: Config) Client {
    return .{
        .local_addr = config.local_addr,
        .remote_addr = config.remote_addr,
        .transactions = .init(allocator),
        .events_out = .empty,
    };
}

pub fn deinit(c: *Client) void {
    c.events_out.deinit(c.transactions.allocator);
    c.transactions.deinit();
}

pub fn handleWrite(c: *Client, id: u96, msg: []const u8, now: i64) !void {
    const transaction = Transaction{
        .id = id,
        .attempt = 0,
        .msg = msg,
        .deadline = now + base_rto,
    };

    try c.transactions.put(id, transaction);
    errdefer _ = c.transactions.remove(id);
    try c.events_out.pushBack(c.transactions.allocator, .{
        .out_message = .{ .from = &c.local_addr, .to = &c.remote_addr, .data = msg },
    });
}

pub fn handleRead(c: *Client, data: []const u8) !void {
    const msg = try stun.Message.parse(data);
    if (c.transactions.remove(msg.header.transaction_id)) {
        try c.events_out.pushBack(c.transactions.allocator, .{ .in_message = msg });
    }
}

pub fn handleTimeout(c: *Client, now: i64) !i64 {
    var next_deadline: i64 = std.math.maxInt(i64);
    var it = c.transactions.valueIterator();
    while (it.next()) |tr| {
        if (tr.deadline > now) {
            next_deadline = @min(next_deadline, tr.deadline);
            continue;
        }

        tr.attempt += 1;
        if (tr.attempt >= max_attempts) {
            try c.events_out.pushBack(c.transactions.allocator, .{ .timeout = .{ tr.id, tr.msg } });
            _ = c.transactions.remove(tr.id);
        } else {
            tr.deadline = now + @as(i64, tr.attempt + 1) * base_rto;
            next_deadline = @min(next_deadline, tr.deadline);
            try c.events_out.pushBack(c.transactions.allocator, .{
                .out_message = .{ .from = &c.local_addr, .to = &c.remote_addr, .data = tr.msg },
            });
        }
    }

    return next_deadline;
}

pub fn pollEvent(c: *Client) ?Event {
    return c.events_out.popFront();
}

const testing = std.testing;

const test_local_addr: IpAddress = .{ .ip4 = .loopback(1000) };
const test_remote_addr: IpAddress = .{ .ip4 = .loopback(2000) };

fn bindingRequest(buffer: *[stun.header_size]u8, tx_id: u96) ![]const u8 {
    var out = stun.Writer.init(buffer, .{});
    try out.writeHeader(.{
        .message_type = .fromClassAndMethod(.request, .binding),
        .transaction_id = tx_id,
        .message_length = 0,
    });
    return out.final();
}

test "handleWrite: queues out_message and stores transaction" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try client.handleWrite(1, "req", 100);

    const tr = client.transactions.get(1) orelse return error.ExpectedTransaction;
    try testing.expectEqual(0, tr.attempt);
    try testing.expectEqual(100 + base_rto, tr.deadline);

    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqualStrings("req", event.out_message.data);
    try testing.expect(event.out_message.from == &client.local_addr);
    try testing.expect(event.out_message.to == &client.remote_addr);
    try testing.expectEqual(null, client.pollEvent());
}

test "handleRead: matches pending transaction" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    const tx_id: u96 = 0x000102030405060708090A0B;
    try client.handleWrite(tx_id, "req", 0);
    _ = client.pollEvent();

    var buf: [stun.header_size]u8 = undefined;
    try client.handleRead(try bindingRequest(&buf, tx_id));

    try testing.expect(!client.transactions.contains(tx_id));
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqual(tx_id, event.in_message.header.transaction_id);
    try testing.expectEqual(null, client.pollEvent());
}

test "handleRead: unknown transaction produces no event" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    var buf: [stun.header_size]u8 = undefined;
    try client.handleRead(try bindingRequest(&buf, 0xABC));

    try testing.expectEqual(null, client.pollEvent());
}

test "handleRead: invalid stun message returns error" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try testing.expectError(error.WrongMagicCookie, client.handleRead(&([_]u8{0} ** stun.header_size)));
}

test "handleTimeout: does nothing before the deadline" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try client.handleWrite(1, "req", 0);
    _ = client.pollEvent();

    const next_deadline = try client.handleTimeout(base_rto - 1);
    try testing.expectEqual(base_rto, next_deadline);
    try testing.expectEqual(null, client.pollEvent());

    const tr = client.transactions.get(1) orelse return error.ExpectedTransaction;
    try testing.expectEqual(0, tr.attempt);
}

test "handleTimeout: retransmits and backs off before max attempts" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try client.handleWrite(1, "req", 0);
    _ = client.pollEvent();

    const next_deadline = try client.handleTimeout(base_rto);
    try testing.expectEqual(base_rto + 2 * base_rto, next_deadline);

    const tr = client.transactions.get(1) orelse return error.ExpectedTransaction;
    try testing.expectEqual(1, tr.attempt);
    try testing.expectEqual(next_deadline, tr.deadline);

    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqualStrings("req", event.out_message.data);
    try testing.expectEqual(null, client.pollEvent());
}

test "handleTimeout: emits timeout event and drops transaction after max attempts" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try client.handleWrite(1, "req", 0);
    _ = client.pollEvent();

    var now: i64 = base_rto;
    var next_deadline = try client.handleTimeout(now);
    for (1..max_attempts - 1) |_| {
        _ = client.pollEvent();
        now = next_deadline;
        next_deadline = try client.handleTimeout(now);
    }
    _ = client.pollEvent();

    now = next_deadline;
    _ = try client.handleTimeout(now);

    try testing.expect(!client.transactions.contains(1));
    const event = client.pollEvent() orelse return error.ExpectedEvent;
    try testing.expectEqual(1, event.timeout.@"0");
    try testing.expectEqualStrings("req", event.timeout.@"1");
    try testing.expectEqual(null, client.pollEvent());
}

test "pollEvent: returns null when empty" {
    var client: Client = .init(testing.allocator, .{ .local_addr = test_local_addr, .remote_addr = test_remote_addr });
    defer client.deinit();

    try testing.expectEqual(null, client.pollEvent());
}
