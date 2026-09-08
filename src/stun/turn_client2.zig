const std = @import("std");
const stun = @import("stun.zig");

const TurnClient = @This();
const IpAddress = std.Io.net.IpAddress;

const max_payload_size = 384;
const max_transactions = 8;

const max_attempts = 7;
const base_rto = 200; // milliseconds

pub const Error = error{
    AllocationAlreadyExists,
    TooManyTransactions,
} || std.Io.Writer.Error || std.mem.Allocator.Error;

pub const StunError = error{
    BadRequest,
    Unauthorized,
    Forbidden,
    UnknownAttribute,
    AllocationMismatch,
    StaleNonce,
    AddressFamilyNotSupported,
    WrongCredentials,
    UnsupportedTransportProtocol,
    AllocationQuotaReached,
    RoleConflict,
    ServerError,
    InsufficientCapacity,
    UnknownStunError,
    NoAllocation,
    BufferTooShort,
    CreatePermissionFailed,
    MissingErrorCode,
    MissingRealm,
    MissingNonce,
    MissingRelayedAddress,
    MissingMappedAddress,
    MissingLifetime,
    Timeout,
};

pub const AllocationResult = struct {
    relayed_address: IpAddress,
    mapped_address: IpAddress,
    lifetime: u32,
};

pub const Event = union(enum) {
    allocated: AllocationResult,
    allocation_failed: StunError,
    allocation_refreshed: u32,
    allocation_refresh_failed: StunError,
};

pub const Config = struct {
    local_addr: IpAddress,
    remote_addr: IpAddress,
    random: *std.Random,
    username: []const u8,
    password: []const u8,
};

const AuthInfo = struct {
    buffer: []u8,
    nonce_len: u32,
    realm_len: u32,
    key_len: u32,

    const empty = AuthInfo{
        .buffer = &.{},
        .nonce_len = 0,
        .realm_len = 0,
        .key_len = 0,
    };

    fn init(
        self: *AuthInfo,
        allocator: std.mem.Allocator,
        nonce: []const u8,
        realm: []const u8,
        username: []const u8,
        password: []const u8,
    ) std.mem.Allocator.Error!void {
        const new_len = nonce.len + realm.len + 16; // 16 bytes for MD5 digest
        if (self.buffer.len < new_len) {
            self.buffer = try allocator.realloc(self.buffer, new_len);
        }

        @memcpy(self.buffer[0..nonce.len], nonce);
        @memcpy(self.buffer[nonce.len..][0..realm.len], realm);
        const digest = self.buffer[nonce.len + realm.len ..][0..16];
        digest.* = stun.longTermCredentialsKey(std.crypto.hash.Md5, username, realm, password);

        self.nonce_len = @intCast(nonce.len);
        self.realm_len = @intCast(realm.len);
        self.key_len = 16;
    }

    fn deinit(self: *AuthInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
        self.* = .empty;
    }

    fn getNonce(self: *AuthInfo) []const u8 {
        return self.buffer[0..self.nonce_len];
    }

    fn getRealm(self: *AuthInfo) []const u8 {
        return self.buffer[self.nonce_len..][0..self.realm_len];
    }

    fn getKey(self: *AuthInfo) []const u8 {
        return self.buffer[self.nonce_len + self.realm_len ..][0..self.key_len];
    }
};

const Transaction = struct {
    id: u96,
    method: stun.Method,
    authenticated: bool,
    attempt: u8,
    payload_len: u32,
    deadline: i64,
};

allocator: std.mem.Allocator,
local_addr: IpAddress,
remote_addr: IpAddress,
random: *std.Random,
username: []const u8,
password: []const u8,

auth_info: AuthInfo,
req_payload: [max_payload_size * max_transactions]u8,
transactions: [max_transactions]?Transaction,
events_out: std.Deque(Event),
transmits: std.Deque(stun.TransportMessage),

allocation_lifetime: u32,
next_allocation_refresh_deadline: i64,

pub fn init(allocator: std.mem.Allocator, config: Config) TurnClient {
    return .{
        .allocator = allocator,
        .random = config.random,
        .local_addr = config.local_addr,
        .remote_addr = config.remote_addr,
        .username = config.username,
        .password = config.password,
        .auth_info = .empty,
        .req_payload = @splat(0),
        .transactions = @splat(null),
        .events_out = .empty,
        .transmits = .empty,
        .next_allocation_refresh_deadline = 0,
        .allocation_lifetime = 0,
    };
}

pub fn deinit(c: *TurnClient) void {
    c.auth_info.deinit(c.allocator);
    c.events_out.deinit(c.allocator);
    c.transmits.deinit(c.allocator);
}

pub fn createAllocation(c: *TurnClient, now: i64) Error!void {
    if (c.next_allocation_refresh_deadline != 0) return error.AllocationAlreadyExists;

    const idx = try c.nextTransactionSlot();
    const tr = try c.buildAllocateRequest(c.getBuffer(idx, max_payload_size), now, false);

    try c.transmits.ensureUnusedCapacity(c.allocator, 1);

    c.transactions[idx] = tr;
    c.transmits.pushBackAssumeCapacity(.{
        .from = &c.local_addr,
        .to = &c.remote_addr,
        .data = c.getBuffer(idx, tr.payload_len),
    });
}

pub fn deleteAllocation(c: *TurnClient, buffer: []u8) !void {
    if (c.next_allocation_refresh_deadline == 0) return;

    const id = c.random.int(u96);
    var w = stun.Writer.init(buffer, .{ .password = c.auth_info.getKey() });
    try writeHeader(&w, .request, .refresh, id);
    try w.writeAttributes(&.{
        .{ .lifetime = 0 },
        .{ .username = c.username },
        .{ .realm = c.auth_info.getRealm() },
        .{ .nonce = c.auth_info.getNonce() },
        .{ .message_integrity = &.{} },
        .fingerprint,
    });

    const msg = w.final();
    c.next_allocation_refresh_deadline = 0;
    c.auth_info.deinit(c.allocator);

    try c.transmits.pushBack(c.allocator, .{
        .from = &c.local_addr,
        .to = &c.remote_addr,
        .data = msg,
    });
}

pub fn handleTimeout(c: *TurnClient, now: i64) Error!void {
    if (c.next_allocation_refresh_deadline != 0 and now >= c.next_allocation_refresh_deadline) {
        c.next_allocation_refresh_deadline = now + (c.allocation_lifetime / 2) * std.time.ms_per_s;
        try c.newRefreshRequest(now);
    }

    var idx: usize = 0;
    while (idx < max_transactions) : (idx += 1) {
        if (c.transactions[idx] == null) continue;
        const tr = &c.transactions[idx].?;
        if (tr.deadline > now) continue;

        tr.attempt += 1;
        if (tr.attempt >= max_attempts) {
            c.transactions[idx] = null;
            try c.events_out.pushBack(c.allocator, .{ .allocation_failed = StunError.Timeout });
        } else {
            tr.deadline = now + @as(i64, tr.attempt + 1) * base_rto;
            try c.transmits.pushBack(c.allocator, .{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = c.getBuffer(idx, tr.payload_len),
            });
        }
    }
}

pub fn handleRead(c: *TurnClient, buffer: []const u8, now: i64) !void {
    const msg = try stun.Message.parse(buffer);
    const idx = c.findTransaction(msg.header.transaction_id) orelse return;
    const tr = c.transactions[idx].?;
    c.transactions[idx] = null;

    switch (tr.method) {
        .allocate => try c.handleAllocateResponse(&tr, &msg, now),
        .refresh => try c.handleRefreshResponse(&tr, &msg, now),
        else => {},
    }
}

pub fn pollTimeout(c: *TurnClient) ?i64 {
    var next_deadline: i64 = std.math.maxInt(i64);
    for (c.transactions) |tr| if (tr != null) {
        next_deadline = @min(next_deadline, tr.?.deadline);
    };

    if (c.next_allocation_refresh_deadline != 0) next_deadline = @min(next_deadline, c.next_allocation_refresh_deadline);
    return if (next_deadline == std.math.maxInt(i64)) null else next_deadline;
}

pub fn pollEvent(c: *TurnClient) ?Event {
    return c.events_out.popFront();
}

pub fn pollOutput(c: *TurnClient) ?stun.TransportMessage {
    return c.transmits.popFront();
}

fn writeHeader(w: *stun.Writer, class: stun.Class, method: stun.Method, tx_id: u96) !void {
    try w.writeHeader(.{
        .message_length = 0,
        .message_type = .fromClassAndMethod(class, method),
        .transaction_id = tx_id,
    });
}

fn handleAllocateResponse(c: *TurnClient, tr: *const Transaction, msg: *const stun.Message, now: i64) !void {
    switch (msg.header.message_type.class()) {
        .error_response => {
            if (tr.authenticated) {
                try c.events_out.pushBack(c.allocator, .{ .allocation_failed = StunError.Unauthorized });
                return;
            }

            try c.applyChallenge(msg);
            const idx = try c.nextTransactionSlot();
            const buffer = c.getBuffer(idx, max_payload_size);
            const new_tr = try c.buildAllocateRequest(buffer, now, true);
            try c.transmits.ensureUnusedCapacity(c.allocator, 1);

            c.transactions[idx] = new_tr;
            c.transmits.pushBackAssumeCapacity(.{
                .from = &c.local_addr,
                .to = &c.remote_addr,
                .data = c.getBuffer(idx, new_tr.payload_len),
            });
        },
        .success_response => {
            const result = try c.parseAllocation(msg);
            try c.events_out.pushBack(c.allocator, result);
            if (result == .allocated) {
                c.allocation_lifetime = result.allocated.lifetime;
                c.next_allocation_refresh_deadline = now + (result.allocated.lifetime / 2) * std.time.ms_per_s;
            }
        },
        else => {},
    }
}

fn handleRefreshResponse(c: *TurnClient, tr: *const Transaction, msg: *const stun.Message, now: i64) !void {
    _ = tr;

    switch (msg.header.message_type.class()) {
        .error_response => {
            c.applyChallenge(msg) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.Discard => return,
                else => |e| {
                    try c.events_out.pushBack(c.allocator, .{ .allocation_refresh_failed = e });
                    return;
                },
            };
            try c.newRefreshRequest(now);
        },
        .success_response => {
            const lifetime = c.parseRefresh(msg) catch |err| switch (err) {
                error.Discard => return,
                else => |e| {
                    try c.events_out.pushBack(c.allocator, .{ .allocation_refresh_failed = e });
                    return;
                },
            };
            c.allocation_lifetime = lifetime;
            c.next_allocation_refresh_deadline = now + (c.allocation_lifetime / 2) * std.time.ms_per_s;

            try c.events_out.pushBack(c.allocator, .{ .allocation_refreshed = lifetime });
        },
        else => {},
    }
}

fn newRefreshRequest(c: *TurnClient, now: i64) !void {
    const idx = try c.nextTransactionSlot();
    const buffer = c.getBuffer(idx, max_payload_size);
    const tr = try c.buildRefreshRequest(buffer, now);
    try c.transmits.ensureUnusedCapacity(c.allocator, 1);

    c.transactions[idx] = tr;
    c.transmits.pushBackAssumeCapacity(.{
        .from = &c.local_addr,
        .to = &c.remote_addr,
        .data = c.getBuffer(idx, tr.payload_len),
    });
}

/// Extracts REALM/NONCE from a 401/438 error response and derives the long-term credentials key.
fn applyChallenge(c: *TurnClient, msg: *const stun.Message) !void {
    var realm: ?[]const u8 = null;
    var nonce: ?[]const u8 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(c.auth_info.getKey());
    while (it.next() catch return error.Discard) |attr| switch (attr) {
        .realm => realm = attr.realm,
        .nonce => nonce = attr.nonce,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    switch (code orelse return error.MissingErrorCode) {
        .unauthorized, .stale_nonce => {},
        else => |co| return errorFromCode(co),
    }

    if (realm == null) return error.MissingRealm;
    if (nonce == null) return error.MissingNonce;

    try c.auth_info.init(c.allocator, nonce.?, realm.?, c.username, c.password);
}

fn buildAllocateRequest(c: *TurnClient, buffer: []u8, now: i64, authenticated: bool) !Transaction {
    const tx_id = c.random.int(u96);

    var transaction = Transaction{
        .id = tx_id,
        .method = .allocate,
        .authenticated = authenticated,
        .attempt = 0,
        .payload_len = 0,
        .deadline = now + base_rto,
    };

    var w = stun.Writer.init(buffer, .{ .password = if (authenticated) c.auth_info.getKey() else null });
    try writeHeader(&w, .request, .allocate, tx_id);
    try w.writeAttribute(.{ .requested_transport = .udp });
    try w.writeAttribute(.{ .requested_address_family = std.meta.activeTag(c.local_addr) });

    if (authenticated) {
        try w.writeAttributes(&.{
            .{ .username = c.username },
            .{ .realm = c.auth_info.getRealm() },
            .{ .nonce = c.auth_info.getNonce() },
            .{ .message_integrity = &.{} },
            .fingerprint,
        });
    }

    transaction.payload_len = @intCast(w.final().len);
    return transaction;
}

fn buildRefreshRequest(c: *TurnClient, buffer: []u8, now: i64) !Transaction {
    var tr = Transaction{
        .id = c.random.int(u96),
        .method = .refresh,
        .authenticated = true,
        .attempt = 0,
        .payload_len = 0,
        .deadline = now + base_rto,
    };

    var w = stun.Writer.init(buffer, .{ .password = c.auth_info.getKey() });
    try writeHeader(&w, .request, .refresh, tr.id);
    try w.writeAttributes(&.{
        .{ .lifetime = c.allocation_lifetime },
        .{ .username = c.username },
        .{ .realm = c.auth_info.getRealm() },
        .{ .nonce = c.auth_info.getNonce() },
        .{ .message_integrity = &.{} },
        .fingerprint,
    });

    tr.payload_len = @intCast(w.final().len);
    return tr;
}

fn parseAllocation(client: *TurnClient, msg: *const stun.Message) !Event {
    var relayed_address: ?IpAddress = null;
    var mapped_address: ?IpAddress = null;
    var lifetime: ?u32 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(client.auth_info.getKey());
    while (try it.next()) |attr| switch (attr) {
        .xor_relayed_address => |addr| relayed_address = addr,
        .xor_mapped_address => |addr| mapped_address = addr,
        .lifetime => lifetime = attr.lifetime,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    if (code) |c| return .{ .allocation_failed = errorFromCode(c) };

    return .{ .allocated = .{
        .relayed_address = relayed_address orelse return .{ .allocation_failed = error.MissingRelayedAddress },
        .mapped_address = mapped_address orelse return .{ .allocation_failed = error.MissingMappedAddress },
        .lifetime = lifetime orelse return .{ .allocation_failed = error.MissingLifetime },
    } };
}

fn parseRefresh(client: *TurnClient, msg: *const stun.Message) !u32 {
    var lifetime: ?u32 = null;
    var code: ?stun.StunErrorCode = null;

    var it = msg.iterateAttributes(client.auth_info.getKey());
    while (it.next() catch return error.Discard) |attr| switch (attr) {
        .lifetime => lifetime = attr.lifetime,
        .error_code => code = attr.error_code.code,
        else => {},
    };

    if (code) |c| return errorFromCode(c);
    return lifetime orelse return error.MissingLifetime;
}

fn errorFromCode(code: stun.StunErrorCode) StunError {
    return switch (code) {
        .bad_request => error.BadRequest,
        .unauthorized => error.Unauthorized,
        .forbidden => error.Forbidden,
        .unknown_attribute => error.UnknownAttribute,
        .allocation_mismatch => error.AllocationMismatch,
        .stale_nonce => error.StaleNonce,
        .address_family_not_supported => error.AddressFamilyNotSupported,
        .wrong_credentials => error.WrongCredentials,
        .unsupported_transport_protocol => error.UnsupportedTransportProtocol,
        .allocation_quota_reached => error.AllocationQuotaReached,
        .role_conflict => error.RoleConflict,
        .server_error => error.ServerError,
        .insufficient_capacity => error.InsufficientCapacity,
        _ => error.UnknownStunError,
    };
}

fn nextTransactionSlot(c: *TurnClient) !usize {
    for (c.transactions, 0..) |tr, idx| if (tr == null) return idx;
    return error.TooManyTransactions;
}

fn findTransaction(c: *TurnClient, tx_id: u96) ?usize {
    for (c.transactions, 0..) |tr, idx| if (tr != null and tr.?.id == tx_id) return idx;
    return null;
}

fn getBuffer(c: *TurnClient, index: usize, payload_len: u32) []u8 {
    const start = index * max_payload_size;
    return c.req_payload[start .. start + payload_len];
}

fn testClient(random: *std.Random) TurnClient {
    return TurnClient.init(std.testing.allocator, .{
        .local_addr = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 12345 } },
        .remote_addr = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 3478 } },
        .random = random,
        .username = "user",
        .password = "pass",
    });
}

test "createAllocation: queues an unauthenticated allocate request" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var random = r.random();

    var c = testClient(&random);
    defer c.deinit();

    try c.createAllocation(0);

    const out = c.pollOutput() orelse return error.ExpectedOutput;
    try std.testing.expect(out.from.eql(&c.local_addr));
    try std.testing.expect(out.to.eql(&c.remote_addr));
    try std.testing.expectEqual(null, c.pollOutput());

    const msg = try stun.Message.parse(out.data);
    try std.testing.expectEqual(.request, msg.header.message_type.class());
    try std.testing.expectEqual(.allocate, msg.header.message_type.method());

    var it = msg.iterateAttributes(&.{});
    var attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expectEqual(.udp, attribute.requested_transport);

    attribute = try it.next() orelse return error.ExpectedAttribute;
    try std.testing.expectEqual(.ip4, attribute.requested_address_family);

    try std.testing.expectEqual(null, try it.next());
}

test "createAllocation: registers a transaction with a retransmit deadline" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var random = r.random();

    var c = testClient(&random);
    defer c.deinit();

    try c.createAllocation(1000);

    var found: ?Transaction = null;
    for (c.transactions) |tr| if (tr != null) {
        found = tr;
    };

    const tr = found orelse return error.ExpectedTransaction;
    try std.testing.expectEqual(.allocate, tr.method);
    try std.testing.expectEqual(false, tr.authenticated);
    try std.testing.expectEqual(0, tr.attempt);
    try std.testing.expectEqual(1000 + base_rto, tr.deadline);
    try std.testing.expectEqual(1000 + base_rto, c.pollTimeout());
}

test "createAllocation: fails when an allocation already exists" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var random = r.random();

    var c = testClient(&random);
    defer c.deinit();

    c.next_allocation_refresh_deadline = 5000;
    try std.testing.expectError(error.AllocationAlreadyExists, c.createAllocation(0));
    try std.testing.expectEqual(null, c.pollOutput());
}

test "createAllocation: fails when no transaction slot is free" {
    var r = std.Random.DefaultPrng.init(std.testing.random_seed);
    var random = r.random();

    var c = testClient(&random);
    defer c.deinit();

    for (&c.transactions) |*slot| slot.* = Transaction{
        .id = 0,
        .method = .allocate,
        .authenticated = false,
        .attempt = 0,
        .payload_len = 0,
        .deadline = 0,
    };

    try std.testing.expectError(error.TooManyTransactions, c.createAllocation(0));
    try std.testing.expectEqual(null, c.pollOutput());
}
