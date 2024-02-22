// version 0.12
// replace  .Big  to .big  @std.builtin.Endian,
// replace std.mem.copy to std.mem.copyForwards

const std = @import("std");

const Mem = std.mem;
const Fmt = std.fmt;
const memcp = Mem.copy;

///  backend
const AUTHENTICATIONOK = 'R'; // MD5Password SASLFinal SASLContinue SASL GSSContinue SSPI GSS SCMCredential  CleartextPassword KerberosV5
const NEGOTIATEPROTOCOLVERSION = 'v';
const BACKENDKEYDATA = 'K';
const PARAMETERSTATUS = 'S';
const ERRORRESPONSE = 'E';
const NOTICERESPONSE = 'N';
const NOTIFICATIONRESPONSE = 'A';
const READYFORQUERY = 'Z';

const EMPTYQUERYRESPONSE = 'I';
const ROWDESCRIPTION = 'T';
const DATAROW = 'D';
const COMMANDCOMPLETE = 'C';

///  frontend
const PASSWORDMESSAGE = 'p';
const QUERY = 'Q';
const TERMINATE = 'X';
//  ErrorMessage
//  CancelRequest
//  StartupMessage

// --------------------------------------------------------------
pub const DbError = error{
    Could_not_connect_to_server,
    Not_supported_error,
    Internal_error,
    Not_support_authentication_method,
    Authentication_error,
    Authentication_fail,
    Lost_connection_to_server,
    Transaction_failed,
    Transaction_idle,
    Connection_is_closed,
    Cursor_is_closed,
    Sql_execute_error,
    Sql_too_long,
};

// -----------------------------
//  var conninfo: zpg.ConnInfo = .{host="192.168.56.51",.port=5432,.user="test",.password="passw0rd",.database="test",.appname="zpg"};
//  ConnInfo.parse("appname://user:passw0rd@host:port/database"));
pub const ConnInfo = struct {
    const Self = @This();
    host: []const u8 = "127.0.0.1",
    port: u16 = 5432,
    user: []const u8 = "test",
    password: []const u8 = "",
    database: []const u8 = "test",
    appname: []const u8 = "zpg",

    pub fn parse(dburl: []const u8) Self {
        var self: Self = .{};

        var levelurl: []const u8 = "";
        var netloc: []const u8 = "";
        var i: usize = 0xffff;
        var upath: []const u8 = "/";

        i = Mem.indexOf(u8, dburl, "://") orelse 0xffff;
        if (i == 0xffff) {
            levelurl = dburl;
        } else {
            self.appname = dburl[0..i];
            levelurl = dburl[i + 3 ..];
        }

        i = Mem.indexOfAny(u8, levelurl, "/") orelse 0xffff;
        if (i < 0xffff) {
            netloc = levelurl[0..i];
            upath = levelurl[i..];

            i = Mem.indexOfAny(u8, upath, ";") orelse 0xffff;
            if (i < 0xffff) {
                upath = upath[0..i];
            }

            i = Mem.indexOfAny(u8, upath, "?") orelse 0xffff;
            if (i < 0xffff) {
                upath = upath[0..i];
            }

            i = Mem.indexOfAny(u8, upath, "#") orelse 0xffff;
            if (i < 0xffff) {
                upath = upath[0..i];
            }
        } else {
            netloc = levelurl;
        }

        i = Mem.indexOfAny(u8, netloc, "@") orelse 0xffff;
        if (i < 0xffff) {
            const authent = netloc[0..i];
            netloc = netloc[i + 1 ..];

            i = Mem.indexOfAny(u8, authent, ":") orelse 0xffff;
            if (i < 0xffff) {
                self.user = authent[0..i];
                self.password = authent[i + 1 ..];
            } else {
                self.user = authent;
            }
        }
        i = Mem.indexOfAny(u8, netloc, ":") orelse 0xffff;
        if (i < 0xffff) {
            self.host = netloc[0..i];
            const sport = netloc[i + 1 ..];
            const iport = Fmt.parseInt(u16, sport, 10) catch 0;
            if (iport > 100) {
                self.port = iport;
            }
        } else {
            if (netloc.len > 0) {
                self.host = netloc;
            }
        }

        while (true) {
            i = Mem.indexOfAny(u8, upath, "/") orelse 0xffff;
            if (i == 0) {
                upath = upath[1..];
                continue;
            }
            if (i < 0xffff) {
                upath = upath[0..i];
            } else {
                break;
            }
        }

        if (upath.len > 0) {
            self.database = upath;
        }

        return self;
    }

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: Fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const ss =
            \\{{"host": "{s}", "port": {d}, "user": "{s}", "password": "********", "database": "{s}", "appname": "{s}"}}
        ;
        try writer.print(ss, .{ self.host, self.port, self.user, self.database, self.appname });
    }
};

// -----------------------------
const Pgstatus = enum(i32) {
    const Self = @This();
    undetermined = -1,
    closed = 0,
    abort = -2,
    active = 256,
};

const Transtatus = enum(u8) {
    const Self = @This();
    idle = 'I',
    fail = 'E',
    ing = 'T',
    fn from(t: u8) !Self {
        switch (t) {
            'I' => return Self.idle,
            'T' => return Self.ing,
            'E' => return Self.fail,
            else => return DbError.Not_supported_error,
        }
    }
};

// -----------------------------
pub const PgDb = struct {
    const Self = @This();
    memalloc: Mem.Allocator,
    netstream: std.net.Stream,
    backend: i32 = @intFromEnum(Pgstatus.undetermined), //  status (undetermined, -1 |active, >=256 |closed, 0|abort, -2)
    secret: i32 = 0,
    transaction: Transtatus = Transtatus.idle, //  #IDLE = 'I' IN = 'T' FAILED = 'E'
    parameter: std.StringHashMap([]const u8),
    LastMsg: ReplyMsg,

    pub fn connect(connInfo: ConnInfo) !Self {
        var pgconn = Self{
            .memalloc = std.heap.page_allocator,
            .netstream = undefined,
            .parameter = undefined,
            .LastMsg = ReplyMsg.new(),
        };

        pgconn.netstream = std.net.tcpConnectToHost(pgconn.memalloc, connInfo.host, connInfo.port) catch {
            std.debug.print("Could not connect host {s}:{d}!\r\n", .{ connInfo.host, connInfo.port });
            return DbError.Could_not_connect_to_server;
        };
        pgconn.parameter = std.StringHashMap([]const u8).init(pgconn.memalloc);

        pgconn.startup(connInfo.user, connInfo.database, connInfo.appname) catch |err| return err;
        pgconn.authenticate(connInfo.user, connInfo.password) catch |err| return err;
        pgconn.readyforquery() catch |err| return err;

        const sport: []const u8 = Fmt.allocPrint(pgconn.memalloc, "{d}", .{connInfo.port}) catch "5432";
        try pgconn.parameter.put("host", connInfo.host);
        try pgconn.parameter.put("port", sport);
        try pgconn.parameter.put("user", connInfo.user);
        try pgconn.parameter.put("dbname", connInfo.database);

        return pgconn;
    }

    pub fn deinit(self: *Self) void {
        self.parameter.deinit();
        self.close() catch {};
        self.LastMsg.free(self.memalloc);
    }

    pub fn close(self: *Self) !void {
        if (self.backend > @intFromEnum(Pgstatus.active)) {
            _ = try self.sendData(TERMINATE, "");
            self.backend = @intFromEnum(Pgstatus.closed);
        }
        self.netstream.close();
    }

    fn startup(self: *Self, user: []const u8, database: []const u8, appname: []const u8) !void {
        var databuf: [128]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&databuf);
        const bfswr = fbs.writer();
        try bfswr.writeInt(i32, 196608, .Big); //  protocol version { 0, 3, 0, 0 }
        try bfswr.writeAll("user\x00");
        try bfswr.writeAll(user);
        try bfswr.writeByte(0);
        try bfswr.writeAll("database\x00");
        try bfswr.writeAll(database);
        try bfswr.writeByte(0);
        try bfswr.writeAll("application_name\x00");
        try bfswr.writeAll(appname);
        try bfswr.writeByte(0);
        try bfswr.writeAll("client_encoding\x00UTF8\x00");
        try bfswr.writeByte(0);
        _ = self.sendData(0, fbs.getWritten()) catch |err| return err;
    }

    fn authenticate(self: *Self, user: []const u8, password: []const u8) !void {
        const nsreader = self.netstream.reader();
        const code = nsreader.readInt(u8, .Big) catch return DbError.Lost_connection_to_server;
        var lenbuf: [4]u8 = undefined;
        _ = nsreader.read(&lenbuf) catch return DbError.Lost_connection_to_server;
        var nomsgf: bool = false;

        var len = Mem.readInt(u32, &lenbuf, .Big);

        if (len > 4096) { //  1178686529  b'E,FATA,L
            nomsgf = true;
            len = 128;
        }

        const msgdata = try self.memalloc.alloc(u8, len - 4);
        defer self.memalloc.free(msgdata);
        _ = nsreader.read(msgdata) catch return DbError.Lost_connection_to_server;

        if (nomsgf == true) {
            //  b'EFATAL:  unsupported frontend protocol 0.12345: server supports 2.0 to 3.0\n\x00'
            var i: usize = 0;
            var ret: []const u8 = "";
            while (msgdata[i] != 0 and i < (len - 4)) : (i += 1) {}
            i += 1;
            ret = msgdata[0 .. i - 1];
            std.debug.print("InternalError {s}{s}\r\n", .{ lenbuf, ret });
            return DbError.Internal_error;
        }

        var authmsg = MsgData{ .code = code, .data = msgdata };
        var password_type: i32 = 0;
        var scram: Scram = undefined;
        var dscrpto: [256]u8 = undefined;
        while (true) {
            if (authmsg.code != AUTHENTICATIONOK) {
                if (authmsg.code == ERRORRESPONSE) {
                    //  b'E\x00\x00\x00\x88SFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend protocol 29.65474: server supports 2.0 to 3.0\x00Fpostmaster.c\x00L2120\x00RProcessStartupPacket\x00\x00'
                    const errmsg = ReplyMsg.parseResponse(self.memalloc, &authmsg);
                    std.debug.print("InternalError code:{s},{s}:{s}\r\n", .{ errmsg.code, errmsg.severity, errmsg.message });
                    return DbError.Internal_error;
                }
                return DbError.Not_supported_error;
            }

            password_type = authmsg.readInt(i32);
            switch (password_type) {
                0 => return, // authenticationok

                3 => { //  plain-text
                    if (password.len == 0) {
                        return DbError.Authentication_fail;
                    }
                    var plainpw: [64]u8 = undefined;
                    var j: usize = 0;
                    memcp(u8, plainpw[0..], password);
                    j += password.len;
                    memcp(u8, plainpw[j..], &[_]u8{0x00});
                    j += 1;
                    _ = self.sendData(PASSWORDMESSAGE, plainpw[0..j]) catch |err| return err;
                },

                5 => { //  md5
                    if (password.len == 0) {
                        return DbError.Authentication_fail;
                    }
                    const salt = authmsg.readBytes(4);
                    const md5 = pghashMd5(user, password, salt);
                    _ = self.sendData(PASSWORDMESSAGE, md5) catch |err| return err;
                },

                10 => { //  sasl AuthenticationSASL
                    if (password.len == 0) {
                        return DbError.Authentication_fail;
                    }
                    scram = Scram.init(password);
                    const L = scram.state.genhashData(&dscrpto);
                    _ = self.sendData(PASSWORDMESSAGE, dscrpto[0..L]) catch |err| return err;
                },
                11 => { //  sasl AuthenticationSASLContinue
                    scram.update(authmsg.data[4..]) catch return DbError.Authentication_error;
                    const L = scram.state.genhashData(&dscrpto);
                    _ = self.sendData(PASSWORDMESSAGE, dscrpto[0..L]) catch |err| return err;
                },
                12 => { //  sasl AuthenticationSASLFinal
                    scram.finish(authmsg.data[4..]) catch return DbError.Authentication_error;
                },

                else => return DbError.Not_support_authentication_method,
            }
            authmsg = self.readData(self.memalloc) catch |err| return err;
            // defer authmsg.free(self.memalloc);
        }
    }

    fn readyforquery(self: *Self) !void {
        var k: []const u8 = "";
        var v: []const u8 = "";
        while (true) {
            var msg = self.readData(self.memalloc) catch |err| return err;
            defer msg.free(self.memalloc);

            switch (msg.code) {
                PARAMETERSTATUS => {
                    k = try self.memalloc.dupe(u8, msg.readString());
                    v = try self.memalloc.dupe(u8, msg.readString());
                    try self.parameter.put(k, v);
                },
                BACKENDKEYDATA => {
                    self.backend = msg.readInt(i32);
                    self.secret = msg.readInt(i32);
                },
                ERRORRESPONSE => {
                    //  b'E\x00\x00\x00gSFATAL\x00VFATAL\x00C42704\x00Munrecognized configuration parameter "pgdb"\x00Fguc.c\x00L6759\x00Rset_config_option\x00\x00'
                    const errmsg = ReplyMsg.parseResponse(self.memalloc, &msg);
                    std.debug.print("InternalError code:{s},{s}:{s}\r\n", .{ errmsg.code, errmsg.severity, errmsg.message });
                    return DbError.Internal_error;
                },
                NOTICERESPONSE => {
                    self.LastMsg = ReplyMsg.parseResponse(self.memalloc, &msg);
                },
                READYFORQUERY => {
                    self.transaction = Transtatus.from(msg.data[0]) catch |err| return err;
                    break;
                },
                NEGOTIATEPROTOCOLVERSION => {},
                else => {
                    return DbError.Not_supported_error;
                },
            }
        }
    }

    pub fn cursor(self: *Self) Cursor {
        return Cursor.init(self);
    }

    pub fn cancel(self: *Self) !void {
        var databuf: [16]u8 = undefined;
        var i: usize = 0;
        Mem.writeInt(i32, &databuf[i..][0..4].*, 80877102, .Big);
        i += 4;
        Mem.writeInt(i32, &databuf[i..][0..4].*, self.backend, .Big);
        i += 4;
        Mem.writeInt(i32, &databuf[i..][0..4].*, self.secret, .Big);
        i += 4;
        _ = self.sendData(0, databuf[0..i]) catch |err| return err;
    }

    fn sendData(self: *Self, code: u8, payload: []const u8) !usize {
        var databuf: [SQLLEN + 16]u8 = undefined;
        const datalen = payload.len;
        var i: usize = 0;
        if (code > 0) {
            Mem.writeInt(u8, &databuf[i..][0..1].*, code, .Big);
            i += 1;
        }
        Mem.writeInt(i32, &databuf[i..][0..4].*, @as(i32, @intCast(datalen + 4)), .Big);
        i += 4;
        memcp(u8, databuf[i..], payload);
        const nswriter = self.netstream.writer();
        nswriter.writeAll(databuf[0 .. datalen + i]) catch {
            if (self.backend > @intFromEnum(Pgstatus.active)) {
                self.backend = @intFromEnum(Pgstatus.abort);
            }
            return DbError.Lost_connection_to_server;
        };
        return datalen;
    }

    fn readData(self: *Self, memalloc: Mem.Allocator) !MsgData {
        const nsreader = self.netstream.reader();
        const code = nsreader.readInt(u8, .Big) catch {
            if (self.backend > @intFromEnum(Pgstatus.active)) {
                self.backend = @intFromEnum(Pgstatus.abort);
            }
            return DbError.Lost_connection_to_server;
        };
        const len = nsreader.readInt(u32, .Big) catch {
            if (self.backend > @intFromEnum(Pgstatus.active)) {
                self.backend = @intFromEnum(Pgstatus.abort);
            }
            return DbError.Lost_connection_to_server;
        };
        if (len > 4) {
            const data = try memalloc.alloc(u8, len - 4);
            // defer memalloc.free(data);
            _ = nsreader.readNoEof(data) catch {
                if (self.backend > @intFromEnum(Pgstatus.active)) {
                    self.backend = @intFromEnum(Pgstatus.abort);
                }
                return DbError.Lost_connection_to_server;
            };
            return MsgData{ .code = code, .data = data };
        }
        return MsgData{ .code = code, .data = "" };
    }
};

// -----------------------------
const SQLLEN = 4096;

pub const Cursor = struct {
    const Self = @This();
    conn: *PgDb = undefined,
    mAllocator: std.heap.ArenaAllocator,
    description: []Column,
    rows: []Drow,
    rowcount: i32,
    LastMsg: ReplyMsg,
    status: Pgstatus,

    pub fn init(pgconn: *PgDb) Self {
        return .{
            .conn = pgconn,
            .mAllocator = std.heap.ArenaAllocator.init(std.heap.page_allocator),
            .description = &[_]Column{},
            .rows = &[_]Drow{},
            .rowcount = 0,
            .LastMsg = ReplyMsg.new(),
            .status = Pgstatus.active,
        };
    }

    pub fn deinit(self: *Self) void {
        const memalloc = self.mAllocator.allocator();
        defer {
            self.LastMsg.free(memalloc);
            self.mAllocator.deinit();
        }
        self.close();
    }

    pub fn close(self: *Self) void {
        self.description = undefined;
        self.rows = undefined;
        self.rowcount = 0;
        self.status = Pgstatus.closed;
    }

    fn islive(self: *Self) !void {
        if (self.status != Pgstatus.active)
            return DbError.Cursor_is_closed;
        if (self.conn.backend == @intFromEnum(Pgstatus.closed))
            return DbError.Connection_is_closed;
    }

    pub fn begin(self: *Self) !void {
        try self.islive();
        if (self.conn.transaction != Transtatus.ing)
            return self.exec("BEGIN")
        else
            return DbError.Transaction_idle;
    }
    pub fn commit(self: *Self) !void {
        try self.islive();
        if (self.conn.transaction == Transtatus.ing)
            return self.exec("COMMIT")
        else
            return DbError.Transaction_failed;
    }
    pub fn rollback(self: *Self) !void {
        try self.islive();
        if (self.conn.transaction != Transtatus.idle)
            return self.exec("ROLLBACK")
        else
            return DbError.Transaction_failed;
    }

    pub fn exec(self: *Self, sqlstr: []const u8) !void {
        try self.islive();

        if (sqlstr.len > SQLLEN) {
            return DbError.Sql_too_long;
        }

        if (self.conn.transaction == Transtatus.idle) self.rowcount = 0;

        var qrybuf: [SQLLEN + 8]u8 = undefined;
        var j: usize = 0;
        memcp(u8, qrybuf[0..], sqlstr);
        j += sqlstr.len;
        memcp(u8, qrybuf[j..], &[_]u8{0x00});
        j += 1;
        _ = self.conn.sendData(QUERY, qrybuf[0..j]) catch |err| return err;

        var erm = false;
        const memalloc = self.mAllocator.allocator();

        while (true) {
            var msg = self.conn.readData(memalloc) catch |err| return err;
            defer msg.free(memalloc);
            switch (msg.code) {
                ERRORRESPONSE => {
                    erm = true;
                    self.LastMsg = ReplyMsg.parseResponse(memalloc, &msg);
                },
                NOTICERESPONSE => {
                    self.LastMsg = ReplyMsg.parseResponse(memalloc, &msg);
                },
                NOTIFICATIONRESPONSE => {},
                ROWDESCRIPTION => {
                    self.description = parseRowDescription(memalloc, &msg);
                },
                DATAROW => {},
                EMPTYQUERYRESPONSE => {},
                COMMANDCOMPLETE => {
                    const rcnt = parseCommandComplete(msg.readString());
                    if (rcnt >= 0) self.rowcount = rcnt;
                },
                READYFORQUERY => {
                    self.conn.transaction = Transtatus.from(msg.data[0]) catch |err| return err;
                    break;
                },
                else => {}, // PARAMETERSTATUS
            }
        }
        if (erm) {
            const errmsg = self.LastMsg;
            std.debug.print("Sql_execute_error code:{s},{s}:{s}\r\n", .{ errmsg.code, errmsg.severity, errmsg.message });
            return DbError.Sql_execute_error;
        }
    }

    pub fn query(self: *Self, sqlstr: []const u8) !void {
        try self.islive();

        if (sqlstr.len > SQLLEN) {
            return DbError.Sql_too_long;
        }
        if (self.conn.transaction == Transtatus.idle) self.rowcount = 0;

        var qrybuf: [SQLLEN + 8]u8 = undefined;
        var j: usize = 0;
        memcp(u8, qrybuf[0..], sqlstr);
        j += sqlstr.len;
        memcp(u8, qrybuf[j..], &[_]u8{0x00});
        j += 1;
        _ = self.conn.sendData(QUERY, qrybuf[0..j]) catch |err| return err;

        var i: i32 = 0;
        var erm = false;
        const memalloc = self.mAllocator.allocator();

        var rowlist = std.ArrayList(Drow).init(memalloc);
        while (true) {
            var msg = self.conn.readData(memalloc) catch |err| return err;
            defer msg.free(memalloc);
            switch (msg.code) {
                ERRORRESPONSE => {
                    erm = true;
                    self.LastMsg = ReplyMsg.parseResponse(memalloc, &msg);
                },
                NOTICERESPONSE => {
                    //  self.LastMsg.free(self.memalloc);
                    self.LastMsg = ReplyMsg.parseResponse(memalloc, &msg);
                },
                NOTIFICATIONRESPONSE => {},
                ROWDESCRIPTION => {
                    self.description = parseRowDescription(memalloc, &msg);
                },
                DATAROW => {
                    const row = parseDataRow(memalloc, &msg);
                    try rowlist.append(row);
                    i += 1;
                },
                EMPTYQUERYRESPONSE => {},
                COMMANDCOMPLETE => {
                    const rcnt = parseCommandComplete(msg.readString());
                    if (rcnt >= 0) self.rowcount = rcnt;
                    self.rows = rowlist.items;
                },
                READYFORQUERY => {
                    self.conn.transaction = Transtatus.from(msg.data[0]) catch |err| return err;
                    break;
                },
                else => {}, // PARAMETERSTATUS
            }
        }
        if (erm) {
            const errmsg = self.LastMsg;
            std.debug.print("Sql_execute_error code:{s},{s}:{s}\r\n", .{ errmsg.code, errmsg.severity, errmsg.message });
            return DbError.Sql_execute_error;
        }
    }
};

// -------------------------------------------------------------
const Column = struct {
    const Self = @This();
    name: []const u8,
    col: i16,
    typid: i32,
    typlen: i16,
    typmod: i32,
    // fmtcode: i16,

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: Fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var fieldlen: i32 = 0;
        if ((self.typlen > 0) or (self.typid == 1700)) fieldlen = self.typlen else fieldlen = self.typmod;
        _ = fmt;
        _ = options;
        var ft: [48]u8 = undefined;
        const L = pgtyp(self.typid, self.typmod, &ft);
        try writer.print("(name = {s}, type = {s}, size = {d})", .{ self.name, ft[0..L], fieldlen });
    }

    fn free(self: *Self, memalloc: Mem.Allocator) void {
        memalloc.free(self.name);
    }

    fn pgtyp(fdtyp: i32, fdmod: i32, t: []u8) usize {
        var s: []const u8 = "";
        var buf: [48]u8 = undefined;
        var fl: usize = 0;
        switch (fdtyp) {
            16 => {
                s = "bool";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            18 => {
                s = "char";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            20 => {
                s = "int8 (bigint)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            21 => {
                s = "int2 (smallint)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            23 => {
                s = "int4 (integer)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            25 => {
                s = "text";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            114 => {
                s = "json";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            142 => {
                s = "xml";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            650 => {
                s = "cidr";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            700 => {
                s = "float4 (real)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            701 => {
                s = "float8 (double precision)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            790 => {
                s = "money";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            829 => {
                s = "macaddr";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            869 => {
                s = "inet";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1042 => {
                s = Fmt.bufPrint(&buf, "char({})", .{fdmod - 4}) catch "char(n)";
                memcp(u8, t[0..], s);
                fl = s.len;
            }, // t = "char", // char(n) (character(n))
            1043 => {
                s = Fmt.bufPrint(&buf, "varchar({})", .{fdmod - 4}) catch "varchar(n)";
                memcp(u8, t[0..], s);
                fl = s.len;
            }, //  t = "varchar", // varchar(n) (character varying())
            1082 => {
                s = "date";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1083 => {
                s = "time (time without time zone)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1114 => {
                s = "timestamp (timestamp without time zone)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1184 => {
                s = "timestamptz (timestamp with time zone)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1266 => {
                s = "timetz (time with time zone)";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            1700 => {
                const tynum = parsnumeric(fdmod);
                s = Fmt.bufPrint(&buf, "numeric({},{})", .{ tynum.p, tynum.s }) catch "unknow pg_type";
                memcp(u8, t[0..], s);
                fl = s.len;
            }, //  t = "numeric", // numeric(p,s)
            2950 => {
                s = "uuid";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
            else => {
                s = Fmt.bufPrint(&buf, "pg_type({d})", .{fdtyp}) catch "unknow pg_type";
                memcp(u8, t[0..], s);
                fl = s.len;
            },
        }
        return fl;
    }

    fn parsnumeric(tymod: i32) Numerictyp {
        const x: u32 = @as(u32, @intCast(tymod - 4));
        const p = x / 65536; // 2**16 std.math.pow
        const s = x - p * 65536;
        return .{ .p = @as(u16, @intCast(p)), .s = @as(u16, @intCast(s)) };
    }

    const Numerictyp = struct {
        p: u16 = 0,
        s: u16 = 0,
    };
};

fn parseRowDescription(memalloc: Mem.Allocator, msg: *MsgData) []Column {
    const colnum = msg.readInt(i16);
    var collist = std.ArrayList(Column).init(memalloc);

    var coln: i16 = 0;
    var dtyp: i32 = 0;
    var dlen: i16 = 0;
    var dmod: i32 = 0;
    var name: []const u8 = "";
    for (0..(@as(u16, @intCast(colnum)))) |i| {
        name = memalloc.dupe(u8, msg.readString()) catch "?";
        if ((Mem.eql(u8, name, "?")) or (Mem.eql(u8, name, "")) or (Mem.eql(u8, name, "?column?"))) {
            var buf: [16]u8 = undefined;
            name = memalloc.dupe(u8, Fmt.bufPrint(&buf, "column{:0>2}", .{i}) catch "column") catch "column";
        }
        _ = msg.readInt(i32);
        coln = msg.readInt(i16);
        dtyp = msg.readInt(i32);
        dlen = msg.readInt(i16);
        dmod = msg.readInt(i32);
        _ = msg.readInt(i16);
        collist.append(.{
            .name = name,
            .col = coln,
            .typid = dtyp,
            .typlen = dlen,
            .typmod = dmod,
        }) catch {};
    }
    return collist.items;
}

// ------------------------------
const Dcol = struct {
    const Self = @This();
    col: []const u8,
    idx: i16,
    size: i32,

    fn free(self: *Self, memalloc: Mem.Allocator) void {
        memalloc.free(self.col);
    }

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: Fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{s},", .{self.col});
    }
};

const Drow = struct {
    const Self = @This();
    row: []Dcol,
    size: i16,

    fn free(self: *Self, memalloc: Mem.Allocator) void {
        for (self.row) |*row| {
            row.free(memalloc);
        }
        //  self.deinit();
    }

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: Fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll("(");
        for (0..(@as(u16, @intCast(self.size)))) |j| {
            try writer.print("{any}", .{self.row[j]});
        }
        try writer.writeAll(")");
    }
};

fn parseDataRow(memalloc: Mem.Allocator, msg: *MsgData) Drow {
    var valLen: i32 = 0;
    var value: []const u8 = undefined;
    const colnum = msg.readInt(i16);
    var collist = std.ArrayList(Dcol).init(memalloc);

    //  bufLen -= 2;
    var j: i16 = 0;
    while (j < colnum) : (j += 1) {
        valLen = msg.readInt(i32);
        //  bufLen -= 4;
        if (valLen == -1) { // u32 0xFFFFFFFF i32 -1
            valLen = 0;
            value = "null";
        } else {
            value = memalloc.dupe(u8, msg.readBytes(@as(usize, @intCast(valLen)))) catch "None";
            //  bufLen -= valLen;
        }
        collist.append(.{
            .col = value,
            .idx = j,
            .size = valLen,
        }) catch {};
    }
    return .{ .row = collist.items, .size = colnum };
}

// ------------------------------
fn parseCommandComplete(command: []const u8) i32 {
    // MOVE,FETCH,COPY
    // INSERT,DELETE,UPDATE,SELECT
    if (command.len == 0) return 0;
    var last: []const u8 = "-1";
    var iter = Mem.tokenize(u8, command, " ");
    const first = iter.next().?;
    if ((Mem.eql(u8, first, "INSERT")) or (Mem.eql(u8, first, "DELETE")) or (Mem.eql(u8, first, "UPDATE")) or (Mem.eql(u8, first, "SELECT"))) {
        last = "0";
        while (iter.next()) |item| {
            // if (item.len > 0)
            last = item;
        }
    }
    return Fmt.parseInt(i32, last, 10) catch 0;
}

// -------------------------------------------------------------
const MsgData = struct {
    const Self = @This();
    code: u8 = 0,
    data: []const u8,
    pos: usize = 0,

    fn free(self: *Self, memalloc: Mem.Allocator) void {
        memalloc.free(self.data);
    }

    fn readInt(self: *Self, comptime T: type) T {
        var ret: T = 0;
        if ((self.data.len - @sizeOf(T)) >= self.pos) {
            ret = Mem.readInt(T, self.data[self.pos..][0..@sizeOf(T)], .Big);
            self.pos += @sizeOf(T);
        }
        return ret;
    }

    fn readBytes(self: *Self, num: usize) []const u8 {
        var ret: []const u8 = "";
        var dlen: usize = 0;
        const start = self.pos;
        if (self.data.len >= start) {
            dlen = self.data.len - start;
            if (dlen > num) {
                dlen = num;
            }
            ret = self.data[start .. start + dlen];
            self.pos += dlen;
        }
        return ret;
    }

    fn readString(self: *Self) []const u8 {
        const start = self.pos;
        var ret: []const u8 = "";
        if (self.data.len >= start) {
            while (self.data[self.pos] != 0 and self.pos < self.data.len) : (self.pos += 1) {}
            self.pos += 1;
            ret = self.data[start .. self.pos - 1];
        }
        return ret;
    }
};

// -----------------------------
// Response (Error&Notice) Message
pub const ReplyMsg = struct {
    const Self = @This();
    code: [5]u8,
    severity: []const u8,
    message: []const u8, // ERROR;FATAL;PANIC;WARNING;NOTICE;DEBUG;INFO;LOG
    // hint: ?[]const u8 = null,

    fn new() Self {
        return Self{
            .code = "00000".*,
            .severity = "",
            .message = "",
        };
    }

    fn parseResponse(memalloc: Mem.Allocator, msg: *MsgData) Self {
        var resp = Self.new();

        var mtyp = msg.readInt(u8);
        while (mtyp != 0) : (mtyp = msg.readInt(u8)) {
            switch (mtyp) {
                'V' => {
                    const value = msg.readString();
                    resp.severity = memalloc.dupe(u8, value) catch "";
                },
                'C' => memcp(u8, resp.code[0..], msg.readString()),
                'M' => {
                    const value = msg.readString();
                    // resp.message = msg.readString(); //[0..128];
                    resp.message = memalloc.dupe(u8, value) catch "";
                },
                else => _ = msg.readString(),
            }
        }
        return resp;
    }

    pub fn format(
        self: Self,
        comptime fmt: []const u8,
        options: Fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.print("{{code: {s}, {s}: {s}}}", .{
            self.code,
            self.severity,
            self.message,
        });
    }

    fn free(self: *Self, memalloc: Mem.Allocator) void {
        memalloc.free(self.severity);
        memalloc.free(self.message);
    }
};

// -------------------------------------------------------------
const Md5 = std.crypto.hash.Md5;

fn pghashMd5(user: []const u8, password: []const u8, salt: []const u8) []const u8 {
    var hkey: [16]u8 = undefined;
    var hasher = Md5.init(.{});
    hasher.update(password);
    hasher.update(user);
    hasher.final(&hkey);
    hasher = Md5.init(.{});
    var buf: [48]u8 = undefined;
    const hexfirst = Fmt.bufPrint(&buf, "{}", .{Fmt.fmtSliceHexLower(&hkey)}) catch "";
    hasher.update(hexfirst);
    hasher.update(salt);
    hasher.final(&hkey);
    const hexfinal = Fmt.bufPrint(&buf, "md5{}\x00", .{Fmt.fmtSliceHexLower(&hkey)}) catch "";
    return hexfinal;
}

// -----------------------------
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Base64 = std.base64.standard;
const Rand = std.rand;
const Meta = std.meta;

pub const Scram = struct {
    buffer: [512]u8 = undefined,
    state: State,

    pub const State = union(enum) {
        update: struct {
            nonce: [24]u8,
            password: []const u8,
        },
        finish: struct {
            salted_password: [32]u8,
            auth: []const u8,
            message: []const u8,
        },
        done: void,

        pub fn genhashData(self: *State, databuf: []u8) usize {
            // var databuf: [256]u8 = undefined;
            var i: usize = 0;
            switch (self.*) {
                .update => |u| {
                    const scrypto = "SCRAM-SHA-256\x00";
                    const sclient = "n,,n=,r=";
                    const dlen = sclient.len + u.nonce.len;

                    memcp(u8, databuf[i..], scrypto);
                    i += scrypto.len;
                    Mem.writeInt(i32, &databuf[i..][0..4].*, @as(i32, @intCast(dlen)), .Big);
                    i += 4;
                    memcp(u8, databuf[i..], sclient);
                    i += sclient.len;
                    memcp(u8, databuf[i..], &u.nonce);
                    i += u.nonce.len;
                },
                .finish => |f| {
                    memcp(u8, databuf[i..], f.message);
                    i += f.message.len;
                },
                .done => {},
            }
            return i;
        }
    };

    pub fn init(password: []const u8) Scram {
        var nonce: [24]u8 = undefined;
        const addr = @intFromPtr(&nonce);
        var randomizer = Rand.Xoshiro256.init(addr);
        for (&nonce) |*b| {
            var byte = randomizer.random().intRangeAtMost(u8, 0x21, 0x7e);
            if (byte == 0x2c) {
                byte = 0x7e;
            }
            b.* = byte;
        }

        return Scram{
            .state = .{
                .update = .{
                    .nonce = nonce,
                    .password = password,
                },
            },
        };
    }

    pub fn update(self: *Scram, message: []const u8) !void {
        if (Meta.activeTag(self.state) != .update) return error.InvalidState;

        var nonce: []const u8 = "";
        var salt: []const u8 = "";
        var iterations: []const u8 = "";

        var parser = Mem.tokenize(u8, message, ",");
        while (parser.next()) |kv| {
            if (kv[0] == 'r' and kv.len > 2) {
                nonce = kv[2..];
            }
            if (kv[0] == 's' and kv.len > 2) {
                salt = kv[2..];
            }
            if (kv[0] == 'i' and kv.len > 2) {
                iterations = kv[2..];
            }
        }
        if (nonce.len == 0 or salt.len == 0 or iterations.len == 0) {
            return error.InvalidInput;
        }

        if (!Mem.startsWith(u8, nonce, &self.state.update.nonce)) {
            return error.InvalidInput;
        }

        var decoded_salt_buf: [32]u8 = undefined;
        const decoded_salt_len = try Base64.Decoder.calcSizeForSlice(salt);
        if (decoded_salt_len > 32) return error.OutOfMemory;
        try Base64.Decoder.decode(&decoded_salt_buf, salt);
        const decoded_salt = decoded_salt_buf[0..decoded_salt_len];

        var salted_password = hi(self.state.update.password, decoded_salt, Fmt.parseInt(usize, iterations, 10) catch 0);
        var hmac = HmacSha256.init(&salted_password);
        hmac.update("Client Key");
        var client_key: [HmacSha256.key_length]u8 = undefined;
        hmac.final(&client_key);

        var hsha256 = Sha256.init(.{});
        hsha256.update(&client_key);
        var stored_key = hsha256.finalResult();

        const cbind = "biws"; //  base64 of 'n,,'
        var finish_state = Scram.State{ .finish = undefined };

        finish_state.finish.auth = try Fmt.bufPrint(self.buffer[0..256], "n=,r={s},{s},c={s},r={s}", .{
            self.state.update.nonce,
            message,
            cbind,
            nonce,
        });

        var client_hmac = HmacSha256.init(&stored_key);
        client_hmac.update(finish_state.finish.auth);
        var client_signature: [HmacSha256.key_length]u8 = undefined;
        client_hmac.final(&client_signature);

        var client_proof = client_key;
        var i: usize = 0;
        while (i < HmacSha256.key_length) : (i += 1) {
            client_proof[i] ^= client_signature[i];
        }

        var encoded_proof: [Base64.Encoder.calcSize(HmacSha256.key_length)]u8 = undefined;
        _ = Base64.Encoder.encode(&encoded_proof, &client_proof);

        finish_state.finish.message = try Fmt.bufPrint(self.buffer[256..512], "c={s},r={s},p={s}", .{
            cbind,
            nonce,
            &encoded_proof,
        });

        finish_state.finish.salted_password = salted_password;
        self.state = finish_state;
    }

    pub fn finish(self: *Scram, message: []const u8) !void {
        if (Meta.activeTag(self.state) != .finish) return error.InvalidState;
        if (message[0] != 'v' and message.len <= 2) return error.InvalidInput;

        const verifier = message[2..];
        var verifier_buf: [128]u8 = undefined;
        const verifier_len = try Base64.Decoder.calcSizeForSlice(verifier);
        if (verifier_len > 128) return error.OutOfMemory;
        try Base64.Decoder.decode(&verifier_buf, verifier);
        const decoded_verified = verifier_buf[0..verifier_len];

        var hmac = HmacSha256.init(&self.state.finish.salted_password);
        hmac.update("Server Key");
        var server_key: [32]u8 = undefined;
        hmac.final(&server_key);

        hmac = HmacSha256.init(&server_key);
        hmac.update(self.state.finish.auth);
        var hashed_verified: [HmacSha256.key_length]u8 = undefined;
        hmac.final(&hashed_verified);

        if (!Mem.eql(u8, decoded_verified, &hashed_verified)) return error.VerifyError;

        self.state = .{ .done = {} };
    }
};

fn hi(string: []const u8, salt: []const u8, iterations: usize) [32]u8 {
    var result: [HmacSha256.key_length]u8 = undefined;
    var hmac = HmacSha256.init(string);
    hmac.update(salt);
    hmac.update(&.{ 0, 0, 0, 1 });
    var previous: [HmacSha256.key_length]u8 = undefined;
    hmac.final(&previous);

    result = previous;
    for (1..iterations) |_| {
        var hmac_iter = HmacSha256.init(string);
        hmac_iter.update(&previous);
        hmac_iter.final(&previous);

        for (0..HmacSha256.key_length) |j| {
            result[j] ^= previous[j];
        }
    }
    return result;
}

//  Error and Notice RESPONSE returned from Postgres server
// 'S' => "SeverityS",
// 'V' => "Severity",
// 'C' => "Code",
// 'M' => "Message",
// 'D' => "Detail",
// 'H' => "Hint",
// 'P' => "Position",
// 'p' => "Internal position",
// 'q' => "Internal query",
// 'W' => "Where",
// 's' => "Schema name",
// 't' => "Table name",
// 'c' => "column name",
// 'd' => "Data type name",
// 'n' => "Constraint name",
// 'F' => "File",
// 'L' => "Line",
// 'R' => "Routine",

//backend
const PARSECOMPLETE = '1';
const BINDCOMPLETE = '2';
const CLOSECOMPLETE = '3';
const PARAMETERDESCRIPTION = 't';
const FUNCTIONCALLRESPONSE = 'V';
const PORTALSUSPENDED = 's';
const NODATA = 'n';

//frontend
const PARSE = 'P';
const BIND = 'B';
const DESCRIBE = 'D';
const FUNCTIONCALL = 'F';
const EXECUTE = 'E';
const SYNC = 'S';
const FLUSH = 'H';
const CLOSE = 'C';

