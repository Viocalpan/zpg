const std = @import("std");
const zpg = @import("zpg.zig");

const stdout = std.io.getStdOut().writer();

pub fn main() !void {
//    const conninfo: zpg.ConnInfo = .{host="192.168.56.51",.port=5432,.user="test",.database="test",.password="1qaz.2",.appname="zpg"};
const conninfo = zpg.ConnInfo.parse("test:1qaz.2@127.0.0.1");
    try stdout.print("conninfo = {any}\n", .{conninfo});

    var conn = try zpg.PgDb.connect(conninfo);
    defer conn.deinit();

    try stdout.print("conn.id = {}\n", .{conn.backend});

    const value = conn.parameter.get("server_version");
    try stdout.print("params = {s},count={d}\n", .{ value.?, conn.parameter.count() });

    try stdout.print("\r\n", .{});
    var iterator = conn.parameter.iterator();
    while (iterator.next()) |item| {
        try stdout.print("{s} = {s}\r\n", .{ item.key_ptr.*, item.value_ptr.* });
    }
        var cur = conn.cursor();
        defer cur.deinit();

        try cur.begin();
        cur.query("select * from handlers limit 5;") catch |err| { //'abcd', 5, 2>1;
            try cur.rollback();
            try stdout.print("\n catch:  code = {s}, messages = {s}\n", .{ cur.LastMsg.code, cur.LastMsg.message });
            //  return err;
            try stdout.print("\n error = {}\n", .{err});
            break;
        };
        try cur.commit();
        try stdout.print("\n success:  code = {s}, messages = {s}\n\r\n", .{ cur.LastMsg.code, cur.LastMsg.message });

        for (cur.description) |*col| {
            try stdout.print(" fields = {any}\n", .{col});
        }

        try stdout.print("\n", .{});

        for (cur.rows) |*row| {
            try stdout.print(" data: {any}\n", .{row});
        }

        try stdout.print(" description = {any}, rows = {d}\n\n", .{ cur.description.len, cur.rowcount });

}
