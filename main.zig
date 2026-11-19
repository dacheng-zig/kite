const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const out = std.Io.File.stdout();
    try out.writeStreamingAll(init.io, "Hello, Kite!");
}
