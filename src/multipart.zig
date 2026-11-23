//! RFC 7578 `multipart/form-data` payload builder.
//!
//! Orthogonal payload codec with zero coupling to `Client` or `Pool`. Builds an
//! owned `Form` containing the exact `Content-Type` header (including boundary)
//! and serialized multipart body ready for `Client.fetch()`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const kite_build_options = @import("kite_build_options");
const zio = @import("zio");
const http = @import("http.zig");

const default_boundary_prefix = "----" ++ kite_build_options.name;

/// Finished multipart payload ready to attach to a request.
pub const Form = struct {
    content_type: []u8,
    body: []u8,

    pub fn contentTypeHeader(self: *const Form) http.Header {
        return .{
            .name = "Content-Type",
            .value = self.content_type,
        };
    }

    pub fn deinit(self: *Form, gpa: Allocator) void {
        gpa.free(self.content_type);
        gpa.free(self.body);
        self.* = undefined;
    }
};

pub const Error = error{
    InvalidBoundary,
    InvalidFieldName,
    InvalidHeaderValue,
    AlreadyFinished,
} || Allocator.Error;

pub const Builder = struct {
    gpa: Allocator,
    boundary: []u8,
    buf: std.ArrayList(u8) = .empty,
    finished: bool = false,

    /// Creates a builder with a cryptographically random boundary (`----<name><32 hex>`).
    pub fn init(gpa: Allocator) (Allocator.Error || zio.RandomSecureError)!Builder {
        var rnd: [16]u8 = undefined;
        try zio.randomSecure(&rnd);

        const hex = "0123456789abcdef";
        const prefix = default_boundary_prefix;
        const boundary = try gpa.alloc(u8, prefix.len + rnd.len * 2);
        @memcpy(boundary[0..prefix.len], prefix);
        for (rnd, 0..) |b, i| {
            boundary[prefix.len + i * 2] = hex[b >> 4];
            boundary[prefix.len + i * 2 + 1] = hex[b & 0x0F];
        }
        return .{
            .gpa = gpa,
            .boundary = boundary,
        };
    }

    /// Creates a builder with an explicit boundary (primarily for deterministic tests).
    pub fn initWithBoundary(gpa: Allocator, boundary: []const u8) Error!Builder {
        if (boundary.len == 0 or boundary.len > 70) return error.InvalidBoundary;
        for (boundary) |c| {
            const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
            if (!ok) return error.InvalidBoundary;
        }
        return .{
            .gpa = gpa,
            .boundary = try gpa.dupe(u8, boundary),
        };
    }

    pub fn deinit(self: *Builder) void {
        self.gpa.free(self.boundary);
        self.buf.deinit(self.gpa);
        self.* = undefined;
    }

    /// Appends a plain text form field.
    pub fn addField(self: *Builder, name: []const u8, value: []const u8) Error!void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0) return error.InvalidFieldName;
        try validateNoCrLf(name);

        try self.buf.appendSlice(self.gpa, "--");
        try self.buf.appendSlice(self.gpa, self.boundary);
        try self.buf.appendSlice(self.gpa, "\r\nContent-Disposition: form-data; name=\"");
        try appendEscapedParam(&self.buf, self.gpa, name);
        try self.buf.appendSlice(self.gpa, "\"\r\n\r\n");
        try self.buf.appendSlice(self.gpa, value);
        try self.buf.appendSlice(self.gpa, "\r\n");
    }

    /// Appends a file part with filename, MIME `content_type`, and raw bytes.
    pub fn addFile(
        self: *Builder,
        name: []const u8,
        filename: []const u8,
        content_type: []const u8,
        data: []const u8,
    ) Error!void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0) return error.InvalidFieldName;
        try validateNoCrLf(name);
        try validateNoCrLf(filename);
        http.validateHeaderValue(content_type) catch return error.InvalidHeaderValue;

        try self.buf.appendSlice(self.gpa, "--");
        try self.buf.appendSlice(self.gpa, self.boundary);
        try self.buf.appendSlice(self.gpa, "\r\nContent-Disposition: form-data; name=\"");
        try appendEscapedParam(&self.buf, self.gpa, name);
        try self.buf.appendSlice(self.gpa, "\"; filename=\"");
        try appendEscapedParam(&self.buf, self.gpa, filename);
        try self.buf.appendSlice(self.gpa, "\"\r\nContent-Type: ");
        try self.buf.appendSlice(self.gpa, content_type);
        try self.buf.appendSlice(self.gpa, "\r\n\r\n");
        try self.buf.appendSlice(self.gpa, data);
        try self.buf.appendSlice(self.gpa, "\r\n");
    }

    /// Finalizes the multipart stream with `--{boundary}--\r\n` and transfers
    /// ownership of `content_type` and `body` into `Form`.
    pub fn finish(self: *Builder) Error!Form {
        if (self.finished) return error.AlreadyFinished;

        try self.buf.appendSlice(self.gpa, "--");
        try self.buf.appendSlice(self.gpa, self.boundary);
        try self.buf.appendSlice(self.gpa, "--\r\n");

        const content_type = try self.gpa.print("multipart/form-data; boundary={s}", .{self.boundary});
        errdefer self.gpa.free(content_type);

        const body = try self.buf.toOwnedSlice(self.gpa);
        self.finished = true;

        return .{
            .content_type = content_type,
            .body = body,
        };
    }
};

/// Constant-memory streaming `multipart/form-data` writer.
///
/// Writes multipart boundaries, part headers, and streamed file payloads directly
/// into any `*std.Io.Writer` (such as `PendingRequest.writer()` with
/// `.body = .stream_chunked`), enabling multi-GB uploads without buffering the
/// entire form in RAM.
pub const StreamWriter = struct {
    gpa: Allocator,
    out: *Writer,
    boundary: []u8,
    content_type: []u8,
    finished: bool = false,

    pub fn init(gpa: Allocator, out: *Writer) !StreamWriter {
        var rnd: [16]u8 = undefined;
        try zio.randomSecure(&rnd);

        const hex = "0123456789abcdef";
        const prefix = default_boundary_prefix;
        const boundary = try gpa.alloc(u8, prefix.len + rnd.len * 2);
        errdefer gpa.free(boundary);
        @memcpy(boundary[0..prefix.len], prefix);
        for (rnd, 0..) |b, i| {
            boundary[prefix.len + i * 2] = hex[b >> 4];
            boundary[prefix.len + i * 2 + 1] = hex[b & 0x0F];
        }

        const content_type = try gpa.print("multipart/form-data; boundary={s}", .{boundary});
        return .{
            .gpa = gpa,
            .out = out,
            .boundary = boundary,
            .content_type = content_type,
        };
    }

    pub fn initWithBoundary(gpa: Allocator, out: *Writer, boundary: []const u8) !StreamWriter {
        if (boundary.len == 0 or boundary.len > 70) return error.InvalidBoundary;
        for (boundary) |c| {
            const ok = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
            if (!ok) return error.InvalidBoundary;
        }
        const owned_boundary = try gpa.dupe(u8, boundary);
        errdefer gpa.free(owned_boundary);
        const content_type = try gpa.print("multipart/form-data; boundary={s}", .{owned_boundary});
        return .{
            .gpa = gpa,
            .out = out,
            .boundary = owned_boundary,
            .content_type = content_type,
        };
    }

    pub fn contentTypeHeader(self: *const StreamWriter) http.Header {
        return .{
            .name = "Content-Type",
            .value = self.content_type,
        };
    }

    pub fn deinit(self: *StreamWriter) void {
        self.gpa.free(self.boundary);
        self.gpa.free(self.content_type);
        self.* = undefined;
    }

    /// Streams a plain text form field directly to `self.out`.
    pub fn writeField(self: *StreamWriter, name: []const u8, value: []const u8) !void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0) return error.InvalidFieldName;
        try validateNoCrLf(name);

        try self.out.print("--{s}\r\nContent-Disposition: form-data; name=\"", .{self.boundary});
        try writeEscapedParam(self.out, name);
        try self.out.writeAll("\"\r\n\r\n");
        try self.out.writeAll(value);
        try self.out.writeAll("\r\n");
    }

    /// Streams a file part from any `*std.Io.Reader` directly to `self.out` using
    /// a fixed 4 KiB buffer (constant memory regardless of file size).
    pub fn writeFileFromReader(
        self: *StreamWriter,
        name: []const u8,
        filename: []const u8,
        content_type: []const u8,
        src: *Reader,
    ) !void {
        if (self.finished) return error.AlreadyFinished;
        if (name.len == 0) return error.InvalidFieldName;
        try validateNoCrLf(name);
        try validateNoCrLf(filename);
        http.validateHeaderValue(content_type) catch return error.InvalidHeaderValue;

        try self.out.print("--{s}\r\nContent-Disposition: form-data; name=\"", .{self.boundary});
        try writeEscapedParam(self.out, name);
        try self.out.writeAll("\"; filename=\"");
        try writeEscapedParam(self.out, filename);
        try self.out.print("\"\r\nContent-Type: {s}\r\n\r\n", .{content_type});

        var buf: [4096]u8 = undefined;
        while (true) {
            const n = try src.readSliceShort(&buf);
            if (n == 0) break;
            try self.out.writeAll(buf[0..n]);
        }
        try self.out.writeAll("\r\n");
    }

    /// Writes the closing `--{boundary}--\r\n`. Idempotent.
    pub fn finish(self: *StreamWriter) !void {
        if (self.finished) return;
        try self.out.print("--{s}--\r\n", .{self.boundary});
        self.finished = true;
    }
};

fn writeEscapedParam(w: *Writer, s: []const u8) Writer.Error!void {
    for (s) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
}

fn validateNoCrLf(s: []const u8) error{InvalidFieldName}!void {
    for (s) |c| {
        if (c == '\r' or c == '\n' or c == 0) return error.InvalidFieldName;
    }
}

fn appendEscapedParam(out: *std.ArrayList(u8), gpa: Allocator, s: []const u8) Allocator.Error!void {
    for (s) |c| {
        if (c == '"' or c == '\\') {
            try out.append(gpa, '\\');
        }
        try out.append(gpa, c);
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "multipart Builder formats fields, files, escaping, and rejects header injection" {
    const gpa = std.testing.allocator;

    var builder = try Builder.initWithBoundary(gpa, "test-boundary-42");
    defer builder.deinit();

    try builder.addField("title", "hello kite");
    try builder.addFile("doc", "my \"file\".txt", "text/plain", "binary\x00data");

    var form = try builder.finish();
    defer form.deinit(gpa);

    try std.testing.expectEqualStrings("multipart/form-data; boundary=test-boundary-42", form.content_type);
    try std.testing.expectEqualStrings(
        "--test-boundary-42\r\n" ++
            "Content-Disposition: form-data; name=\"title\"\r\n" ++
            "\r\n" ++
            "hello kite\r\n" ++
            "--test-boundary-42\r\n" ++
            "Content-Disposition: form-data; name=\"doc\"; filename=\"my \\\"file\\\".txt\"\r\n" ++
            "Content-Type: text/plain\r\n" ++
            "\r\n" ++
            "binary\x00data\r\n" ++
            "--test-boundary-42--\r\n",
        form.body,
    );

    // Rejects CRLF injection in field name / content-type and double finish
    try std.testing.expectError(error.AlreadyFinished, builder.addField("x", "y"));

    var b2 = try Builder.initWithBoundary(gpa, "b2");
    defer b2.deinit();
    try std.testing.expectError(error.InvalidFieldName, b2.addField("bad\r\nname", "v"));
    try std.testing.expectError(error.InvalidHeaderValue, b2.addFile("f", "a.txt", "text/plain\r\nEvil: 1", "x"));
}

test "multipart Builder generates cryptographically random boundaries" {
    const gpa = std.testing.allocator;
    const rt = try zio.Runtime.init(gpa, .{});
    defer rt.deinit();

    var b1 = try Builder.init(gpa);
    defer b1.deinit();
    var b2 = try Builder.init(gpa);
    defer b2.deinit();

    try std.testing.expect(std.mem.startsWith(u8, b1.boundary, default_boundary_prefix));
    try std.testing.expectEqual(@as(usize, default_boundary_prefix.len + 32), b1.boundary.len);
    try std.testing.expect(!std.mem.eql(u8, b1.boundary, b2.boundary));
}

test "multipart StreamWriter matches Builder wire format with constant memory" {
    const gpa = std.testing.allocator;

    var out: Writer.Allocating = .init(gpa);
    defer out.deinit();

    var sw = try StreamWriter.initWithBoundary(gpa, &out.writer, "stream-b");
    defer sw.deinit();

    try sw.writeField("k", "v");
    var file_src: Reader = .fixed("streamed-file-bytes");
    try sw.writeFileFromReader("file", "a.bin", "application/octet-stream", &file_src);
    try sw.finish();
    try sw.finish(); // idempotent

    try std.testing.expectEqualStrings("multipart/form-data; boundary=stream-b", sw.contentTypeHeader().value);
    try std.testing.expectEqualStrings(
        "--stream-b\r\n" ++
            "Content-Disposition: form-data; name=\"k\"\r\n" ++
            "\r\n" ++
            "v\r\n" ++
            "--stream-b\r\n" ++
            "Content-Disposition: form-data; name=\"file\"; filename=\"a.bin\"\r\n" ++
            "Content-Type: application/octet-stream\r\n" ++
            "\r\n" ++
            "streamed-file-bytes\r\n" ++
            "--stream-b--\r\n",
        out.written(),
    );
}
