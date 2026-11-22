//! Kite — an async HTTP/1.1 client library for Zig 0.17 powered by zio.

const std = @import("std");

pub const version = @import("kite_build_options").version;

pub const http = @import("http.zig");
pub const h1 = @import("h1.zig");
pub const Connection = @import("Connection.zig");
pub const Transport = @import("Transport.zig");
pub const Pool = @import("Pool.zig");
pub const Client = @import("Client.zig");
pub const RetryTransport = @import("RetryTransport.zig");
pub const CookieJar = @import("CookieJar.zig");
pub const multipart = @import("multipart.zig");

pub const CaStore = Connection.CaStore;
pub const TlsConfig = Connection.TlsConfig;
pub const ProxyConfig = Connection.ProxyConfig;
pub const AddressFilter = Connection.AddressFilter;
pub const Trace = Transport.Trace;
pub const ExchangeMetrics = Transport.ExchangeMetrics;
pub const RetryBudget = RetryTransport.RetryBudget;
pub const CookieEntry = CookieJar.CookieEntry;
pub const Method = http.Method;
pub const Status = http.Status;
pub const Scheme = http.Scheme;
pub const Origin = http.Origin;
pub const Header = http.Header;
pub const Headers = http.Headers;
pub const CheckRedirect = Client.CheckRedirect;
pub const RedirectDecision = Client.RedirectDecision;
pub const RedirectInfo = Client.RedirectInfo;
pub const RequestOptions = Client.RequestOptions;
pub const Response = Client.Response;
pub const PendingRequest = Client.PendingRequest;
pub const StreamResponse = Client.StreamResponse;

test {
    std.testing.refAllDecls(@This());
}
