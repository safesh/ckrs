const std = @import("std");

const pkcs11 = @cImport({
    @cDefine("CK_PTR", "*");
    @cDefine("CK_DECLARE_FUNCTION(returnType, name)", "returnType name");
    @cDefine("CK_DECLARE_FUNCTION_POINTER(returnType, name)", "returnType (* name)");
    @cDefine("CK_CALLBACK_FUNCTION(returnType, name)", "returnType (* name)");
    @cInclude("v300/include/pkcs11.h");
});

pub fn main() !void {
    std.debug.print("Hello, World!\n", .{});
}

test "test" {
    try main();
}
