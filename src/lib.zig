const std = @import("std");
const cki = @cImport({
    @cDefine("CK_PTR", "*");
    @cDefine("CK_DECLARE_FUNCTION(returnType, name)", "returnType name");
    @cDefine("CK_DECLARE_FUNCTION_POINTER(returnType, name)", "returnType (* name)");
    @cDefine("CK_CALLBACK_FUNCTION(returnType, name)", "returnType (* name)");
    @cInclude("pkcs11.h");
});

const debug = std.debug.print;
const assert = std.debug.assert;

const BitSet = std.bit_set.IntegerBitSet(64);

const Template = struct {
    attr: *cki.CK_ATTRIBUTE,
    len: usize,
    total: usize = 1,
};

const Context = struct {
    objects: []cki.CK_OBJECT_HANDLE,
};

const Session = struct { rw: bool, app: []const u8, object_filter: ?Template = undefined };

var CKRS: struct {
    initialized: bool = false,
    handles: BitSet = BitSet.initFull(),
    sessions: [64]Session,

    fn new_session(self: *@TypeOf(CKRS)) !usize {
        if (self.handles.toggleFirstSet()) |handle|
            return handle;

        return error.SessionsFull;
    }

    fn close_session(self: *@TypeOf(CKRS), handle: usize) !void {
        if (self.handles.isSet(handle)) return error.InvalidHandle;

        self.handles.set(handle);
    }

    fn get_session(self: *@TypeOf(CKRS), handle: usize) !*Session {
        if (self.handles.isSet(handle)) return error.InvalidHandle;

        return &self.sessions[handle];
    }

    fn active_sessions(self: *@TypeOf(CKRS)) usize {
        return 64 - self.handles.count();
    }
} = .{ .sessions = std.mem.zeroes([64]Session) };

test "test_open_and_close_all_sessions" {
    for (0..@bitSizeOf(u64)) |_| {
        _ = try CKRS.new_session();
    }

    for (0..@bitSizeOf(u64)) |i| {
        try CKRS.close_session(i);
    }
}

// FIXME: Replace with compiler builtin
fn ffs(n: u64) !u6 {
    for (0..@bitSizeOf(u64)) |i| {
        if (n & @as(u64, 1) << @intCast(i) != 0) {
            return @intCast(i);
        }
    }

    return error.Full;
}

test "test_ffs_all_valid" {
    for (0..64) |i| {
        const ret = try ffs(@as(u64, 0x01) << @intCast(i));

        assert(ret == i);
    }
}

fn make_fn_list(comptime T: type, version: cki.CK_VERSION) T {
    const meta = @import("std").meta;

    var ret: T = undefined;

    inline for (meta.fields(T)) |field| {
        if (std.mem.eql(u8, field.name, "version")) {
            @field(ret, field.name).major = version.major;
            @field(ret, field.name).minor = version.minor;
        } else {
            @field(ret, field.name) = @ptrCast(&@field(@This(), field.name));
        }
    }

    return ret;
}

const fn_list_v2 = make_fn_list(cki.struct_CK_FUNCTION_LIST, .{ .major = 2, .minor = 40 });
const fn_list_v3 = make_fn_list(cki.struct_CK_FUNCTION_LIST_3_0, .{ .major = 3, .minor = 10 });

fn make_padded_string(comptime str: []const u8, comptime size: usize) [size]u8 {
    if (size < 1) @compileError("size must be greater than 0");

    var ret: [size]u8 = [_]u8{' '} ** size;

    for (str, 0..) |c, i| {
        ret[i] = c;

        if (i == size) break;
    }

    return ret;
}

const manufacturer = make_padded_string("safesh", 32);
const description = make_padded_string("Cryptoki Key Retention Service", 32);
const slot_description = make_padded_string("Key Retention Service Slot", 64);

// TODO: Define this through the build system.
const ver_major = 0;
const ver_minor = 1;

export fn C_Initialize(args: cki.CK_C_INITIALIZE_ARGS_PTR) callconv(.C) cki.CK_RV {
    debug("C_Initialize {*}\n", .{args});

    CKRS.initialized = true;

    // NOTE(Mulling): CKF_LIBRARY_CANT_CREATE_OS_THREADS we WILL not create threads

    if (args == null) {
        return cki.CKR_OK;
    } else if (args.*.flags & cki.CKF_OS_LOCKING_OK == 0 and args.*.LockMutex == null and args.*.CreateMutex == null and args.*.UnlockMutex == null and args.*.DestroyMutex == null) {
        return cki.CKR_OK;
    }

    // FIXME: Support multi-thread access

    return cki.CKR_CANT_LOCK;
}

export fn C_Finalize(_: cki.CK_VOID_PTR) callconv(.C) cki.CK_RV {
    debug("C_Finalize\n", .{});

    CKRS.handles = BitSet.initFull();

    for (&CKRS.sessions) |*session| {
        session.object_filter = undefined;
        session.rw = false;
        session.app = undefined;
    }

    return cki.CKR_OK;
}

export fn C_GetInfo(info: cki.CK_INFO_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetInfo {*}\n", .{info});

    if (info == null)
        return cki.CKR_ARGUMENTS_BAD;

    std.mem.copyForwards(u8, &info.*.manufacturerID, &manufacturer);
    std.mem.copyForwards(u8, &info.*.libraryDescription, &description);

    info.*.libraryVersion.major = ver_major;
    info.*.libraryVersion.minor = ver_minor;

    info.*.cryptokiVersion.major = 3;
    info.*.cryptokiVersion.minor = 10;

    return cki.CKR_OK;
}

export fn C_GetFunctionList(list: [*c][*c]cki.CK_FUNCTION_LIST) callconv(.C) cki.CK_RV {
    debug("C_GetFunctionList {*}\n", .{list});

    if (list == null) return cki.CKR_ARGUMENTS_BAD;

    list.* = @constCast(&fn_list_v2);

    return cki.CKR_OK;
}

export fn C_GetSlotList(present: cki.CK_BBOOL, slot_list: cki.CK_SLOT_ID_PTR, count: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetSlotList present = {}, slot_list = {*}, count = {*}\n", .{ present, slot_list, count });

    if (slot_list == null) {
        if (count != null)
            count.* = 1
        else
            return cki.CKR_ARGUMENTS_BAD;
    } else {
        if (count == null or count.* > 1) return cki.CKR_ARGUMENTS_BAD;
        if (count.* == 0) return cki.CKR_BUFFER_TOO_SMALL;
        slot_list[0] = 1;
    }

    return cki.CKR_OK;
}

export fn C_GetSlotInfo(id: cki.CK_SLOT_ID, info: cki.CK_SLOT_INFO_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetSlotInfo id = {}, info = {*}\n", .{ id, info });

    std.mem.copyForwards(u8, &info.*.manufacturerID, &manufacturer);
    std.mem.copyForwards(u8, &info.*.slotDescription, &slot_description);

    info.*.hardwareVersion.major = 0;
    info.*.hardwareVersion.minor = 0;

    info.*.firmwareVersion.major = 0;
    info.*.firmwareVersion.minor = 1;

    return cki.CKR_OK;
}

export fn C_GetTokenInfo(id: cki.CK_SLOT_ID, info: cki.CK_TOKEN_INFO_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetTokenInfo id = {}, info = {*}\n", .{ id, info });

    const memcpy = std.mem.copyForwards;

    // Application-defined label, assigned during token initialization.
    memcpy(u8, &info.*.label, &make_padded_string("ckrs", 32));

    // ID of the device manufacturer.
    memcpy(u8, &info.*.manufacturerID, &manufacturer);

    // Model of the device.
    memcpy(u8, &info.*.model, &make_padded_string("ckrs", 16));

    // Character-string serial number of the device.
    memcpy(u8, &info.*.serialNumber, &make_padded_string("1303199831031997", 16));

    // Bit flags indicating capabilities and status of the device
    info.*.flags = if (CKRS.initialized) cki.CKF_TOKEN_INITIALIZED else 0 | cki.CKF_USER_PIN_INITIALIZED | cki.CKF_PROTECTED_AUTHENTICATION_PATH;

    // Maximum number of sessions that can be opened with the token at one time by a single application.
    info.*.ulMaxSessionCount = @sizeOf(u64);

    // Number of sessions that this application currently has open with the token
    info.*.ulSessionCount = CKRS.active_sessions();

    // Maximum number of read/write sessions that can be opened with the token at one time by a single application
    info.*.ulMaxRwSessionCount = @sizeOf(u64);

    // Number of read/write sessions that this application currently has open with the token
    info.*.ulRwSessionCount = CKRS.active_sessions();

    // Maximum length in bytes of the PIN
    info.*.ulMaxPinLen = 256;

    // Minimum length in bytes of the PIN
    info.*.ulMinPinLen = 8;

    // The total amount of memory on the token in bytes in which public objects may be stored (see CK_TOKEN_INFO Note below)
    info.*.ulTotalPublicMemory = cki.CK_UNAVAILABLE_INFORMATION;

    // The amount of free (unused) memory on the token in bytes for public objects (see CK_TOKEN_INFO Note below)
    info.*.ulFreePublicMemory = cki.CK_UNAVAILABLE_INFORMATION;

    // The total amount of memory on the token in bytes in which private objects may be stored (see CK_TOKEN_INFO Note below)
    info.*.ulTotalPrivateMemory = cki.CK_UNAVAILABLE_INFORMATION;

    // The amount of free (unused) memory on the token in bytes for private objects (see CK_TOKEN_INFO Note below)
    info.*.ulFreePrivateMemory = cki.CK_UNAVAILABLE_INFORMATION;

    // Version number of hardware
    info.*.hardwareVersion = .{ .major = 0, .minor = 0 };

    // Version number of firmware
    info.*.firmwareVersion = .{ .major = 0, .minor = 1 }; // TODO:

    // current time as a character-string of length 16, represented in the format YYYYMMDDhhmmssxx
    info.*.utcTime = make_padded_string("", 16);

    return cki.CKR_OK;
}

export fn C_GetMechanismList(id: cki.CK_SLOT_ID, mechanisms: cki.CK_MECHANISM_TYPE_PTR, count: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetMechanismList id = {}, mechanisms = {*}, count = {*}\n", .{ id, mechanisms, count });

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetMechanismInfo(id: cki.CK_SLOT_ID, kind: cki.CK_MECHANISM_TYPE, info: cki.CK_MECHANISM_INFO_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetMechanismInfo id = {}, type = {}, info = {*}\n", .{ id, kind, info });

    return cki.CKR_DEVICE_ERROR;
}

fn C_InitToken(_: cki.CK_SLOT_ID, _: cki.CK_UTF8CHAR_PTR, _: cki.CK_ULONG, _: cki.CK_UTF8CHAR_PTR) callconv(.C) cki.CK_RV {
    debug("UNSUPORTED C_InitToken\n", .{});

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_InitPIN(_: cki.CK_SESSION_HANDLE, _: cki.CK_UTF8CHAR_PTR, _: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    debug("UNSUPORTED C_InitPIN\n", .{});

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_SetPIN(_: cki.CK_SESSION_HANDLE, _: cki.CK_UTF8CHAR_PTR, _: cki.CK_ULONG, _: cki.CK_UTF8CHAR_PTR, _: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    debug("UNSUPORTED C_SetPIN\n", .{});

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_OpenSession(id: cki.CK_SLOT_ID, flags: cki.CK_FLAGS, app: cki.CK_VOID_PTR, notify: cki.CK_NOTIFY, handle: cki.CK_SESSION_HANDLE_PTR) callconv(.C) cki.CK_RV {
    debug("C_OpenSession id = {}, flags = {}, app = {*}, notify = {*}, handle = {*}\n", .{ id, flags, app, notify, handle });

    if (handle == null) return cki.CKR_ARGUMENTS_BAD;

    if ((flags & cki.CKF_SERIAL_SESSION) == 0) return cki.CKR_SESSION_PARALLEL_NOT_SUPPORTED;

    const h = CKRS.new_session();
    handle.* = h catch return cki.CKR_DEVICE_ERROR;

    var session = &CKRS.sessions[handle.*];

    session.rw = flags & cki.CKF_RW_SESSION != 0;

    if (app != null) {
        // TODO:
    }

    return cki.CKR_OK;
}

export fn C_CloseSession(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    debug("C_CloseSession handle = {}", .{handle});

    const session = CKRS.get_session(handle) catch return cki.CKR_SESSION_HANDLE_INVALID;

    session.* = std.mem.zeroInit(Session, .{});

    CKRS.close_session(handle) catch return cki.CKR_SESSION_HANDLE_INVALID;

    return cki.CKR_OK;
}

export fn C_CloseAllSessions(slot: cki.CK_SLOT_ID) callconv(.C) cki.CK_RV {
    if (slot != 1) return cki.CKR_SLOT_ID_INVALID;

    CKRS.handles = BitSet.initFull();

    for (&CKRS.sessions) |*session| {
        session.*.object_filter = undefined;
        session.*.app = undefined;
    }

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetSessionInfo(handle: cki.CK_SESSION_HANDLE, info: cki.CK_SESSION_INFO_PTR) callconv(.C) cki.CK_RV {
    debug("C_GetSessionInfo handle = {}, info = {*}\n", .{ handle, info });

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetOperationState(handle: cki.CK_SESSION_HANDLE, state: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = state;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SetOperationState(handle: cki.CK_SESSION_HANDLE, state: cki.CK_BYTE_PTR, len: cki.CK_ULONG, encryption_key: cki.CK_OBJECT_HANDLE, auth_key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = state;
    _ = len;
    _ = encryption_key;
    _ = auth_key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Login(handle: cki.CK_SESSION_HANDLE, kind: cki.CK_USER_TYPE, pin: cki.CK_UTF8CHAR_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = kind;
    _ = pin;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Logout(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_CreateObject(handle: cki.CK_SESSION_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG, obj: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = template;
    _ = count;
    _ = obj;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_CopyObject(handle: cki.CK_SESSION_HANDLE, src: cki.CK_OBJECT_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG, dst: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = src;
    _ = template;
    _ = count;
    _ = dst;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DestroyObject(handle: cki.CK_SESSION_HANDLE, object: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = object;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetObjectSize(handle: cki.CK_SESSION_HANDLE, object: cki.CK_OBJECT_HANDLE, size: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = object;
    _ = size;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetAttributeValue(handle: cki.CK_SESSION_HANDLE, object: cki.CK_OBJECT_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    debug("C_GetAttributeValue handle = {}, object = {}, template = {*}, count = {}\n", .{ handle, object, template, count });

    for (0..count) |i| {
        if (template[i].type == cki.CKA_KEY_TYPE) {
            debug("---------------------\n", .{});
            debug("attr type = {x}\n", .{template[i].type});
            debug("len = {}\n", .{template[i].ulValueLen});
            debug("class = {}\n", .{@as(*c_ulong, @ptrCast(@alignCast(template[i].pValue))).*});

            const key_type = @as(*c_ulong, @ptrCast(@alignCast(template[i].pValue)));

            key_type.* = cki.CKK_ECDSA;
        } else if (template[i].type == cki.CKA_LABEL) {
            if (template[i].pValue == null) {
                std.debug.panic("pValue is null", .{});
            } else {
                const value = @as([*]u8, @ptrCast(template[i].pValue))[0..template[i].ulValueLen];
                for (0..template[i].ulValueLen) |j| {
                    debug("{}", .{value[j]});
                }

                std.mem.copyForwards(u8, value, "key1");

                for (0..template[i].ulValueLen) |j| {
                    debug("{}", .{value[j]});
                }

                debug("\n", .{});
            }
        }
    }

    return cki.CKR_OK;
}

export fn C_SetAttributeValue(handle: cki.CK_SESSION_HANDLE, object: cki.CK_OBJECT_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = object;
    _ = template;
    _ = count;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_FindObjectsInit(handle: cki.CK_SESSION_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    debug("C_FindObjectsInit handle = {} template = {*} count = {}\n", .{ handle, template, count });

    for (0..count) |i| {
        debug("type = {}\n", .{template[i].type});
        debug("len = {}\n", .{template[i].ulValueLen});
        debug("class = {}\n", .{@as(*c_ulong, @ptrCast(@alignCast(template[i].pValue))).*});
    }

    CKRS.sessions[handle].object_filter = .{ .attr = template, .len = count };

    return cki.CKR_OK;
}

export fn C_FindObjects(handle: cki.CK_SESSION_HANDLE, object: cki.CK_OBJECT_HANDLE_PTR, max: cki.CK_ULONG, count: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    debug("C_FindObjects handle = {} object = {*} max = {},count = {*}\n", .{ handle, object, max, count });

    const session = CKRS.get_session(handle) catch return cki.CKR_SESSION_HANDLE_INVALID;

    if (session.*.object_filter) |*filter| {
        if (filter.*.total != 0) {
            object.* = 1;
            count.* = 1;

            filter.*.total = 0;
        } else {
            count.* = 0;
        }
    } else {
        count.* = 0;
    }

    return cki.CKR_OK;
}

export fn C_FindObjectsFinal(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    debug("C_FindObjectsFinal handle = {}\n", .{handle});

    CKRS.sessions[handle].object_filter = undefined;

    return cki.CKR_OK;
}

export fn C_EncryptInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Encrypt(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG, encrypted_data: cki.CK_BYTE_PTR, encrypted_data_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;
    _ = encrypted_data;
    _ = encrypted_data_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_EncryptUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;
    _ = encrypted_part;
    _ = encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_EncryptFinal(handle: cki.CK_SESSION_HANDLE, last_encrypted_part: cki.CK_BYTE_PTR, last_encrypted_part_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = last_encrypted_part;
    _ = last_encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DecryptInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Decrypt(handle: cki.CK_SESSION_HANDLE, encrypted_data: cki.CK_BYTE_PTR, encrypted_data_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = encrypted_data;
    _ = encrypted_data_len;
    _ = data;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DecryptUpdate(handle: cki.CK_SESSION_HANDLE, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = encrypted_part;
    _ = encrypted_part_len;
    _ = part;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DecryptFinal(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DigestInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Digest(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG, digest: cki.CK_BYTE_PTR, digest_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;
    _ = digest;
    _ = digest_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DigestUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DigestKey(handle: cki.CK_SESSION_HANDLE, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DigestFinal(handle: cki.CK_SESSION_HANDLE, digest: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = digest;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Sign(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;
    _ = signature;
    _ = signature_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignFinal(handle: cki.CK_SESSION_HANDLE, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = signature;
    _ = signature_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignRecoverInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignRecover(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;
    _ = signature;
    _ = signature_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_VerifyInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_Verify(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;
    _ = signature;
    _ = signature_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_VerifyUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_VerifyFinal(handle: cki.CK_SESSION_HANDLE, signature: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = signature;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_VerifyRecoverInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_VerifyRecover(handle: cki.CK_SESSION_HANDLE, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DigestEncryptUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;
    _ = encrypted_part;
    _ = encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DecryptDigestUpdate(handle: cki.CK_SESSION_HANDLE, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;
    _ = encrypted_part;
    _ = encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SignEncryptUpdate(handle: cki.CK_SESSION_HANDLE, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;
    _ = encrypted_part;
    _ = encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DecryptVerifyUpdate(handle: cki.CK_SESSION_HANDLE, encrypted_part: cki.CK_BYTE_PTR, encrypted_part_len: cki.CK_ULONG, part: cki.CK_BYTE_PTR, len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = part;
    _ = len;
    _ = encrypted_part;
    _ = encrypted_part_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GenerateKey(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG, key: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = template;
    _ = count;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GenerateKeyPair(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, pub_key_template: cki.CK_ATTRIBUTE_PTR, pub_key_template_count: cki.CK_ULONG, priv_key_template: cki.CK_ATTRIBUTE_PTR, priv_key_template_count: cki.CK_ULONG, pub_key: cki.CK_OBJECT_HANDLE_PTR, priv_key: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = pub_key_template;
    _ = pub_key_template_count;
    _ = priv_key_template;
    _ = priv_key_template_count;
    _ = pub_key;
    _ = priv_key;

    return cki.CKR_DEVICE_ERROR;
}

fn C_WrapKey(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, whrapping_key: cki.CK_OBJECT_HANDLE, key: cki.CK_OBJECT_HANDLE, wrapped_key: cki.CK_BYTE_PTR, wrapped_key_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = whrapping_key;
    _ = key;
    _ = wrapped_key;
    _ = wrapped_key_len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_UnwrapKey(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, unwrapping_key: cki.CK_OBJECT_HANDLE, wrapped_key: cki.CK_BYTE_PTR, wrapped_key_len: cki.CK_ULONG, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG, key: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = unwrapping_key;
    _ = wrapped_key;
    _ = wrapped_key_len;
    _ = template;
    _ = count;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_DeriveKey(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, base_key: cki.CK_OBJECT_HANDLE, template: cki.CK_ATTRIBUTE_PTR, count: cki.CK_ULONG, key: cki.CK_OBJECT_HANDLE_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = base_key;
    _ = template;
    _ = count;
    _ = key;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_SeedRandom(handle: cki.CK_SESSION_HANDLE, seed: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = seed;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GenerateRandom(handle: cki.CK_SESSION_HANDLE, data: cki.CK_BYTE_PTR, len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = data;
    _ = len;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_GetFunctionStatus(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_CancelFunction(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_DEVICE_ERROR;
}

export fn C_WaitForSlotEvent(flags: cki.CK_FLAGS, slot: cki.CK_SLOT_ID_PTR, _: cki.CK_VOID_PTR) callconv(.C) cki.CK_RV {
    _ = flags;
    _ = slot;

    return cki.CKR_DEVICE_ERROR;
}

const v2_interface = cki.CK_INTERFACE{
    .flags = 0,
    .pFunctionList = @constCast(&fn_list_v2),
    .pInterfaceName = @constCast("PKCS #11"),
};

const v3_interface = cki.CK_INTERFACE{
    .flags = 0,
    .pFunctionList = @constCast(&fn_list_v3),
    .pInterfaceName = @constCast("PKCS #11"),
};

// v3.00+

export fn C_GetInterface(_: cki.CK_UTF8CHAR_PTR, version: cki.CK_VERSION_PTR, interface: cki.CK_INTERFACE_PTR_PTR, flags: cki.CK_FLAGS) callconv(.C) cki.CK_RV {
    if (interface == null) return cki.CKR_ARGUMENTS_BAD;

    interface.* = null;

    if (flags != 0) return cki.CKR_OK;
    // if (name != null and !std.mem.eql(u8, name, "PKCS #11")) return cki.CKR_OK; # FIXME

    if (version != null) {
        if (version.*.major == 2) {
            interface.* = @constCast(&v2_interface);
        } else if (version.*.major == 3) {
            interface.* = @constCast(&v3_interface);
        }
    }

    return cki.CKR_OK;
}

export fn C_GetInterfaceList(interfaces: cki.CK_INTERFACE_PTR, count: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    if (count == null) return cki.CKR_ARGUMENTS_BAD;

    if (interfaces == null) {
        count.* = 2;
    } else {
        interfaces[0].pInterfaceName = v2_interface.pInterfaceName;
        interfaces[0].pInterfaceName = v2_interface.pInterfaceName;
        interfaces[0].pInterfaceName = v2_interface.pInterfaceName;

        interfaces[0].pInterfaceName = v3_interface.pInterfaceName;
        interfaces[0].pInterfaceName = v3_interface.pInterfaceName;
        interfaces[0].pInterfaceName = v3_interface.pInterfaceName;
    }

    return cki.CKR_OK;
}

export fn C_LoginUser(handle: cki.CK_SESSION_HANDLE, kind: cki.CK_USER_TYPE, pin: cki.CK_UTF8CHAR_PTR, len: cki.CK_ULONG, name: cki.CK_UTF8CHAR_PTR, name_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = kind;
    _ = pin;
    _ = len;
    _ = name;
    _ = name_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_SessionCancel(handle: cki.CK_SESSION_HANDLE, flags: cki.CK_FLAGS) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = flags;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageEncryptInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_EncryptMessage(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, text: cki.CK_BYTE_PTR, text_len: cki.CK_ULONG, cipher: cki.CK_BYTE_PTR, cipher_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = data;
    _ = data_len;
    _ = text;
    _ = text_len;
    _ = cipher;
    _ = cipher_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_EncryptMessageBegin(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_EncryptMessageNext(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, text: cki.CK_BYTE_PTR, text_len: cki.CK_ULONG, cipher: cki.CK_BYTE_PTR, cipher_len: cki.CK_ULONG_PTR, flags: cki.CK_FLAGS) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = text;
    _ = text_len;
    _ = cipher;
    _ = cipher_len;
    _ = flags;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageEncryptFinal(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageDecryptInit(handle: cki.CK_SESSION_HANDLE, meachanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = meachanism;
    _ = key;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

fn C_DecryptMessage(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, cipher: cki.CK_BYTE_PTR, cipher_len: cki.CK_ULONG, text: cki.CK_BYTE_PTR, text_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = text;
    _ = text_len;
    _ = data;
    _ = data_len;
    _ = cipher;
    _ = cipher_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_DecryptMessageBegin(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_DecryptMessageNext(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, cipher: cki.CK_BYTE_PTR, cipher_len: cki.CK_ULONG, text: cki.CK_BYTE_PTR, text_len: cki.CK_ULONG_PTR, flags: cki.CK_FLAGS) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = text;
    _ = text_len;
    _ = cipher;
    _ = cipher_len;
    _ = flags;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageDecryptFinal(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageSignInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_SignMessage(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_SignMessageBegin(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_SignMessageNext(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG_PTR) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageSignFinal(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageVerifyInit(handle: cki.CK_SESSION_HANDLE, mechanism: cki.CK_MECHANISM_PTR, key: cki.CK_OBJECT_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = mechanism;
    _ = key;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_VerifyMessage(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_VerifyMessageBegin(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_VerifyMessageNext(handle: cki.CK_SESSION_HANDLE, param: cki.CK_VOID_PTR, param_len: cki.CK_ULONG, data: cki.CK_BYTE_PTR, data_len: cki.CK_ULONG, signature: cki.CK_BYTE_PTR, signature_len: cki.CK_ULONG) callconv(.C) cki.CK_RV {
    _ = handle;
    _ = param;
    _ = param_len;
    _ = signature;
    _ = signature_len;
    _ = data;
    _ = data_len;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}

export fn C_MessageVerifyFinal(handle: cki.CK_SESSION_HANDLE) callconv(.C) cki.CK_RV {
    _ = handle;

    return cki.CKR_FUNCTION_NOT_SUPPORTED;
}
