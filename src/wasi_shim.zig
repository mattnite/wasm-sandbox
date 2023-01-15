const std = @import("std");
const StructField = std.builtin.Type.StructField;
const assert = std.debug.assert;

const c = @cImport({
    @cInclude("wasm3.h");
    @cInclude("wasi_core.h");
    @cInclude("m3_api_wasi.h");
});

const wasi = struct {
    const iovec_t = extern struct {
        buf: c.__wasi_size_t,
        buf_len: c.__wasi_size_t,
    };
};

// stack pointer seems to never be null
const RawCall = fn (c.IM3Runtime, c.IM3ImportContext, ?[*]u64, ?*anyopaque) callconv(.C) ?*const anyopaque;

var wasi_context: ?*c.m3_wasi_context_t = null;

export fn m3_GetWasiContext() ?*c.m3_wasi_context_t {
    return wasi_context;
}

const Error = LinkError || Traps;

const Traps = error{
    TrapExit,
    TrapAbort,
};

const LinkError = error{
    ModuleNotLinked,
    ModuleAlreadyLinked,
    FunctionLookupFailed,
    FunctionImportMissing,
    MalformedFunctionSignature,
};

fn linkErrorFromResult(res: c.M3Result) ?LinkError {
    return if (c.m3Err_none == res)
        null
    else if (c.m3Err_moduleNotLinked == res)
        error.ModuleNotLinked
    else if (c.m3Err_moduleAlreadyLinked == res)
        error.ModuleAlreadyLinked
    else if (c.m3Err_functionLookupFailed == res)
        error.FunctionLookupFailed
    else if (c.m3Err_functionImportMissing == res)
        error.FunctionImportMissing
    else if (c.m3Err_malformedFunctionSignature == res)
        error.MalformedFunctionSignature
    else {
        if (res != null) {
            std.log.err("{s}", .{res});
        }

        @panic("unhandled error from m3_LinkRawFunction");
    };
}

fn errorToResult(err: Error) c.M3Result {
    return switch (err) {
        error.ModuleNotLinked => c.m3Err_moduleNotLinked,
        error.ModuleAlreadyLinked => c.m3Err_moduleAlreadyLinked,
        error.FunctionLookupFailed => c.m3Err_functionLookupFailed,
        error.FunctionImportMissing => c.m3Err_functionImportMissing,
        error.MalformedFunctionSignature => c.m3Err_malformedFunctionSignature,

        // traps
        error.TrapExit => c.m3Err_trapExit,
        error.TrapAbort => c.m3Err_trapAbort,
    };
}

// standin for c.IM3Module
const Module = opaque {
    fn link(
        module: *Module,
        module_name: [:0]const u8,
        function_name: [:0]const u8,
        comptime function: anytype,
    ) LinkError!void {
        const signature = M3Signature.init(@TypeOf(function));
        const raw_function = m3RawFunction(function);
        std.log.info("signature: {s}", .{signature.toString()});

        const result = c.m3_LinkRawFunction(
            @ptrCast(c.IM3Module, module),
            module_name.ptr,
            function_name.ptr,
            signature.toString().ptr,
            raw_function,
        );

        if (linkErrorFromResult(result)) |err|
            return err;
    }

    fn linkExtra(
        module: *Module,
        module_name: [:0]const u8,
        function_name: [:0]const u8,
        userdata: ?*anyopaque,
        comptime function: anytype,
    ) LinkError!void {
        const signature = M3Signature.init(@TypeOf(function));
        std.log.info("signature: {s}", .{signature.toString()});
        const raw_function = m3RawFunction(function);
        if (linkErrorFromResult(c.m3_LinkRawFunctionEx(
            @ptrCast(c.IM3Module, module),
            module_name.ptr,
            function_name.ptr,
            signature.toString().ptr,
            raw_function,
            userdata,
        ))) |err| {
            return err;
        }
    }

    fn linkIgnoreLookupFailure(
        module: *Module,
        module_name: [:0]const u8,
        function_name: [:0]const u8,
        comptime function: anytype,
    ) LinkError!void {
        module.link(module_name, function_name, function) catch |err| {
            if (err != error.FunctionLookupFailed)
                return err;
        };
    }

    fn linkExtraIgnoreLookupFailure(
        module: *Module,
        module_name: [:0]const u8,
        function_name: [:0]const u8,
        userdata: ?*anyopaque,
        comptime function: anytype,
    ) LinkError!void {
        module.linkExtra(module_name, function_name, userdata, function) catch |err| {
            if (err != error.FunctionLookupFailed)
                return err;
        };
    }
};

const M3Signature = struct {
    return_type: ?type,
    params: []const std.builtin.Type.Fn.Param,

    fn init(comptime Fn: type) M3Signature {
        const type_info = @typeInfo(Fn);

        assert(type_info.Fn.params[0].type.? == *c.M3Runtime);
        assert(type_info.Fn.params[1].type.? == *c.M3ImportContext);

        const eu_info = @typeInfo(type_info.Fn.return_type.?).ErrorUnion;
        assert(Error == eu_info.error_set);
        return M3Signature{
            .return_type = eu_info.payload,
            .params = type_info.Fn.params[2..],
        };
    }

    fn toString(comptime signature: M3Signature) [:0]const u8 {
        comptime var ret: [:0]const u8 = switch (signature.return_type.?) {
            u32 => "i",
            void => "v",
            else => unreachable,
        };

        ret = ret ++ "(";
        inline for (signature.params) |param| {
            const param_type_info = @typeInfo(param.type.?);
            ret = ret ++ switch (param_type_info) {
                .Int => |int| switch (int.bits) {
                    32 => "i",
                    64 => "I",
                    else => unreachable,
                },
                .Pointer => "*",
                else => unreachable,
            };
        }

        ret = ret ++ ")";

        return ret;
    }
};

fn m3ApiOffsetToPtr(comptime T: type, memory: *anyopaque, sp: *[*]u64) T {
    const type_info = @typeInfo(T);
    assert(type_info == .Pointer);

    const offset = @ptrCast(*u32, sp).*;
    sp.* += @sizeOf(u64);

    const mem = @ptrCast([*]u8, memory);
    return @ptrCast(T, @alignCast(@alignOf(T), mem + offset));
}

fn m3RawFunction(comptime function: anytype) RawCall {
    const signature = M3Signature.init(@TypeOf(function));
    var fields: [signature.params.len]StructField = undefined;
    for (signature.params) |param, i|
        fields[i] = StructField{
            .name = std.fmt.comptimePrint("{}", .{i}),
            .type = param.type.?,
            .default_value = null,
            .is_comptime = false,
            .alignment = @sizeOf(param.type.?),
        };

    const ArgsTuple = @Type(.{
        .Struct = .{
            .layout = .Auto,
            .backing_integer = null,
            .fields = &fields,
            .decls = &.{},
            .is_tuple = true,
        },
    });

    return struct {
        fn tmp(
            runtime: c.IM3Runtime,
            import_context: c.IM3ImportContext,
            stack_pointer: ?[*]u64,
            memory: ?*anyopaque,
        ) callconv(.C) ?*const anyopaque {
            var sp = stack_pointer.?;
            const Return = signature.return_type.?;
            const return_loc = if (Return != void) return_loc: {
                assert(@sizeOf(Return) <= @sizeOf(u64));
                var ret = @ptrCast(*Return, sp);
                sp += @sizeOf(u64);

                break :return_loc ret;
            } else {};

            var args: ArgsTuple = undefined;
            inline for (args) |_, i| {
                const Arg = @TypeOf(args[i]);
                const arg_info = @typeInfo(Arg);
                if (arg_info == .Pointer) {
                    args[i] = m3ApiOffsetToPtr(Arg, memory.?, &sp);
                } else {
                    args[i] = @ptrCast(*Arg, sp).*;
                    sp += @sizeOf(u64);
                }
            }

            const err_union = @call(.auto, function, .{
                @ptrCast(*c.M3Runtime, runtime),
                @ptrCast(*c.M3ImportContext, import_context),
            } ++ args);
            return if (Return != void) ret: {
                return_loc.* = err_union catch |err| {
                    break :ret errorToResult(err);
                };

                break :ret c.m3Err_none;
            } else c.m3Err_none;
        }
    }.tmp;
}

const namespaces = [_][:0]const u8{
    "wasi_unstable",
    "wasi_snapshot_preview1",
};

fn linkWASI(module: *Module) !void {
    if (wasi_context == null) {
        wasi_context = std.heap.c_allocator.create(c.m3_wasi_context_t) catch @panic("failed to allocate ctx");
        wasi_context.?.* = .{
            .exit_code = 0,
            .argc = 0,
            .argv = null,
        };
    }

    try module.linkIgnoreLookupFailure("wasi_unstable", "fd_seek", unstable_fd_seek);
    try module.linkIgnoreLookupFailure("wasi_snapshot_preview1", "fd_seek", snapshot_preview1_fd_seek);
    inline for (@typeInfo(functions).Struct.decls) |decl| {
        const decl_name = std.fmt.comptimePrint("{s}", .{decl.name});

        for (namespaces) |ns| {
            std.log.debug("ns: {s}, decl_name: {s}", .{ ns, decl_name });
            try module.linkIgnoreLookupFailure(ns, decl_name, @field(functions, decl.name));
        }
    }

    inline for (@typeInfo(functions_extra).Struct.decls) |decl| {
        const decl_name = std.fmt.comptimePrint("{s}", .{decl.name});

        for (namespaces) |ns| {
            std.log.debug("ns: {s}, decl_name: {s}", .{ ns, decl_name });
            try module.linkExtraIgnoreLookupFailure(ns, decl_name, wasi_context, @field(functions_extra, decl.name));
        }
    }
}

export fn m3_LinkWASI(module: *Module) c.M3Result {
    return if (linkWASI(module))
        c.m3Err_none
    else |err|
        errorToResult(err);
}

//==============================================================================
// implementations
//==============================================================================
fn unstable_fd_seek(
    runtime: *c.M3Runtime,
    import_context: *c.M3ImportContext,
    fd: c.__wasi_fd_t,
    offset: c.__wasi_filedelta_t,
    wasi_whence: u32,
    result: *c.__wasi_filesize_t,
) Error!u32 {
    _ = runtime;
    _ = import_context;
    _ = fd;
    _ = offset;
    _ = wasi_whence;
    _ = result;
    return 0;
}

fn snapshot_preview1_fd_seek(
    runtime: *c.M3Runtime,
    import_context: *c.M3ImportContext,
    fd: c.__wasi_fd_t,
    offset: c.__wasi_filedelta_t,
    wasi_whence: u32,
    result: *c.__wasi_filesize_t,
) Error!u32 {
    _ = runtime;
    _ = import_context;
    _ = fd;
    _ = offset;
    _ = wasi_whence;
    _ = result;
    return 0;
}

const functions = struct {
    fn fd_write(
        runtime: *c.M3Runtime,
        import_context: *c.M3ImportContext,
        fd: c.__wasi_fd_t,
        wasi_iovs: *wasi.iovec_t,
        iovs_len: u32,
        nwritten: *c.__wasi_size_t,
    ) Error!u32 {
        _ = runtime;
        _ = import_context;
        _ = fd;
        _ = wasi_iovs;
        _ = iovs_len;
        _ = nwritten;
        return error.TrapAbort;
    }
};

const functions_extra = struct {
    fn proc_exit(
        runtime: *c.M3Runtime,
        import_context: *c.M3ImportContext,
        code: u32,
    ) Error!void {
        _ = runtime;

        const context = @ptrCast(*c.m3_wasi_context_t, @alignCast(@alignOf(*c.m3_wasi_context_t), import_context.userdata));
        context.exit_code = @intCast(i32, code);

        return error.TrapExit;
    }
};
