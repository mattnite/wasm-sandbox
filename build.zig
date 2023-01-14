const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const wasm3 = b.addExecutable("wasm3", null);
    wasm3.setTarget(target);
    wasm3.setBuildMode(mode);
    wasm3.install();
    wasm3.linkLibC();

    if (target.getCpuArch() == .wasm32 and target.getOsTag() == .wasi) {
        wasm3.linkSystemLibrary("wasi-emulated-process-clocks");
    }

    wasm3.addIncludePath("source");
    wasm3.addCSourceFiles(&.{
        "deps/wasm3/source/m3_api_libc.c",
        "deps/wasm3/source/m3_api_meta_wasi.c",
        "deps/wasm3/source/m3_api_tracer.c",
        "deps/wasm3/source/m3_api_uvwasi.c",
        "deps/wasm3/source/m3_api_wasi.c",
        "deps/wasm3/source/m3_bind.c",
        "deps/wasm3/source/m3_code.c",
        "deps/wasm3/source/m3_compile.c",
        "deps/wasm3/source/m3_core.c",
        "deps/wasm3/source/m3_env.c",
        "deps/wasm3/source/m3_exec.c",
        "deps/wasm3/source/m3_function.c",
        "deps/wasm3/source/m3_info.c",
        "deps/wasm3/source/m3_module.c",
        "deps/wasm3/source/m3_parse.c",
        "deps/wasm3/platforms/app/main.c",
    }, &.{
        "-I./deps/wasm3/source",
        "-Dd_m3HasWASI",
        "-fno-sanitize=undefined", // TODO investigate UB sites in the codebase, then delete this line.
    });

    const exe = b.addExecutable("hello", "src/main.zig");
    exe.setTarget(std.zig.CrossTarget{ .cpu_arch = .wasm32, .os_tag = .wasi });
    exe.setBuildMode(.ReleaseSmall);
    exe.install();
}
