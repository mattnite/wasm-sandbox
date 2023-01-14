const c = @cImport({
    @cInclude("m3_api_wasi.h");
});

export fn m3_LinkWASI(module: c.IM3Module) c.M3Result {
    _ = module;
    return c.m3Err_none;
}

var ctx = c.m3_wasi_context_t{
    .argc = 0,
    .argv = null,
    .exit_code = 0,
};

export fn m3_GetWasiContext() *c.m3_wasi_context_t {
    return &ctx;
}
