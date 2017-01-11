local lib          = require "resty.nettle.library"
local ffi          = require "ffi"
local ffi_new      = ffi.new
local ffi_typeof   = ffi.typeof
local ffi_cdef     = ffi.cdef
local ffi_str      = ffi.string
local assert       = assert
local tonumber     = tonumber
local setmetatable = setmetatable

ffi_cdef[[
typedef struct base16_decode_ctx {
  unsigned word;
  unsigned bits;
} BASE16_DECODE_CTX;
void nettle_base16_encode_single(uint8_t *dst, uint8_t src);
void nettle_base16_encode_update(uint8_t *dst, size_t length, const uint8_t *src);
void nettle_base16_decode_init(struct base16_decode_ctx *ctx);
int  nettle_base16_decode_single(struct base16_decode_ctx *ctx, uint8_t *dst, uint8_t src);
int  nettle_base16_decode_update(struct base16_decode_ctx *ctx, size_t *dst_length, uint8_t *dst, size_t src_length, const uint8_t *src);
int  nettle_base16_decode_final(struct base16_decode_ctx *ctx);
]]
local ctxdec = ffi_typeof "BASE16_DECODE_CTX[1]"

local length = ffi_new "size_t[1]"
local uint8t = ffi_typeof "uint8_t[?]"
local buf8   = ffi_new(uint8t, 1)
local buf16  = ffi_new(uint8t, 2)

local encoder = {}
encoder.__index = encoder

function encoder.new()
    return setmetatable({}, encoder)
end

function encoder:single(src)
    lib.nettle_base16_encode_single(buf16, (src:byte()))
    return ffi_str(buf16, 2)
end

function encoder:update(src)
    local len = #src
    local dln = len * 2
    local dst = ffi_new(uint8t, dln)
    lib.nettle_base16_encode_update(dst, len, src)
    return ffi_str(dst, dln)
end

local decoder = {}
decoder.__index = decoder

function decoder.new()
    local ctx = ffi_new(ctxdec)
    lib.nettle_base16_decode_init(ctx)
    return setmetatable({ context = ctx }, decoder)
end

function decoder:single(src)
    local len = lib.nettle_base16_decode_single(self.context, buf8, (src:byte()))
    return ffi_str(buf8, len), len

end

function decoder:update(src)
    local len = #src
    local dst = ffi_new(uint8t, (len + 1) / 2)
    lib.nettle_base16_decode_update(self.context, length, dst, len, src)
    local len = tonumber(length[0])
    return ffi_str(dst, len), len
end

function decoder:final()
    return (assert(lib.nettle_base16_decode_final(self.context) == 1, "Base16 end of data is incorrect."))
end

local base16 = { encoder = encoder, decoder = decoder }

function base16.encode(src)
    local len = #src
    local dln = len * 2
    local dst = ffi_new(uint8t, dln)
    lib.nettle_base16_encode_update(dst, len, src)
    return ffi_str(dst, dln)
end

function base16.decode(src)
    local ctx = ffi_new(ctxdec)
    local len = #src
    local dst = ffi_new(uint8t, (len + 1) / 2)
    lib.nettle_base16_decode_init(ctx)
    lib.nettle_base16_decode_update(ctx, length, dst, len, src)
    assert(lib.nettle_base16_decode_final(ctx) == 1, "Base16 end of data is incorrect.")
    return ffi_str(dst, length[0])
end

return base16