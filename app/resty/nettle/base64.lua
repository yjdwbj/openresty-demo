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
typedef struct base64_encode_ctx {
  unsigned word;
  unsigned bits;
} BASE64_ENCODE_CTX;
typedef struct base64_decode_ctx {
  unsigned word;
  unsigned bits;
  unsigned padding;
} BASE64_DECODE_CTX;
void   nettle_base64_encode_init   (struct base64_encode_ctx *ctx);
void   nettle_base64url_encode_init(struct base64_encode_ctx *ctx);
size_t nettle_base64_encode_single (struct base64_encode_ctx *ctx, uint8_t *dst, uint8_t src);
size_t nettle_base64_encode_update (struct base64_encode_ctx *ctx, uint8_t *dst, size_t length, const uint8_t *src);
size_t nettle_base64_encode_final  (struct base64_encode_ctx *ctx, uint8_t *dst);
void   nettle_base64_encode_raw    (uint8_t *dst, size_t length, const uint8_t *src);
void   nettle_base64_decode_init   (struct base64_decode_ctx *ctx);
void   nettle_base64url_decode_init(struct base64_decode_ctx *ctx);
int    nettle_base64_decode_single (struct base64_decode_ctx *ctx, uint8_t *dst, uint8_t src);
int    nettle_base64_decode_update (struct base64_decode_ctx *ctx, size_t *dst_length, uint8_t *dst, size_t src_length, const uint8_t *src);
int    nettle_base64_decode_final  (struct base64_decode_ctx *ctx);
]]
local ctxenc = ffi_typeof "BASE64_ENCODE_CTX[1]"
local ctxdec = ffi_typeof "BASE64_DECODE_CTX[1]"

local length = ffi_new "size_t[1]"
local uint8t = ffi_typeof "uint8_t[?]"
local buf8   = ffi_new(uint8t, 1)
local buf16  = ffi_new(uint8t, 2)
local buf24  = ffi_new(uint8t, 3)

local encoder = {}
encoder.__index = encoder

function encoder.new(urlsafe)
    local ctx = ffi_new(ctxenc)
    if urlsafe then
        lib.nettle_base64url_encode_init(ctx)
    else
        lib.nettle_base64_encode_init(ctx)
    end
    return setmetatable({ context = ctx }, encoder)
end

function encoder:single(src)
    local len = tonumber(lib.nettle_base64_encode_single(self.context, buf16, (src:byte())))
    return ffi_str(buf16, len), tonumber(len)
end

function encoder:update(src)
    local len = #src
    local dln = (len * 8 + 4) / 6
    local dst = ffi_new(uint8t, dln)
    local len = tonumber(lib.nettle_base64_encode_update(self.context, dst, len, src))
    return ffi_str(dst, len), len
end

function encoder:final()
    local len = tonumber(lib.nettle_base64_encode_final(self.context, buf24))
    return ffi_str(buf24, len), len
end

local decoder = {}
decoder.__index = decoder

function decoder.new(urlsafe)
    local ctx = ffi_new(ctxdec)
    if urlsafe then
        lib.nettle_base64url_decode_init(ctx)
    else
        lib.nettle_base64_decode_init(ctx)
    end
    return setmetatable({ context = ctx }, decoder)
end

function decoder:single(src)
    local len = tonumber(lib.nettle_base64_decode_single(self.context, buf8, (src:byte())))
    return ffi_str(buf8, len), len

end

function decoder:update(src)
    local len = #src
    local dst = ffi_new(uint8t, (len + 1) * 6 / 8)
    lib.nettle_base64_decode_update(self.context, length, dst, len, src)
    local len = tonumber(length[0])
    return ffi_str(dst, len), len
end

function decoder:final()
    return (assert(lib.nettle_base64_decode_final(self.context) == 1, "Base64 final padding is incorrect."))
end

local base64 = setmetatable({ encoder = encoder, decoder = decoder }, {
    __call = function(_, src)
        local len = #src
        local dln = (len + 2) / 3 * 4
        local dst = ffi_new(uint8t, dln)
        lib.nettle_base64_encode_raw(dst, len, src)
        return ffi_str(dst, dln)
    end
})

function base64.encode(src, urlsafe)
    local ctx = ffi_new(ctxenc)
    if urlsafe then
        lib.nettle_base64url_encode_init(ctx)
    else
        lib.nettle_base64_encode_init(ctx)
    end
    local len = #src
    local dln = (len * 8 + 4) / 6
    local dst = ffi_new(uint8t, dln)
    dst = ffi_str(dst, lib.nettle_base64_encode_update(ctx, dst, len, src))
    return dst .. ffi_str(buf24, lib.nettle_base64_encode_final(ctx, buf24))
end

function base64.decode(src, urlsafe)
    local ctx = ffi_new(ctxdec)
    local len = #src
    local dst = ffi_new(uint8t, (len + 1) * 6 / 8)
    if urlsafe then
        lib.nettle_base64url_decode_init(ctx)
    else
        lib.nettle_base64_decode_init(ctx)
    end
    lib.nettle_base64_decode_update(ctx, length, dst, len, src)
    assert(lib.nettle_base64_decode_final(ctx) == 1, "Base64 final padding is incorrect.")
    return ffi_str(dst, length[0])
end

return base64