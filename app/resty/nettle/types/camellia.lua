require "resty.nettle.types.gcm"

local ffi      = require "ffi"
local ffi_cdef = ffi.cdef

ffi_cdef[[
typedef struct camellia128_ctx {
  uint64_t keys[24];
} CAMELLIA128_CTX;
typedef struct camellia256_ctx {
  uint64_t keys[32];
} CAMELLIA256_CTX;
typedef struct gcm_camellia128_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct camellia128_ctx cipher;
} GCM_CAMELLIA128_CTX;
typedef struct gcm_camellia256_ctx {
  struct gcm_key key;
  struct gcm_ctx gcm;
  struct camellia256_ctx cipher;
} GCM_CAMELLIA256_CTX;
]]