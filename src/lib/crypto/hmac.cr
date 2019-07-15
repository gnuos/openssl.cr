require "./evp"

@[Link("crypto")]
lib LibCrypto
  struct HMAC_CTX_Struct
    md : EVP_MD
    md_ctx : EVP_MD_CTX_Struct
    i_ctx : EVP_MD_CTX_Struct
    o_ctx : EVP_MD_CTX_Struct
    key_length : UInt32
    key : UInt8[128]
  end

  alias HMAC_CTX = HMAC_CTX_Struct*

  fun hmac_ctx_init = HMAC_CTX_init(ctx : HMAC_CTX)
  fun hmac_ctx_cleanup = HMAC_CTX_cleanup(ctx : HMAC_CTX)
  fun hmac_init_ex = HMAC_Init_ex(ctx : HMAC_CTX, key : Void*, len : Int32, md : EVP_MD, engine : Void*) : Int32
  fun hmac_update = HMAC_Update(ctx : HMAC_CTX, data : UInt8*, len : LibC::SizeT) : Int32
  fun hmac_final = HMAC_Final(ctx : HMAC_CTX, md : UInt8*, len : UInt32*) : Int32
  fun hmac_ctx_copy = HMAC_CTX_copy(dst : HMAC_CTX, src : HMAC_CTX) : Int32
end
