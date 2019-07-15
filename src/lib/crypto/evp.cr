@[Link("crypto")]
lib LibCrypto
  alias EVP_MD = Void*

  struct EVP_MD_CTX_Struct
    digest : EVP_MD
    engine : Void*
    flags : UInt32
    pctx : Void*
    update_fun : Void*
  end

  alias EVP_MD_CTX = EVP_MD_CTX_Struct*

  fun evp_md_ctx_create = EVP_MD_CTX_new : EVP_MD_CTX
  fun evp_get_digestbyname = EVP_get_digestbyname(name : UInt8*) : EVP_MD
  fun evp_digestinit_ex = EVP_DigestInit_ex(ctx : EVP_MD_CTX, type : EVP_MD, engine : Void*) : Int32
  fun evp_md_ctx_destroy = EVP_MD_CTX_free(ctx : EVP_MD_CTX)
  fun evp_md_ctx_md = EVP_MD_CTX_md(ctx : EVP_MD_CTX) : EVP_MD
  fun evp_digestupdate = EVP_DigestUpdate(ctx : EVP_MD_CTX, data : UInt8*, count : LibC::SizeT) : Int32
  fun evp_md_size = EVP_MD_size(md : EVP_MD) : Int32
  fun evp_digestfinal_ex = EVP_DigestFinal_ex(ctx : EVP_MD_CTX, md : UInt8*, size : UInt32*) : Int32
  fun evp_md_block_size = EVP_MD_block_size(md : EVP_MD) : Int32
  fun evp_md_ctx_copy = EVP_MD_CTX_copy(dst : EVP_MD_CTX, src : EVP_MD_CTX) : Int32

  fun evp_bytestokey = EVP_BytesToKey(ctype : EVP_CIPHER, md : EVP_MD, salt : UInt8*, pass : UInt8*, passlen : Int32, iter : Int32, key : UInt8*, iv : UInt8*) : Int32

  alias EVP_CIPHER = Void*
  alias EVP_CIPHER_CTX = Void*

  fun evp_get_cipherbyname = EVP_get_cipherbyname(name : UInt8*) : EVP_CIPHER

  fun evp_cipher_name = EVP_CIPHER_name(cipher : EVP_CIPHER) : UInt8*
  fun evp_cipher_nid = EVP_CIPHER_nid(cipher : EVP_CIPHER) : Int32
  fun evp_cipher_block_size = EVP_CIPHER_block_size(cipher : EVP_CIPHER) : Int32
  fun evp_cipher_key_length = EVP_CIPHER_key_length(cipher : EVP_CIPHER) : Int32
  fun evp_cipher_iv_length = EVP_CIPHER_iv_length(cipher : EVP_CIPHER) : Int32

  fun evp_cipher_ctx_new = EVP_CIPHER_CTX_new : EVP_CIPHER_CTX
  fun evp_cipher_ctx_free = EVP_CIPHER_CTX_free(ctx : EVP_CIPHER_CTX)
  fun evp_cipherinit_ex = EVP_CipherInit_ex(ctx : EVP_CIPHER_CTX, type : EVP_CIPHER, engine : Void*, key : UInt8*, iv : UInt8*, enc : Int32) : Int32
  fun evp_cipherupdate = EVP_CipherUpdate(ctx : EVP_CIPHER_CTX, out_buf : UInt8*, outl : Int32*, in_buf : UInt8*, inl : Int32) : Int32
  fun evp_cipherfinal_ex = EVP_CipherFinal_ex(ctx : EVP_CIPHER_CTX, out_buf : UInt8*, outl : Int32*) : Int32
  fun evp_cipher_ctx_set_padding = EVP_CIPHER_CTX_set_padding(ctx : EVP_CIPHER_CTX, padding : Int32) : Int32
  fun evp_cipher_ctx_cipher = EVP_CIPHER_CTX_cipher(ctx : EVP_CIPHER_CTX) : EVP_CIPHER

  alias EVP_PKEY = Void*

  fun evp_pkey_bits = EVP_PKEY_bits(pkey : EVP_PKEY) : Int32
  fun evp_pkey_size = EVP_PKEY_size(pkey : EVP_PKEY) : Int32
  fun evp_signfinal = EVP_SignFinal(ctx : EVP_MD_CTX, sigret : UInt8*, siglen : UInt32*, pkey : EVP_PKEY) : Int32
  fun evp_verifyfinal = EVP_VerifyFinal(ctx : EVP_MD_CTX, sigbuf : UInt8*, siglen : UInt32, pkey : EVP_PKEY) : Int32
  fun evp_pkey_new = EVP_PKEY_new : EVP_PKEY
  fun evp_pkey_free = EVP_PKEY_free(pkey : EVP_PKEY)
  fun evp_pkey_assign = EVP_PKEY_assign(pkey : EVP_PKEY, type : Int32, key : Void*) : Int32

  NID_undef                =   0
  NID_rsaEncryption        =   6
  NID_dsa                  = 116
  NID_X9_62_id_ecPublicKey = 408

  EVP_PKEY_NONE = NID_undef
  EVP_PKEY_RSA  = NID_rsaEncryption
  EVP_PKEY_DSA  = NID_dsa
  EVP_PKEY_EC   = NID_X9_62_id_ecPublicKey
end
