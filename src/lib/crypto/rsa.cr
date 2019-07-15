@[Link("crypto")]
lib LibCrypto
  alias PasswordCallback = (UInt8*, Int32, Int32, Void*) -> Int32

  alias RSA = Void*

  RSA_F4 = 65537

  fun rsa_new = RSA_new : RSA
  fun rsa_generate_key = RSA_generate_key_ex(rsa : RSA, bits : Int32, e : BIGNUM, cb : BN_GENCB) : Int32
  fun rsapublickey_dup = RSAPublicKey_dup(rsa : RSA) : RSA
  fun evp_pkey_get1_rsa = EVP_PKEY_get1_RSA(pk : EVP_PKEY) : RSA
  fun rsa_print = RSA_print(bio : BIO, rsa : RSA, off : Int32) : Int32
  fun i2d_rsaprivatekey = i2d_RSAPrivateKey(rsa : RSA, buf : UInt8**) : Int32
  fun i2d_rsa_pubkey = i2d_RSA_PUBKEY(rsa : RSA, buf : UInt8**) : Int32
  fun rsa_size = RSA_size(rsa : RSA) : Int32

  enum Padding
    PKCS1_PADDING      = 1
    SSLV23_PADDING     = 2
    NO_PADDING         = 3
    PKCS1_OAEP_PADDING = 4
    X931_PADDING       = 5
    PKCS1_PSS_PADDING  = 6
  end

  fun rsa_public_encrypt = RSA_public_encrypt(flen : Int32, from : UInt8*, to : UInt8*, rsa : RSA, p : Padding) : Int32
  fun rsa_public_decrypt = RSA_public_decrypt(flen : Int32, from : UInt8*, to : UInt8*, rsa : RSA, p : Padding) : Int32
  fun rsa_private_encrypt = RSA_private_encrypt(flen : Int32, from : UInt8*, to : UInt8*, rsa : RSA, p : Padding) : Int32
  fun rsa_private_decrypt = RSA_private_decrypt(flen : Int32, from : UInt8*, to : UInt8*, rsa : RSA, p : Padding) : Int32

  fun pem_write_bio_rsaprivatekey = PEM_write_bio_RSAPrivateKey(bio : BIO, rsa : RSA, enc : EVP_CIPHER,
                                                                kstr : UInt8*, klen : Int32, cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_write_bio_rsa_pubkey = PEM_write_bio_RSA_PUBKEY(bio : BIO, rsa : RSA)
  fun rand_bytes = RAND_bytes(buf : UInt8*, num : Int32) : Int32
end
