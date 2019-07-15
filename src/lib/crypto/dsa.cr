@[Link("crypto")]
lib LibCrypto
  alias DSA = Void*

  fun dsa_generate_parameters = DSA_generate_parameters(bit : Int32, seed : UInt8*, seed_len : Int32, counter_ret : Int32*,
                                                        h_ret : UInt64*, cb : Void*, user_data : Void*) : DSA
  fun dsa_generate_key = DSA_generate_key(dsa : DSA) : Int32
  fun dsa_free = DSA_free(dsa : DSA)
  fun pem_read_bio_dsaprivatekey = PEM_read_bio_DSAPrivateKey(bio : BIO, dsa : DSA*, cb : PasswordCallback, user_data : Void*) : DSA
  fun d2i_dsaprivatekey_bio = d2i_DSAPrivateKey_bio(bio : BIO, dsa : DSA*) : DSA
  fun d2i_dsa_pubkey_bio = d2i_DSA_PUBKEY_bio(bio : BIO, dsa : DSA*) : DSA

  fun pem_write_bio_dsaprivatekey = PEM_write_bio_DSAPrivateKey(bio : BIO, dsa : DSA, c : EVP_CIPHER, kstr : UInt8*, klen : Int32,
                                                                cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_write_bio_dsa_pubkey = PEM_write_bio_DSA_PUBKEY(bio : BIO, dsa : DSA) : Int32
  fun evp_pkey_get1_dsa = EVP_PKEY_get1_DSA(pkey : EVP_PKEY) : DSA
  fun i2d_dsaprivatekey = i2d_DSAPrivateKey(dsa : DSA, pp : UInt8**) : Int32
  fun i2d_dsa_pubkey = i2d_DSA_PUBKEY(dsa : DSA, pp : UInt8**) : Int32
  fun dsa_size = DSA_size(dsa : DSA) : Int32
  fun dsa_sign = DSA_sign(type : Int32, dgst : UInt8*, dlen : Int32, sig : UInt8*, siglen : Int32*, dsa : DSA) : Int32
  fun dsa_verify = DSA_verify(type : Int32, dgst : UInt8*, dlen : Int32, sig : UInt8*, siglen : Int32, dsa : DSA) : Int32
  fun i2d_dsapublickey = i2d_DSAPublicKey(dsa : DSA, pp : UInt8**) : Int32
  fun d2i_dsapublickey = d2i_DSAPublicKey(dsa : DSA*, pp : UInt8**, length : Int64) : Int32
end
