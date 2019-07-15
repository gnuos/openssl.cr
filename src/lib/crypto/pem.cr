@[Link("crypto")]
lib LibCrypto
  fun pem_read_bio_privatekey = PEM_read_bio_PrivateKey(bio : BIO, pkey : EVP_PKEY*, cb : PasswordCallback, user_data : Void*) : EVP_PKEY
  fun pem_write_bio_privatekey = PEM_write_bio_PrivateKey(bio : BIO, x : EVP_PKEY, enc : EVP_CIPHER,
                                                          kstr : UInt8*, klen : Int32, cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_read_bio_pubkey = PEM_read_bio_PUBKEY(bio : BIO, pkey : EVP_PKEY*, cb : PasswordCallback, user_data : Void*) : EVP_PKEY
  fun pem_write_bio_pubkey = PEM_write_bio_PUBKEY(bio : BIO, pkey : EVP_PKEY*) : Int32
end
