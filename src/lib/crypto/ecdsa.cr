@[Link("crypto")]
lib LibCrypto
  EVP_MAX_KEY_LENGTH = 32
  EVP_MAX_IV_LENGTH  = 16

  OPENSSL_EC_EXPLICIT_CURVE = 0x000
  OPENSSL_EC_NAMED_CURVE    = 0x001

  alias EC_KEY = Void*
  alias EC_GROUP = Void*

  fun ec_key_new = EC_KEY_new : EC_KEY
  fun ec_key_free = EC_KEY_free(key : EC_KEY)
  fun ec_key_generate_key = EC_KEY_generate_key(key : EC_KEY) : Int32
  fun ec_key_new_by_curve_name = EC_KEY_new_by_curve_name(nid : Int32) : EC_KEY
  fun ec_key_print = EC_KEY_print(bio : BIO, key : EC_KEY, off : Int32) : Int32
  fun ec_key_set_asn1_flag = EC_KEY_set_asn1_flag(eckey : EC_KEY, asn1_flag : Int32)
  fun ec_key_get0_group = EC_KEY_get0_group(key : EC_KEY) : EC_GROUP
  fun ec_key_set_group = EC_KEY_set_group(key : EC_KEY, group : EC_GROUP) : Int32
  fun evp_pkey_get1_ec_key = EVP_PKEY_get1_EC_KEY(pkey : EVP_PKEY) : EC_KEY
  fun i2d_ecprivatekey = i2d_ECPrivateKey(key : EC_KEY, out : UInt8**) : Int32
  fun i2d_ec_pubkey = i2d_EC_PUBKEY(key : EC_KEY, out : UInt8**) : Int32
  fun d2i_ecprivatekey = d2i_ECPrivateKey(key : EC_KEY*, out : UInt8**, length : Int64) : EC_KEY
  fun d2i_ec_pubkey = d2i_EC_PUBKEY(key : EC_KEY*, out : UInt8**, length : Int64) : EC_KEY
  fun i2d_ecprivatekey_bio = i2d_ECPrivateKey_bio(bio : BIO, key : EC_KEY) : Int32
  fun i2d_ec_pubkey_bio = i2d_EC_PUBKEY_bio(bio : BIO, key : EC_KEY) : Int32
  fun d2i_ecprivatekey_bio = d2i_ECPrivateKey_bio(bio : BIO, key : EC_KEY*) : EC_KEY
  fun d2i_ec_pubkey_bio = d2i_EC_PUBKEY_bio(bio : BIO, key : EC_KEY*) : EC_KEY
  fun ecdsa_size = ECDSA_size(eckey : EC_KEY) : Int32
  fun ecdsa_sign = ECDSA_sign(type : Int32, dgst : UInt8*, dgstlen : Int32, sig : UInt8*, siglen : UInt32*, eckey : EC_KEY) : Int32
  fun ecdsa_verify = ECDSA_verify(type : Int32, dgst : UInt8*, dgstlen : Int32, sig : UInt8*, siglen : UInt32*, eckey : EC_KEY) : Int32
  fun ec_group_get_curve_name = EC_GROUP_get_curve_name(group : EC_GROUP) : Int32
  fun ec_group_set_asn1_flag = EC_GROUP_set_asn1_flag(group : EC_GROUP, flag : Int32)
  fun pem_read_bio_ecprivatekey = PEM_read_bio_ECPrivateKey(bio : BIO, key : EC_KEY*, cb : PasswordCallback, user_data : Void*) : EC_KEY
  fun pem_write_bio_ecprivatekey = PEM_write_bio_ECPrivateKey(bio : BIO, key : EC_KEY, enc : EVP_CIPHER,
                                                              kstr : UInt8*, klen : Int32, cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_read_bio_ec_pubkey = PEM_read_bio_EC_PUBKEY(bio : BIO, key : EC_KEY*, cb : PasswordCallback, user_data : Void*) : EC_KEY
  fun pem_write_bio_ec_pubkey = PEM_write_bio_EC_PUBKEY(bio : BIO, key : EC_KEY) : Int32
end
