macro get_ex_new_index(name, argl, argp)
  LibCrypto.crypto_get_ex_new_index(LibCrypto::CRYPTO_EX_INDEX_{{name.id.upcase}},
                                    {{argl}}, {{argp}}, nil, nil, nil)
end

@[Link("crypto")]
lib LibCrypto
  CRYPTO_EX_INDEX_SSL            =  0
  CRYPTO_EX_INDEX_SSL_CTX        =  1
  CRYPTO_EX_INDEX_SSL_SESSION    =  2
  CRYPTO_EX_INDEX_X509           =  3
  CRYPTO_EX_INDEX_X509_STORE     =  4
  CRYPTO_EX_INDEX_X509_STORE_CTX =  5
  CRYPTO_EX_INDEX_DH             =  6
  CRYPTO_EX_INDEX_DSA            =  7
  CRYPTO_EX_INDEX_EC_KEY         =  8
  CRYPTO_EX_INDEX_RSA            =  9
  CRYPTO_EX_INDEX_ENGINE         = 10
  CRYPTO_EX_INDEX_UI             = 11
  CRYPTO_EX_INDEX_BIO            = 12
  CRYPTO_EX_INDEX_APP            = 13
  CRYPTO_EX_INDEX_UI_METHOD      = 14
  CRYPTO_EX_INDEX_DRBG           = 15
  CRYPTO_EX_INDEX__COUNT         = 16

  fun crypto_get_ex_new_index = CRYPTO_get_ex_new_index(class_index : Int32, argl : Int64, argp : Void*,
                                                        new_func : Void*, dup_func : Void*, free_func : Void*) : Int32

  # from headers
  PKCS5_SALT_LEN = 8

  fun err_error_string = ERR_error_string(e : UInt64, buf : UInt8*) : UInt8*
  fun get_error = ERR_get_error : UInt64
  fun cleanse = OPENSSL_cleanse(ptr : UInt8*, len : UInt32)
end

require "./asn1"
require "./bio"
require "./bn"
require "./dsa"
require "./ecdsa"
require "./evp"
require "./hmac"
require "./pem"
require "./rsa"
require "./x509"
