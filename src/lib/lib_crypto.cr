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

  # BIGNUM BEGIN

  alias BN_GENCB = Void*
  alias BN_ULONG = UInt64*

  struct BignumStruct
    d : BN_ULONG # Pointer to an array of 'BN_BITS2' bit chunks.
    top : Int32  # Index of last used d +1.
    dmax : Int32 # Size of the d array.
    neg : Int32  # one if the number is negative
    flags : Int32
  end

  alias BIGNUM = BignumStruct*

  fun bn_new = BN_new : BIGNUM
  fun bn_zero = BN_zero(a : BIGNUM)
  fun bn_one = BN_one(a : BIGNUM) : Int32
  fun bn_value_one = BN_value_one : BIGNUM
  fun bn_set_word = BN_set_word(a : BIGNUM, w : UInt64) : Int32
  fun bn_get_word = BN_get_word(a : BIGNUM) : UInt64

  # BIGNUM END

  # from headers
  PKCS5_SALT_LEN     =  8
  EVP_MAX_KEY_LENGTH = 32
  EVP_MAX_IV_LENGTH  = 16

  fun err_error_string = ERR_error_string(e : UInt64, buf : UInt8*) : UInt8*
  fun get_error = ERR_get_error : UInt64
  fun cleanse = OPENSSL_cleanse(ptr : UInt8*, len : UInt32)

  # # EVP BEGIN

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

  NID_undef                =   0
  NID_rsaEncryption        =   6
  NID_dsa                  = 116
  NID_X9_62_id_ecPublicKey = 408

  EVP_PKEY_NONE = NID_undef
  EVP_PKEY_RSA  = NID_rsaEncryption
  EVP_PKEY_DSA  = NID_dsa
  EVP_PKEY_EC   = NID_X9_62_id_ecPublicKey

  fun evp_pkey_assign = EVP_PKEY_assign(pkey : EVP_PKEY, type : Int32, key : Void*) : Int32

  # EVP END

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

  struct BioStruct
    method : Void*
    callback : (Void*, Int32, UInt8*, Int32, Int64, Int64) -> Int64
    cb_arg : UInt8*
    init : Int32
    shutdown : Int32
    flags : Int32
    retry_reason : Int32
    num : Int32
    ptr : Void*
    next_bio : Void*
    prev_bio : Void*
    references : Int32
    num_read : UInt64
    num_write : UInt64
  end

  alias BIO = BioStruct*

  CTRL_PUSH  =  6
  CTRL_POP   =  7
  CTRL_FLUSH = 11

  struct BioMethod
    type_id : Int32
    name : UInt8*
    bwrite : (BIO, UInt8*, Int32) -> Int32
    bread : (BIO, UInt8*, Int32) -> Int32
    bputs : (BIO, UInt8*) -> Int32
    bgets : (BIO, UInt8*, Int32) -> Int32
    ctrl : (BIO, Int32, Int64, Void*) -> Int32
    create : BIO -> Int32
    destroy : BIO -> Int32
    callback_ctrl : (BIO, Int32, Void*) -> Int64
  end

  alias BIO_METHOD = BioMethod*

  fun bio_s_mem = BIO_s_mem : BIO_METHOD
  fun bio_new = BIO_new(type : BIO_METHOD) : BIO
  fun bio_free_all = BIO_free_all(bio : BIO)
  fun bio_read = BIO_read(bio : BIO, data : UInt8*, len : Int32) : Int32
  fun bio_write = BIO_write(bio : BIO, data : UInt8*, len : Int32) : Int32

  BIO_CTRL_RESET = 1
  fun bio_ctrl = BIO_ctrl(bio : BIO, cmd : Int32, larg : Int64, parg : Void*) : Int64

  alias ASN1_OBJECT = Void*
  alias ASN1_INTEGER = Void*
  alias ASN1_TIME = Void*

  fun obj_txt2nid = OBJ_txt2nid(s : UInt8*) : Int32
  fun obj_txt2obj = OBJ_txt2obj(s : UInt8*, no_name : Int32) : ASN1_OBJECT
  fun obj_nid2sn = OBJ_nid2sn(n : Int32) : UInt8*
  fun obj_obj2nid = OBJ_obj2nid(obj : ASN1_OBJECT) : Int32
  fun obj_ln2nid = OBJ_ln2nid(s : UInt8*) : Int32
  fun obj_sn2nid = OBJ_sn2nid(s : UInt8*) : Int32
  fun obj_nid2ln = OBJ_nid2ln(n : Int32) : UInt8*
  fun asn1_object_free = ASN1_OBJECT_free(obj : ASN1_OBJECT)
  fun asn1_dup = ASN1_dup(i2d : Void*, d2i_of_void : Void*, x : Void*) : Void*
  fun i2a_asn1_object = i2a_ASN1_OBJECT(bio : BIO, asn : ASN1_OBJECT) : Int32
  fun asn1_object_size = ASN1_object_size(constructed : Int32, length : Int32, tag : Int32) : Int32
  fun asn1_put_object = ASN1_put_object(pp : UInt8**, constructed : Int32, length : Int32, tag : Int32, xclass : Int32)
  fun asn1_integer_set = ASN1_INTEGER_set(a : ASN1_INTEGER, v : Int64) : Int32
  fun asn1_time_free = ASN1_TIME_free(t : ASN1_TIME)
  fun x509_gmtime_adj = X509_gmtime_adj(t : ASN1_TIME, adj : Int64) : ASN1_TIME

  # # RSA BEGIN

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

  # RSA END

  # # DSA BEGIN

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

  # DSA END

  # # ECDSA BEGIN
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

  # ECDSA END

  # # X509 BEGIN

  alias X509_NAME = Void*

  fun x509_name_free = X509_NAME_free(name : X509_NAME)
  fun x509_name_dup = X509_NAME_dup(name : X509_NAME) : X509_NAME
  fun x509_name_print_ex = X509_NAME_print_ex(bio : BIO, name : X509_NAME, indent : Int32, flags : UInt64) : Int32

  alias X509_STORE_CTX = Void*
  alias X509 = Void*

  fun x509_store_ctx_get_error = X509_STORE_CTX_get_error(store : X509_STORE_CTX) : Int32
  fun x509_store_ctx_get_current_cert = X509_STORE_CTX_get_current_cert(store : X509_STORE_CTX) : X509

  fun x509_new = X509_new : X509
  fun x509_free = X509_free(x509 : X509)
  fun pem_read_bio_x509 = PEM_read_bio_X509(bio : BIO, x509 : X509*, cb : PasswordCallback, user_data : Void*) : X509
  fun pem_write_bio_x509 = PEM_write_bio_X509(bio : BIO, x509 : X509) : Int32
  fun x509_get_pubkey = X509_get_pubkey(x509 : X509) : EVP_PKEY
  fun x509_get_subject_name = X509_get_subject_name(x509 : X509) : X509_NAME
  fun x509_digest = X509_digest(x509 : X509, type : EVP_MD, md : UInt8*, len : UInt32*) : Int32
  fun x509_set_version = X509_set_version(x509 : X509, version : Int64) : Int32
  fun x509_get_serialnumber = X509_get_serialNumber(x509 : X509) : ASN1_INTEGER
  fun x509_set_notbefore = X509_set1_notBefore(x509 : X509, tm : ASN1_TIME) : Int32
  fun x509_set_notafter = X509_set1_notAfter(x509 : X509, tm : ASN1_TIME) : Int32
  fun x509_set_pubkey = X509_set_pubkey(x509 : X509, pkey : EVP_PKEY) : Int32
  fun x509_verify = X509_verify(x509 : X509, pkey : EVP_PKEY) : Int32

  MBSTRING_FLAG = 0x1000
  MBSTRING_UTF8 = MBSTRING_FLAG

  fun x509_name_add_entry_by_txt = X509_NAME_add_entry_by_txt(name : X509_NAME, field : UInt8*, type : Int32, bytes : UInt8*, len : Int32,
                                                              loc : Int32, set : Int32) : Int32
  fun x509_set_issuer_name = X509_set_issuer_name(x509 : X509, name : X509_NAME) : Int32

  struct X509V3_CTX
    flags : Int32
    issuer_cert : Void*
    subject_cert : Void*
    subject_req : Void*
    crl : Void*
    db_meth : Void*
    db : Void*
  end

  alias X509_REQ = Void*
  alias X509_CRL = Void*
  alias X509_EXTENSION = Void*

  fun x509v3_set_ctx = X509V3_set_ctx(ctx : X509V3_CTX*, issuer : X509, subj : X509, req : X509_REQ,
                                      crl : X509_CRL, flags : Int32)
  fun x509v3_ext_conf_nid = X509V3_EXT_conf_nid(conf : Void*, ctx : X509V3_CTX*, ext_nid : Int32, value : UInt8*) : X509_EXTENSION
  fun x509_add_ext = X509_add_ext(x509 : X509, ex : X509_EXTENSION, loc : Int32) : Int32

  NID_ext_key_usage = 126
  NID_key_usage     =  83

  fun x509_extension_free = X509_EXTENSION_free(ex : X509_EXTENSION)
  fun x509_sign = X509_sign(x509 : X509, pkey : EVP_PKEY, md : EVP_MD) : Int32

  # X509 END

  fun pem_read_bio_privatekey = PEM_read_bio_PrivateKey(bio : BIO, pkey : EVP_PKEY*, cb : PasswordCallback, user_data : Void*) : EVP_PKEY
  fun pem_write_bio_privatekey = PEM_write_bio_PrivateKey(bio : BIO, x : EVP_PKEY, enc : EVP_CIPHER,
                                                          kstr : UInt8*, klen : Int32, cb : PasswordCallback, user_data : Void*) : Int32
  fun pem_read_bio_pubkey = PEM_read_bio_PUBKEY(bio : BIO, pkey : EVP_PKEY*, cb : PasswordCallback, user_data : Void*) : EVP_PKEY
  fun pem_write_bio_pubkey = PEM_write_bio_PUBKEY(bio : BIO, pkey : EVP_PKEY*) : Int32
end
