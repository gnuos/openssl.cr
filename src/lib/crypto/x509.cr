@[Link("crypto")]
lib LibCrypto
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
end
