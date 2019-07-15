@[Link("crypto")]
lib LibCrypto
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
end
