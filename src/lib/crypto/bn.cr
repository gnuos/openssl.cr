@[Link("crypto")]
lib LibCrypto
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
end
