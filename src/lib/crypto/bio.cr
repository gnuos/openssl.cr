@[Link("crypto")]
lib LibCrypto
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
end
