require "../openssl"

module OpenSSL
  class PKey::EC < PKey
    class ECError < PKeyError; end

    def self.new(pem : String, password = nil)
      self.new(MemoryIO.new(pem), password)
    end

    def self.new(io : IO, password = nil)
      bio = MemBIO.new
      IO.copy(io, bio)
      priv_key = true
      ec = LibCrypto.pem_read_bio_ecprivatekey(bio, nil, nil, nil)

      unless ec
        bio.reset
        ec = LibCrypto.d2i_ecprivatekey_bio(bio, nil)
      end
      unless ec
        bio.reset
        ec = LibCrypto.d2i_ec_pubkey_bio(bio, nil)
        priv_key = false
      end
      unless ec
        raise ECError.new "Neither PUB or PRIV key"
      end
      new(priv_key).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec.as Pointer(Void))
      end
    end

    def self.new(size : Int32)
      self.generate(size)
    end

    def self.generate(size)
      nid = LibCrypto.obj_txt2nid("secp384r1")
      ec_key = LibCrypto.ec_key_new_by_curve_name(nid)
      LibCrypto.ec_key_set_asn1_flag(ec_key, LibCrypto::OPENSSL_EC_NAMED_CURVE)
      if LibCrypto.ec_key_generate_key(ec_key) == 0
        LibCrypto.ec_key_free(ec_key)
        raise ECError.new
      end

      new(true).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, ec_key.as Pointer(Void))
      end
    end

    def public_key
      f1 = ->LibCrypto.i2d_ecpublickey
      f2 = ->LibCrypto.d2i_ecpublickey

      pub_ec = LibCrypto.asn1_dup(f1.pointer, f2.pointer, ec().as(Void*)).as EC_KEY
      EC.new(false).tap do |pkey|
        LibCrypto.evp_pkey_assign(pkey, LibCrypto::EVP_PKEY_EC, pub_ec.as Pointer(Void))
      end
    end

    def to_pem(io)
      bio = MemBIO.new
      if private_key?
        LibCrypto.pem_write_bio_ecprivatekey(bio, ec, nil, nil, 0, nil, nil)
      else
        LibCrypto.pem_write_bio_ec_pubkey(bio, ec)
      end

      IO.copy(bio, io)
    end

    def to_text
      bio = MemBIO.new
      LibCrypto.ecdsa_print(bio, ec, 0)
      bio.to_string
    end

    def to_der
      fn = ->(buf : UInt8** | Nil) {
        if private_key?
          LibCrypto.i2d_ecprivatekey(ec, buf)
        else
          LibCrypto.i2d_ec_pubkey(ec, buf)
        end
      }
      len = fn.call(nil)
      if len <= 0
        raise ECError.new
      end
      slice = Slice(UInt8).new(len)
      p = slice.to_unsafe
      len = fn.call(pointerof(p))
      slice[0, len]
    end

    def ec_sign(data)
      unless private_key?
        raise ECError.new "need a private key"
      end
      data = data.to_slice
      to = Slice(UInt8).new max_encrypt_size
      if LibCrypto.ecdsa_sign(0, data, data.size, to, out len, ec) == 0
        raise ECError.new
      end
      to[0, len]
    end

    def ec_verify(digest, signature)
      digest = digest.to_slice
      signature = signature.to_slice
      case LibCrypto.ecdsa_verify(0, digest, digest.size, signature, signature.size, ec)
      when 1
        true
      when 0
        false
      else
        raise ECError.new
      end
    end

    private def ec
      LibCrypto.evp_pkey_get1_ec_key(self)
    end

    private def max_encrypt_size
      LibCrypto.ecdsa_size(ec)
    end
  end
end
