require "../openssl"
require "./digest_base"

module OpenSSL
  class Digest
    class DigestError < OpenSSLError; end

    include DigestBase

    macro def_digest_classes(names)
      {% for name in names %}
      class {{name.id}} < Digest
        def self.new
          new("{{name.id}}", create_evp_mt_ctx("{{name.id}}"))
        end
      end
      {% end %}
    end

    def_digest_classes %w(DSS DSS1 MD2 MD4 MD5 MDC2 RIPEMD160 SHA SHA1 SHA224 SHA256 SHA384 SHA512)

    getter name

    def initialize(@name : String, @ctx : LibCrypto::EVP_MD_CTX)
      raise DigestError.new("Invalid EVP_MD_CTX") unless @ctx
    end

    protected def self.create_evp_mt_ctx(name)
      md = LibCrypto.evp_get_digestbyname(name)
      unless md
        oid = LibCrypto.obj_txt2obj(name, 0)
        md = LibCrypto.evp_get_digestbyname(LibCrypto.obj_nid2sn(LibCrypto.obj_obj2nid(oid)))
        LibCrypto.asn1_object_free(oid)
      end
      unless md
        raise "Unsupported digest algoritm: #{name}"
      end
      ctx = LibCrypto.evp_md_ctx_create
      unless ctx
        raise OpenSSL::Digest::DigestError.new "Digest initialization failed."
      end
      if LibCrypto.evp_digestinit_ex(ctx, md, nil) != 1
        raise OpenSSL::Digest::DigestError.new "Digest initialization failed."
      end
      ctx
    end

    def self.new(name)
      new(name, create_evp_mt_ctx(name))
    end

    def finalize
      LibCrypto.evp_md_ctx_destroy(self)
    end

    def clone
      ctx = LibCrypto.evp_md_ctx_create
      if LibCrypto.evp_md_ctx_copy(ctx, @ctx) == 0
        LibCrypto.evp_md_ctx_destroy(ctx)
        raise DigestError.new("Unable to clone digest")
      end
      Digest.new(@name, ctx)
    end

    def reset
      if LibCrypto.evp_digestinit_ex(self, to_unsafe_md, nil) != 1
        raise DigestError.new "Digest initialization failed."
      end
      self
    end

    def update(data : String | Slice)
      LibCrypto.evp_digestupdate(self, data, LibC::SizeT.new(data.bytesize))
      self
    end

    protected def finish
      size = digest_size
      data = Slice(UInt8).new(size)
      LibCrypto.evp_digestfinal_ex(@ctx, data, nil)
      data
    end

    def digest_size
      LibCrypto.evp_md_size(to_unsafe_md)
    end

    def block_size
      LibCrypto.evp_md_block_size(to_unsafe_md)
    end

    def to_unsafe_md
      LibCrypto.evp_md_ctx_md(self)
    end

    def to_unsafe
      @ctx
    end
  end
end
