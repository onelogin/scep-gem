module SCEP
  # A public / private keypair
  class Keypair

    # The various cryptosystems we support. Used mostly for ruby 1.8.7, which cannot
    # automatically determine which cryptosystem is being used.
    SUPPORTED_CRYPTOSYSTEMS = [
      OpenSSL::PKey::RSA,
      OpenSSL::PKey::DSA,
      OpenSSL::PKey::EC,
      OpenSSL::PKey::DH
    ]

    # @return [OpenSSL::X509::Certificate]
    attr_accessor :certificate
    alias_method :cert, :certificate

    # @return [OpenSSL::PKey]
    attr_accessor :private_key

    def initialize(certificate, private_key)
      raise ArgumentError, '`certificate` must be an OpenSSL::X509::Certificate' unless
        certificate.is_a?(OpenSSL::X509::Certificate)

      unless certificate.check_private_key(private_key)
        raise ArgumentError, '`private_key` does not match `certificate`'
      end

      @certificate = certificate
      @private_key = private_key
    end

    # Loads a keypair from a file
    # @param [String] certificate_filepath
    # @param [String] private_key_filepath
    # @param [String] private_key_passphrase add this if you
    # @return [Keypair]
    def self.read(certificate_filepath, private_key_filepath, private_key_passphrase = nil)
      x509_cert = OpenSSL::X509::Certificate.new File.read(certificate_filepath.to_s)
      pkey      = read_private_key(File.open(private_key_filepath.to_s).read, private_key_passphrase)
      new(x509_cert, pkey)
    end

    protected

    # Reads a DER or PEM encoded private key that is one of the {SUPPORTED_CRYPTOSYSTEMS}. In
    # ruby 1.9+ we can do this easily. In ruby 1.8.7 we have to keep on guessing until we get
    # it right.
    def self.read_private_key(encoded_key, passphrase = nil)
      # Ruby 1.9.3+
      if OpenSSL::PKey.respond_to?(:read)
        OpenSSL::PKey.read encoded_key, passphrase

      # Ruby 1.8.7 - keep on guessing which cryptosystem until we're correct
      else
        SUPPORTED_CRYPTOSYSTEMS.each do |system|
          begin
            return system.new(encoded_key, passphrase)
          rescue
          end
        end

        # If we're here, then the file is probably invalid
        raise UnsupportedCryptosystem,
          "Either private key is invalid, passphrase is invalid, or does not support one " \
          "of cryptosystems: #{SUPPORTED_CRYPTOSYSTEMS.map(&:name).join(', ')}"
      end
    end


    class UnsupportedCryptosystem < StandardError; end
  end
end
