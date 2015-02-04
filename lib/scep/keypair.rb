module SCEP
  # A public / private keypair
  class Keypair
    # @return [OpenSSL::X509::Certificate]
    attr_accessor :certificate

    # @return [OpenSSL::PKey]
    attr_accessor :private_key

    def initialize(certificate, private_key)
      raise ArgumentError, '`certificate` must be an OpenSSL::X509::Certificate' unless
        certificate.is_a?(OpenSSL::X509::Certificate)

      @certificate = certificate
      @private_key = private_key
    end

    # Loads a keypair from a file
    # @param [String] certificate_filepath
    # @param [String] private_key_filepath
    # @return [Keypair]
    def self.read(certificate_filepath, private_key_filepath)
      x509_cert = OpenSSL::X509::Certificate.new File.read(certificate_filepath.to_s)
      pkey      = OpenSSL::PKey.read File.read(private_key_filepath.to_s)
      new(x509_cert, pkey)
    end
  end
end
