module SCEP
  module PKIOperation

    # Base class that contains commonalities between both requests and repsonses:
    #
    # * {#ra_certificate RA Certificate}
    # * {#ra_private_key RA Private Key}
    #
    class Base
      DEFAULT_CIPHER = OpenSSL::Cipher::Cipher.new('des-ede3-cbc')

      # Our keypair
      # @return [Keypair]
      attr_accessor :ra_keypair

      # The last signed payload
      # @return [OpenSSL::PKCS7]
      attr_reader :p7sign

      # The last encrypted payload
      # @return [OpenSSL::PKCS7]
      attr_reader :p7enc

      # The store of trusted certs
      # @return [OpenSSL::X509::Store]
      attr_writer :x509_store

      # Creates a new payload
      # @param [Keypair] ra_keypair
      def initialize(ra_keypair)
        @ra_keypair = ra_keypair
      end

      # Gets an x509 store. Defaults to a store with system default paths. Used for
      # {#unsign_and_unencrypt_raw decryption}.
      # @return [OpenSSL::X509::Store]
      def x509_store
        @x509_store ||= OpenSSL::X509::Store.new.tap do |store|
          store.set_default_paths
        end
      end

      protected

      # Takes a raw binary string and returns the raw, unencrypted data
      # @param [String] signed_and_encrypted_csr the signed and encrypted data
      # @return [String] the decrypted and unsigned data (original format)
      # @todo Figure out how to verify
      def unsign_and_unencrypt_raw(signed_and_encrypted_csr)
        # Remove signature
        @p7sign = OpenSSL::PKCS7.new(signed_and_encrypted_csr)

        # TODO: actually verify
        @p7sign.verify([], x509_store, nil, OpenSSL::PKCS7::NOVERIFY | OpenSSL::PKCS7::BINARY)

        # Decrypt
        @p7enc   = OpenSSL::PKCS7.new(@p7sign.data)
        @p7enc.decrypt(ra_keypair.private_key, ra_keypair.certificate, OpenSSL::PKCS7::BINARY)
      end

      # Signs and encrypts the given raw data
      # @param [String] raw_data the raw data to sign and encrypt
      # @param [OpenSSL::X509::Certificate] target_encryption_certs the cert(s) to encrypt for
      # @param [OpenSSL::Cipher::Cipher] cipher the cipher to use. Defaults to {DEFAULT_CIPHER}
      # @return [OpenSSL::PKCS7] the signed and encrypted payload
      def sign_and_encrypt_raw(raw_data, target_encryption_certs, cipher: nil)
        cipher ||= DEFAULT_CIPHER

        encrypted = OpenSSL::PKCS7.encrypt(
          Array.wrap(target_encryption_certs),
          raw_data,
          cipher,
          OpenSSL::PKCS7::BINARY)

        OpenSSL::PKCS7.sign(
          ra_keypair.certificate,
          ra_keypair.private_key,
          encrypted.to_der,
          [ra_keypair.certificate],
          OpenSSL::PKCS7::BINARY)
      end

    end
  end
end
