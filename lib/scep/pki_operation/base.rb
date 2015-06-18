module SCEP
  module PKIOperation

    # Base class that contains commonalities between both requests and repsonses:
    #
    # * {#ra_certificate RA Certificate}
    # * {#ra_private_key RA Private Key}
    #
    class Base
      include SCEP::Loggable

      DEFAULT_CIPHER_ALGORITHM = 'aes-256-cbc'

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
        @x509_store ||= OpenSSL::X509::Store.new
      end

      # Adds a certificate to verify against
      # @param [OpenSSL::X509::Certificate] cert
      def add_verification_certificate(cert)
        x509_store.add_cert(cert)
      end
      alias_method :verify_against, :add_verification_certificate

      protected

      # Takes a raw binary string and returns the raw, unencrypted data
      # @param [String] signed_and_encrypted_csr the signed and encrypted data
      # @param [Boolean] verify if TRUE, verifies the signed PKCS7 payload against the {#x509_store}
      # @raise [SCEP::PKIOperation::VerificationFailed] if `verify` is TRUE and the signed payload
      #   was *not* verified against the {#x509_store}.
      # @return [String] the decrypted and unsigned data (original format)
      def unsign_and_unencrypt_raw(signed_and_encrypted_csr, verify = true)
        # Remove signature
        @p7sign = OpenSSL::PKCS7.new(signed_and_encrypted_csr)

        flags = OpenSSL::PKCS7::BINARY
        flags |= OpenSSL::PKCS7::NOVERIFY unless verify

        # See http://openssl.6102.n7.nabble.com/pkcs7-verification-with-ruby-td28455.html
        verified = @p7sign.verify([], x509_store, nil, flags)

        if !verified
          raise SCEP::PKIOperation::VerificationFailed,
            'Unable to verify signature against certificate store - did you add the correct certificates?'
        end


        # Decrypt
        @p7enc   = OpenSSL::PKCS7.new(@p7sign.data)
        check_if_recipient_matches_ra_certificate_name(@p7enc)
        @p7enc.decrypt(ra_keypair.private_key, ra_keypair.certificate, OpenSSL::PKCS7::BINARY)
      end

      # Signs and encrypts the given raw data
      # @param [String] raw_data the raw data to sign and encrypt
      # @param [OpenSSL::X509::Certificate] target_encryption_certs the cert(s) to encrypt for
      # @param [OpenSSL::Cipher::Cipher] cipher the cipher to use. Defaults to {.create_default_cipher}
      # @return [OpenSSL::PKCS7] the signed and encrypted payload
      def sign_and_encrypt_raw(raw_data, target_encryption_certs, cipher = nil)
        cipher ||= self.class.create_default_cipher

        encrypted = OpenSSL::PKCS7.encrypt(
          wrap_array(target_encryption_certs),
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

      # Creates an {OpenSSL::Cipher} using the {DEFAULT_CIPHER_ALGORITHM}. It's best to create a new Cipher object
      # for every new encryption call so that we don't re-use sensitive data (IV's) [citation needed].
      # @return [OpenSSL::Cipher]
      def self.create_default_cipher
        OpenSSL::Cipher.new(DEFAULT_CIPHER_ALGORITHM)
      end

      protected

      def check_if_recipient_matches_ra_certificate_name(p7enc)
        if p7enc.recipients.nil? || p7enc.recipients.empty?
          logger.warn 'SCEP request does not have any recipient info - ' \
            'cannot determine if SCEP request is intended for us'
          return false
        end

        matched = false
        names = p7enc.recipients.map(&:issuer).each do |name|
          if name.cmp(ra_keypair.certificate.subject) == 0
            matched = true
            break
          end
        end

        unless matched
          logger.warn 'SCEP request does not appear to be addressed to us! ' \
            "RA Cert: #{ra_keypair.certificate.subject.to_s}, Recipients: [#{names.map(&:to_s).join(', ')}]"
        end
        matched
      end

      # Same as `Array.wrap`
      # @see http://apidock.com/rails/Array/wrap/class
      def wrap_array(object)
        if object.nil?
          []
        elsif object.respond_to?(:to_ary)
          object.to_ary || [object]
        else
          [object]
        end
      end
    end
  end
end
