module SCEP

  module PKIOperation

    # Handles decoding or creation of a scep CSR request.
    #
    # @example Get Certificates Ready
    #   ra_cert = SCEP::DEFAULT_RA_CERTIFICATE
    #   ra_key  = SCEP::DEFAULT_RA_PRIVATE_KEY
    #
    # @example Decrypt SCEP Request
    #   # Get the encrypted and signed scep request (der format) somehow
    #   encrypted_scep_request = foo
    #
    #   # Make request & decrypt
    #   request = SCEP::PKIOperation::Request.new(ra_cert, ra_key)
    #   csr = decrypt(encrypted_scep_request)  # OpenSSL::X509::Request
    #
    # @example Encrypt SCEP Request
    #   # Get a CSR object, usually from an earlier step
    #   some_csr = foo
    #
    #   # This is the target OpenSSL::X509::Certificate that we should encrypt this for.
    #   # This will usually be the RA certificate of another SCEP server
    #   target_encryption_cert  = bar
    #
    #   request = SCEP::PKIOperation::request.new(ra_cert, ra_key)
    #   request.csr = some_csr
    #
    #   # Finally, encrypt it in der format
    #   request.encrypt(target_encryption_cert)
    #
    class Request < Base

      # The certificate request
      # @return [OpenSSL::X509::Request]
      attr_reader :csr

      # Decrypts a signed and encrypted csr. Sets {#csr} to the decrypted value
      # @param [String] signed_and_encrypted_csr the raw and encrypted
      # @return [OpenSSL::X509::Request] the raw CSR
      def decrypt(signed_and_encrypted_csr)
        raw_csr = unsign_and_unencrypt_raw(signed_and_encrypted_csr)
        @csr = OpenSSL::X509::Request.new(raw_csr)
      end

      # Encrypt and sign the CSR
      # @param [OpenSSL::X509::Certificate] target_encryption_certs the certificat(s) we should encrypt this for
      # @return [OpenSSL::PKCS7]
      def encrypt(target_encryption_certs)
        raise ArgumentError, 'Must attach a #csr' if csr.blank?
        sign_and_encrypt_raw(csr.to_der, target_encryption_certs)
      end

      # Decrypts a signed and encrypted payload and then re-encrypts it. {#csr} will contain the CSR object
      # @param [String] signed_and_encrypted_csr
      # @param [OpenSSL::X509::Certificate] target_encryption_certs
      # @return [OpenSSL::PKCS7]
      def proxy(signed_and_encrypted_csr, target_encryption_certs)
        decrypt(signed_and_encrypted_csr)
        encrypt(target_encryption_certs)
      end
    end
  end
end
