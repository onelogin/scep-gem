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
    #   request.x509_store.add_certificate some_cert  # Add cert to verify
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
      attr_accessor :csr

      # Decrypts a signed and encrypted csr. Sets {#csr} to the decrypted value
      # @param [String] signed_and_encrypted_csr the raw and encrypted
      # @param [Boolean] verify if TRUE, verifies against {#x509_store}. If FALSE, skips verification
      # @raise [SCEP::PKIOperation::VerificationFailed] if `verify` is TRUE and the signed payload
      #   was *not* verified against the {#x509_store}.
      # @return [OpenSSL::X509::Request] the raw CSR
      def decrypt(signed_and_encrypted_csr, verify = true)
        raw_csr = unsign_and_unencrypt_raw(signed_and_encrypted_csr, verify)
        @csr = OpenSSL::X509::Request.new(raw_csr)
      end

      # Encrypt and sign the CSR
      # @param [OpenSSL::X509::Certificate] target_encryption_certs the certificat(s) we should encrypt this for
      # @return [OpenSSL::PKCS7]
      def encrypt(target_encryption_certs)
        raise ArgumentError, '#csr must be an OpenSSL::X509::Request' unless
          csr.is_a?(OpenSSL::X509::Request)
        encrypted = sign_and_encrypt_raw(csr.to_der, target_encryption_certs)
        return self.class.add_scep_message_type(encrypted)
      end

      # Decrypts a signed and encrypted payload and then re-encrypts it. {#csr} will contain the CSR object
      # @param [String] signed_and_encrypted_csr
      # @param [OpenSSL::X509::Certificate] target_encryption_certs
      # @return [OpenSSL::PKCS7]
      def proxy(signed_and_encrypted_csr, target_encryption_certs, verify = true)
        decrypt(signed_and_encrypted_csr, verify)
        encrypt(target_encryption_certs)
      end


      protected


      # Adds a required message type to the PKCS7 request. I can't believe I'm doing this...
      #
      # @param [OpenSSL::PKCS7] pkcs7 a pkcs7 message
      # @return [OpenSSL::PKCS7] a new pkcs7 message with the proper scep message type
      # @note Don't tamper with the signer info once you've used this method!
      def self.add_scep_message_type(pkcs7)
        asn1 = OpenSSL::ASN1.decode(pkcs7.to_der)
        pkcs_cert_resp_signed = asn1.value[1].value[0]
        signer_info = pkcs_cert_resp_signed.value[4].value[0]
        authenticated_attributes = signer_info.value[3]
        authenticated_attributes.value << SCEP::ASN1.message_type(SCEP::ASN1::MESSAGE_TYPE_PKCS_REQ)
        return OpenSSL::PKCS7.new(asn1.to_der)
      end


    end
  end
end
