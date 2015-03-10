module SCEP
  module PKIOperation

    # Represents a SCEP response from the PKIOperation, which can do two of the following:
    #
    # * Parse a response form another SCEP server (useful for proxying)
    # * Create our own SCEP response
    #
    # @example Get Certificates Ready
    #   ra_cert = SCEP::DEFAULT_RA_CERTIFICATE
    #   ra_key  = SCEP::DEFAULT_RA_PRIVATE_KEY
    #
    # @example Decrypt a SCEP Response
    #   # get encrypted and signed scep response somehow
    #   encrypted_scep_response = foo
    #
    #   # Make response & decrypt
    #   response = SCEP::PKIOperation::Response.new(ra_cert, ra_key)
    #   certs  = response.decrypt(encrypted_scep_response)  # Array of OpenSSL::X509::Certificate
    #
    # @example Create an Encrypted and Signed Response
    #   # This should be an OpenSSL::X509::Certificate signed by a CA.
    #   # This will be from an earlier part of the scep flow
    #   recently_signed_x509_cert = foo
    #
    #   # This is the target OpenSSL::X509::Certificate that we should encrypt this for.
    #   # This will usually be the certificate of whomever signed the initial scep request
    #   target_encryption_cert  = bar
    #
    #   # Make the response objects and attach certs
    #   response = SCEP::PKIOperation::Response.new(ra_cert, ra_key)
    #   response.signed_certificates = recently_signed_x509_cert
    #
    #   # Finally, encrypt it in a der format
    #   encrypted_binary_string = response.encrypt(target_encryption_cert)
    #
    class Response < Base


      # Adds a single, or many certificates to encrypt and sign further
      # @param [Array<OpenSSL::X509::Certificate>] certs
      def signed_certificates=(certs)
        @signed_certificates = wrap_array(certs)
      end

      # Gets any signed certificates that will be encrypted and signed in a SCEP format
      # @return [Array<OpenSSL::X509::Certificate>]
      def signed_certificates
        @signed_certificates ||= []
      end

      # Decrypts a raw response and assigns {#signed_certificates}
      # @param [String] raw_string the raw response
      # @return [Array<OpenSSL::X509::Certificates>] the certificates that were contained
      #   in `raw_string`.
      def decrypt(raw_string, verify = true)
        p7raw = unsign_and_unencrypt_raw(raw_string, verify)
        p7certs = OpenSSL::PKCS7.new(p7raw)
        @signed_certificates = p7certs.certificates
      end

      # Takes the {#signed_certificates} attached to this object and return them in a format
      # defined by SCEP.
      # @param [Array<OpenSSL::X509::Certificate>] target_encryption_certs only those who possess a
      #   private key of one of the `target_encryption_certs` will be able to decrypt the resulting
      #   payload.
      # @return [String] the signed and encrypted payload in binary (DER) format
      def encrypt(target_encryption_certs)
        raise ArgumentError, 'Must contain at least one of #signed_certificates' unless
          signed_certificates.any?
        p7certs = PKCS7CertOnly.new(signed_certificates)
        sign_and_encrypt_raw(p7certs.to_der, target_encryption_certs)
      end

      # Decrypts a signed and encrypted response, gets the certificates ({#signed_certificates}) and then
      # re-encrypts and signs it.
      # @param [String] signed_and_encrypted_certs
      # @param [OpenSSL::X509::Certificate] target_encryption_certs
      # @return [OpenSSL::PKCS7]
      def proxy(signed_and_encrypted_certs, target_encryption_certs, verify = true)
        decrypt(signed_and_encrypted_certs, verify)
        encrypt(target_encryption_certs)
      end
    end
  end
end
