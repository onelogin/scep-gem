module SCEP

  module PKIOperation

    # Handles decoding or creation of a scep CSR request.
    #
    # ## EJBCA Support
    # This requires tampering of the SCEP request. Please see {#tamper_scep_message_type}
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


      # Whether we should tamper with the SCEP message type. This is **required** to work with some SCEP
      # implementations, but this may cause verification to fail. Only affects encryption.
      # @example Without Tampering
      #   request = SCEP::PKIOperation::Request.new(keypair)
      #   encrypted = request.encrypt(another_keypair)
      #
      #   # Here, `encrypted` will not be accepted by EJBCA, but ruby will parse it just fine
      #   p7sign = OpenSSL::PKCS7.new(encrypted)
      #   verified = p7sign.verify([keypair.certificate], nil, nil)
      #   p verified # => true
      #
      # @example With Tampering
      #   request = SCEP::PKIOperation::Request.new(keypair)
      #   request.tamper_scep_message_type = true
      #   encrypted = request.encrypt(another_keypair)
      #
      #   # Here, `encrypted` will be accepted by EJBCA, but rejected by ruby
      #   p7sign = OpenSSL::PKCS7.new(encrypted)
      #   verified = p7sign.verify([keypair.certificate], nil, nil)
      #   p verified # => false
      #
      # @todo Need to figure out how to re-calculate the SCEP extended attributes signature, which will make
      #   this obsolete!
      # @return [Boolean] whether to tamper with the SCEP message type
      attr_accessor :tamper_scep_message_type
      alias_method :tamper_scep_message_type?, :tamper_scep_message_type

      def initialize(ra_keypair)
        super
        @tamper_scep_message_type = false
      end

      # @return [Boolean] TRUE if the request has a challenge password, FALSE otherwise
      def challenge_password?
        csr && csr.challenge_password?
      end

      # Get the challenge password from the request, if any
      # @return [String,nil] a STRING representation of the challenge password, NIL if there is
      #   no challenge password
      def challenge_password
        return nil unless challenge_password?
        csr_challenge_password.value.value.first.value
      end

      # @todo: add code to set the challenge password
      # def challenge_password=(password)
      #   return false if csr.blank?
      #   attribute = csr_challenge_password
      #   if attribute.blank?
      #     attribute = generate_challenge_password(password)
      #     csr.add_attribute(attribute)
      #   else
      #     binding.pry
      #     attribute.value.value.first.value = password
      #   end
      # end

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
        p7enc = sign_and_encrypt_raw(csr.to_der, target_encryption_certs)
        p7enc = add_scep_message_type(p7enc) if tamper_scep_message_type?
        p7enc
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

      # Gets the challenge password from the CSR
      def csr_challenge_password
        csr.send(:read_attributes_by_oid, 'challengePassword')
      end

      # Adds a required message type to the PKCS7 request. I can't believe I'm doing this...
      #
      # Take a look at https://tools.ietf.org/html/draft-nourse-scep-11. Here, we're adding the
      # signerInfo/messageType of "PKCSReq" inside of the "Signed PKCSReq."
      #
      # @param [OpenSSL::PKCS7] pkcs7 a pkcs7 message
      # @return [OpenSSL::PKCS7] a new pkcs7 message with the proper scep message type
      # @note Don't tamper with the signer info once you've used this method!
      def add_scep_message_type(pkcs7)
        asn1 = OpenSSL::ASN1.decode(pkcs7.to_der)
        pkcs_cert_resp_signed = asn1.value[1].value[0]
        signer_info = pkcs_cert_resp_signed.value[4].value[0]
        authenticated_attributes = signer_info.value[3]
        authenticated_attributes.value << SCEP::ASN1.message_type(SCEP::ASN1::MESSAGE_TYPE_PKCS_REQ)
        # todo: broken?? --
        # recalculate_authenticated_attributes_digest(signer_info)
        return OpenSSL::PKCS7.new(asn1.to_der)
      end

      # todo: this currently does not work! Kept here for future purposes
      def recalculate_authenticated_attributes_digest(signer_info)
        digest_algorithm = signer_info.value[2].value[0].sn # => "SHA256"

        # This is where this is not working - we need to hash the "authenticatedAttributes",
        # but this does not appear to be hashing the correct thing!
        authenticated_attributes = signer_info.value[3]

        new_digest = SCEP::ASN1.calculate_and_generate_pkcs7_signature_hash(
          authenticated_attributes.to_der,
          digest_algorithm)

        encrypted_digest = ra_keypair.private_key.private_encrypt(new_digest.to_der)
        signer_info.value.last.value = encrypted_digest
      end


      # Takes a password and generates an attribute
      # @param password [String] what the challenge password should be
      # @return [OpenSSL::X509::Attribute]
      # @todo: This does not currently work!
      # def self.generate_challenge_password(password)
      #   attribute = OpenSSL::X509::Attribute.new('challengePassword')
      #   attribute.value = OpenSSL::ASN1::Set.new([
      #     OpenSSL::ASN1::PrintableString.new(password.to_s)
      #   ])
      #   attribute
      # end

    end
  end
end
