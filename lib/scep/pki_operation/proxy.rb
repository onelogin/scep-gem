module SCEP

  module PKIOperation
    # Enables proxying a PKI SCEP request from the DSL to another SCEP server
    # @example
    #   def pkioperation
    #     server = SCEP::Endpoint.new
    #     proxy = SCEP::Proxy.new(server, @ra_cert, @ra_pk)
    #     proxy.add_verification_certificate @some_cert  # For decrypting the request - this way not "anyone" can decrypt
    #     response = proxy.forward_pki_request(request.raw_post)
    #     send_data response.p7enc_response.to_der
    #   end
    class Proxy
      attr_accessor :server

      attr_accessor :ra_keypair

      # Whether we should verify certificates when decrypting
      # @return [Boolean]
      attr_accessor :verify_request

      attr_accessor :verify_response

      # X509 certificates to verify against the request
      # @return [Array<OpenSSL::X509::Certificate>] a list of certs
      attr_accessor :request_verification_certificates

      attr_accessor :response_verification_certificates

      # @param [SCEP::Endpoint] server
      # @param [Keypair] ra_keypair
      def initialize(server, ra_keypair)
        @server     = server
        @ra_keypair = ra_keypair
        @verify_request = true
        @verify_response = true
        @request_verification_certificates = []
        @response_verification_certificates = []
      end

      # Add certificates to verify when decrypting a request
      # @param [OpenSSL::X509::Certificate]
      def add_response_verification_certificate(cert)
        @response_verification_certificates << cert
      end

      def add_request_verification_certificate(cert)
        @request_verification_certificates << cert
      end

      # Don't verify certificates (possibly dangerous)
      def no_verify!
        no_verify_response!
        no_verify_request!
      end

      def no_verify_response!
        @verify_response = false
      end

      def no_verify_request!
        @verify_request = false
      end

      # Proxies the raw post request to another SCEP server. Extracts CSR andpublic keys along the way
      # @param [String] raw_post the raw post data. Should be a PKCS#7 der encoded message
      # @return [SCEP::Proxy::Result] the results of
      def forward_pki_request(raw_post)
        # Decrypt the request and re-encrypt for the target SCEP server
        request = SCEP::PKIOperation::Request.new(ra_keypair)
        request_verification_certificates.each do |cert|
          request.verify_against(cert)
        end
        reencrypted = request.proxy(raw_post, server.ra_certificate, verify_request).to_der

        # Forward to SCEP server
        http_response_body = server.pki_operation(reencrypted, true)

        # Decrypt response and re-encrypt for the device
        response = SCEP::PKIOperation::Response.new(ra_keypair)
        response_verification_certificates.each do |cert|
          response.verify_against(cert)
        end
        response_reencrypted = response.proxy(http_response_body, request.p7sign.certificates, verify_response)

        # Package relevant information
        return Result.new(request.csr, response.signed_certificates, response_reencrypted)
      end

      # Contains useful data from the results of proxying a SCEP request. Includes unencrypted
      # CSRs, Signed certificates and encrypted response
      class Result

        # The CSR sent to us
        # @return [OpenSSL::X509::Request]
        attr_accessor :csr

        # The signed certificates from the scep server
        # @return [Array<OpenSSL::X509::Certificate>]
        attr_accessor :signed_certificates

        # The resulting encrypted result. Should be sent back to client as DER
        # @return [OpenSSL::PKCS7]
        attr_accessor :p7enc_response

        # @param [OpenSSL::X509::Request] csr
        # @param [Array<OpenSSL::X509::Certificate>] signed_certificates
        # @param [OpenSSL::PKCS7] p7enc_response
        def initialize(csr, signed_certificates, p7enc_response)
          @csr = csr
          @signed_certificates= signed_certificates
          @p7enc_response = p7enc_response
        end
      end
    end
  end
end
