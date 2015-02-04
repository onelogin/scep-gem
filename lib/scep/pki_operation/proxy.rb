module SCEP

  module PKIOperation
    # Enables proxying a PKI SCEP request from the DSL to another SCEP server
    # @example
    #   def pkioperation
    #     server = SCEP::Server.new
    #     proxy = SCEP::Proxy.new(server, @ra_cert, @ra_pk)
    #     response = proxy.forward_pki_request(request.raw_post)
    #     send_data response.p7enc_response.to_der
    #   end
    class Proxy
      attr_accessor :server

      attr_accessor :ra_keypair

      # @param [SCEP::Server] server
      # @param [Keypair] ra_keypair
      def initialize(server, ra_keypair)
        @server = server
        @ra_keypair = ra_keypair
      end

      # Proxies the raw post request to another SCEP server. Extracts CSR andpublic keys along the way
      # @param [String] raw_post the raw post data. Should be a PKCS#7 der encoded message
      # @return [SCEP::Proxy::Result] the results of
      def forward_pki_request(raw_post)
        # Decrypt the request and re-encrypt for the target SCEP server
        request = SCEP::PKIOperation::Request.new(ra_keypair)
        reencrypted = request.proxy(raw_post, server.ra_certificate).to_der

        # Forward to SCEP server
        http_response = server.scep_request('PKIOperation', reencrypted, true)

        # Decrypt response and re-encrypt for the device
        response = SCEP::PKIOperation::Response.new(ra_keypair)
        response_reencrypted = response.proxy(http_response.body, request.p7sign.certificates)

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
