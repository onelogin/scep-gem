module SCEP
  # Handles making requests to a SCEP server and storing the RA and CA certs. Currently uses
  # the URL defined in the `config/endpoints.yml` file.
  #
  # @example
  #   scep_endpoint = SCEP::Server.new
  #   # Downloads RA, CA certs
  #   puts scep_endpoint.ca_certificate # => OpenSSL::X509::Certificate
  #   puts scep_endpoint.ra_certificate
  #
  class Server
    include HTTParty

    # An exception raised if the SCEP server does not properly support the SCEP protocol.
    class ProtocolError < StandardError; end

    default_timeout 2

    attr_writer :ra_certificate

    attr_writer :ca_certificate

    def self.new(uri, *args)
      Class.new(SCEP::AbstractServer) { |klass|
        klass.base_uri(uri)
      }.new(*args)
    end

    # Gets the CA certificate. Will automatically download the CA certificate from
    # the server if it has not yet been downloaded.
    # @return [OpenSSL::X509::Certificate]
    # @raise [ProtocolError] if the SCEP server does not return valid certs
    def ca_certificate
      download_certificates if @ca_certificate.blank?
      return @ca_certificate
    end

    # Gets the RA certificate.
    # @return [OpenSSL::X509::Certificate]
    # @raise [ProtocolError] if the SCEP server does not return valid certs
    # @note This will return the {#ca_certificate CA certificate} if the SCEP server does not
    #   support RA certs.
    def ra_certificate
      # Force download of CA, possibly RA certificate
      ca = ca_certificate
      @ra_certificate || ca
    end

    # Checks to see if the SCEP server supports the RA certificate
    # @return [Boolean]
    def supports_ra_certificate?
      ca_certificate != ra_certificate
    end

    # Downloads RA and CA certificates from the SCEP server using the `GetCACert` operation.
    # Will give {#ra_certificate} and {#ca_certificate} values.
    # @return [HTTParty::Response] the response from the SCEP server.
    # @raise [ProtocolError] if the
    def download_certificates
      log.debug 'Downloading CA, possibly RA certificate from SCEP server'
      response = scep_request 'GetCACert'
      if response.content_type == 'application/x-x509-ca-cert' # Only a CA cert
        handle_ca_only_cert(response.body)
      elsif response.content_type == 'application/x-x509-ca-ra-cert'
        handle_ca_ra_cert(response.body)
      else
        fail ProtocolError, "SCEP server returned invalid content type of #{response.content_type}"
      end
      return response
    end
    alias_method :get_ca_cert, :download_certificates

    # Executes a SCEP request.
    # @param [String] operation the SCEP operation to perform
    # @param [String] message an optional message to send
    # @return [HTTParty::Response] the httparty response
    def scep_request(operation, message = nil, is_post = false)
      query = { operation: operation }
      query[:message] = message if message.present?
      if is_post
        log.debug "Executing POST ?operation=#{operation}"
        response = self.class.post '/', query: {operation: operation}, body: message
      else
        log.debug "Executing GET ?operation=#{operation}&message=#{message}"
        response = self.class.get '/', query: query
      end
      response.assert.status(200)
      return response
    end

    protected

    def handle_ca_only_cert(response_body)
      log.debug 'SCEP server does not support RA certificate - only using CA cert'
      @ca_certificate = OpenSSL::X509::Certificate.new(response_body)
    rescue StandardError
      fail ProtocolError, 'SCEP server did not return parseable X509::Certificate'
    end

    def handle_ca_ra_cert(response_body)
      log.debug 'SCEP server has both RA and CA certificate'

      begin
        pcerts = Pkcs7CertOnly.decode(response_body)
      rescue StandardError
        fail ProtocolError, 'SCEP server did not return a parseable PKCS#7'
      end

      fail ProtocolError,
           'SCEP server did not return two certificates in PKCS#7 cert chain' unless
        pcerts.certificates.length == 2

      @ca_certificate = pcerts.certificates.first
      @ra_certificate = pcerts.certificates.second
    end
  end
end
