require 'httparty'
require 'set'

module SCEP
  # Handles making requests to a SCEP server and storing the RA and CA certs. Currently uses
  # the URL defined in the `config/endpoints.yml` file.
  #
  # @example
  #   scep_endpoint = SCEP::Endpoint.new('https://scep-server-url.com')
  #   # Downloads RA, CA certs
  #   puts scep_endpoint.ca_certificate # => OpenSSL::X509::Certificate
  #   puts scep_endpoint.ra_certificate
  #
  # @todo GetCACaps
  class Endpoint
    include HTTParty
    include SCEP::Loggable

    # An exception raised if the SCEP server does not properly support the SCEP protocol.
    class ProtocolError < StandardError; end

    default_timeout 2

    attr_writer :ra_certificate

    attr_writer :ca_certificate

    attr_accessor :default_options

    def initialize(base_uri, default_options = {})
      @default_options = default_options.merge(:base_uri => base_uri)
    end

    # Gets the CA certificate. Will automatically download the CA certificate from
    # the server if it has not yet been downloaded.
    # @return [OpenSSL::X509::Certificate]
    # @raise [ProtocolError] if the SCEP server does not return valid certs
    def ca_certificate
      download_certificates if @ca_certificate.nil?
      return @ca_certificate
    end

    # Gets the RA certificate.
    # @return [OpenSSL::X509::Certificate]
    # @raise [ProtocolError] if the SCEP server does not return valid certs
    # @note This will return the {#ca_certificate CA certificate} if the SCEP server does not
    #   support RA certs.
    def ra_certificate
      # Force download of CA, possibly RA certificate
      @ra_certificate || ca_certificate
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
      logger.debug 'Downloading CA, possibly RA certificate from SCEP server'
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


    # Gets server capabilities. Memoized version of {#fetch_capabilities}
    # @return [Set<String>] a set of capabilities
    def capabilities
      @capabilities || fetch_capabilities
    end

    # Gets server capabilities. Always triggers a download of capabilities
    # @return [Set<String>] a set of capabilities
    def fetch_capabilities
      logger.debug 'Getting SCEP endpoint capabilities'
      response = scep_request 'GetCACaps'
      caps = response.body.strip.split("\n")
      @capabilities = Set.new(caps)
      logger.debug "SCEP endpoint supports capabilities: #{@capabilities.inspect}"
      return @capabilities
    end

    # Whether the SCEP endpoint supports the POSTPKIOperation
    # @return [Boolean] TRUE if it is supported, FALSE otherwise
    def post_pki_operation?
      capabilities.include?('POSTPKIOperation')
    end

    # Executes a SCEP request.
    # @param [String] operation the SCEP operation to perform
    # @param [String] message an optional message to send
    # @return [HTTParty::Response] the httparty response
    def scep_request(operation, message = nil, is_post = false)
      query = { :operation => operation }
      query[:message] = message unless message.nil?
      if is_post
        logger.debug "Executing POST ?operation=#{operation}"
        response = self.class.post '/', { :query => { :operation => operation}, :body => message }.merge(default_options)
      else
        logger.debug "Executing GET ?operation=#{operation}&message=#{message}"
        response = self.class.get '/', { :query => query }.merge(default_options)
      end

      if response.code != 200
        raise ProtocolError, "SCEP request returned non-200 code of #{response.code}"
      end

      return response
    end


    # TODO: handle GET PKIOperations
    # TODO: verify actually signed by CA?
    # @param [String] payload the raw payload to send
    # @return [String] the response body
    def pki_operation(payload)
      response = scep_request('PKIOperation', payload, true)
      if response.content_type != 'application/x-pki-message'
        raise ProtocolError,
          "SCEP PKIOperation didn't return content-type of application/x-pki-message (returned #{response.content_type})"
      end
      return response.body
    end

    protected

    def handle_ca_only_cert(response_body)
      logger.debug 'SCEP server does not support RA certificate - only using CA cert'
      @ca_certificate = OpenSSL::X509::Certificate.new(response_body)
    rescue StandardError
      fail ProtocolError, 'SCEP server did not return parseable X509::Certificate'
    end

    def handle_ca_ra_cert(response_body)
      logger.debug 'SCEP server has both RA and CA certificate'

      begin
        pcerts = PKCS7CertOnly.decode(response_body)
      rescue StandardError
        fail ProtocolError, 'SCEP server did not return a parseable PKCS#7'
      end

      fail ProtocolError,
           'SCEP server did not return two certificates in PKCS#7 cert chain' unless
        pcerts.certificates.length == 2


      unless pcerts.certificates[1].verify(pcerts.certificates[0].public_key)
        fail ProtocolError,
          'RA certificate must be signed by CA certificate when using RA/CA cert combination'
      end

      @ca_certificate = pcerts.certificates[0]
      @ra_certificate = pcerts.certificates[1]
    end
  end
end
