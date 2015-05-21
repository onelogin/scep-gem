require 'tempfile'
require 'shellwords'

module SCEP
  class JSCEPCli

    # Handles arguments for a request for the JSCEP CLI. The help output is below:
    #
    # ```
    # Usage: <main class> [options]
    # Options:
    #       --algorithm             BouncyCastle signature algorithm to use
    #                               Default: SHA1
    #       --ca-certificate-file   CACert output file
    #                               Default: cacert.pem
    #       --ca-identifier         CA identifier (try AdminCA1 if using a default
    #                               EJBCA install)
    #       --certificate-file      Certificate output file
    #                               Default: cert.pem
    # *     --challenge             Challenge password (EJBCA entity password)
    #       --crl-file              CRL output file
    #                               Default: crl.pem
    #       --csr-file              CSR output file
    # *     --dn                    Subject DN to request
    #       --key-file              Private key output file
    #                               Default: privkey.pem
    #       --keySize               Size of key, if you want more than 2048, you
    #                               need the JCE
    #                               Default: 2048
    #   -t, --text                  Output PEM-format objects on stdout. (similar to
    #                               'openssl <cmd> -text')
    #                               Default: false
    # *     --url                   SCEP URL. For EJBCA, use
    #                               http://<hostname>:<port>/ejbca/publicweb/apply/scep/pkiclient.exe
    #   -v, --verbose               Verbose output
    #                                Default: false
    # ```
    class Request

      # @return [String] the identifier of the CA
      attr_accessor :ca_identifier

      # @return [String] the challenge to send to the
      attr_accessor :challenge

      # @return [OpenSSL::X509::Request] the CSR request
      attr_accessor :csr

      # If in doubt, set to "CN=<name of user in ejdbca>"
      # @return [String] the distinguished name.
      attr_accessor :dn

      # @return [OpenSSL::PKey] the private key of the person making the request (us)
      attr_accessor :private_key

      # @return [String] the URL of the SCEP server
      attr_accessor :url

      def initialize(csr, private_key, ca_identifier, dn, challenge, url)
        @csr = csr
        @private_key = private_key
        @ca_identifier = ca_identifier
        @dn = dn
        @challenge = challenge
        @url = url
      end


      def csr_file
        @csr_file ||= begin
          file = Tempfile.new('jscep-cli.csr')
          file.write(csr.to_pem)
          file
        end
      end

      def private_key_file
        @private_key_file ||= begin
          file = Tempfile.new('jscep-cli.pkey')
          file.write(private_key.to_pem)
          file
        end
      end

      # Gets the certificate returned
      # @return [OpenSSL::X509::Certificate]
      def cert
        cert_file.rewind
        OpenSSL::X509::Certificate.new(cert_file.read)
      end

      def cert_file
        @x509_cert_file ||= Tempfile.new('jscep-cli.crt')
      end


      def destroy_tempfiles!
        csr_file.unlink
        private_key_file.unlink
        cert_file.unlink
      end

      def to_cli_argument_hash
        {
          'ca-identifier' => ca_identifier,
          'challenge' => challenge,
          'url' => url,
          'csr-file' => csr_file.path,
          'key-file' => private_key_file.path,
          'certificate-file' => cert_file.path,
          'dn' => dn
        }
      end

      def to_cli_arguments
        cli_argument_string = ''
        to_cli_argument_hash.each do |argument,value|
          cli_argument_string << "--#{argument} #{Shellwords.escape(value)} "
        end
        cli_argument_string.strip
      end



    end
  end
end
