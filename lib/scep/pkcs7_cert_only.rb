module SCEP
  # Workaround for issue generating PKCS#7 certificate only in ruby 2.x.
  #
  # Normally you could generate the certificate chain using the following code:
  #
  # ```ruby
  # p7certs = OpenSSL::PKCS7.new
  # p7certs.type = 'signed'
  # p7certs.certificates = [x509_cert_1, x509_cert_2]
  # ````
  #
  # But producing this in a der format is not valid:
  #
  # ```ruby
  # der = p7certs.to_der
  # p7decoded = OpenSSL::PKCS7.new(der) # exception!
  # ```
  #
  # This class manually creates the ASN1 notation and creates a correctly formatted result:
  #
  # ```ruby
  # p7certs = Pkcs7CertOnly.new([x509_cert_1, x509_cert_2])
  # der = p7certs.to_der
  # p7decoded = OpenSSL::PKCS7.new(der) # works!
  # p7decoded.certificates # => [ array of the original x509 certificates ]
  # ```
  #
  # @see https://groups.google.com/forum/#!topic/mailing.openssl.users/AIZndhJuG7I
  # @see https://gist.github.com/cgthornt/fe1f9d68e18cc4d1ba20
  class Pkcs7CertOnly
    include OpenSSL::ASN1

    # @return [Array<OpenSSL::X509::Certificate>]
    attr_accessor :certificates

    def initialize(certificates = [])
      @certificates = certificates
    end

    # Takes a binary encoded DER PKCS#7 certificates only payload and decodes it
    # @param [String] der_encoded the encoded payload
    # @return [Pkcs7CertOnly]
    def self.decode(der_encoded)
      p7certs = OpenSSL::PKCS7.new(der_encoded)
      new(p7certs.certificates)
    end

    # Converts this into an ASN1 sequence
    # @return [OpenSSL::ASN1::Sequence]
    def to_asn1

      # Converts to an array of ASN1 encoded certs
      asn1_certs = certificates.map do |cert|
        decode(cert.to_der)
      end

      Sequence.new([
       OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.2'),
       ASN1Data.new([
        Sequence.new([
         OpenSSL::ASN1::Integer.new(1),
         OpenSSL::ASN1::Set.new([]),
         Sequence.new([
            OpenSSL::ASN1::ObjectId.new('1.2.840.113549.1.7.1')
          ]),
         ASN1Data.new(asn1_certs, 0, :CONTEXT_SPECIFIC),
         ASN1Data.new([], 1, :CONTEXT_SPECIFIC),
         OpenSSL::ASN1::Set.new([])
       ])
      ], 0, :CONTEXT_SPECIFIC)
     ])
    end

    # Gets this in a der (binary) format
    # @return [String] binary encoded format
    def to_der
      to_asn1.to_der
    end

    # Gets this as a PKCS7 object
    # @return [OpenSSL::PKCS7]
    def to_pkcs7
      OpenSSL::PKCS7.new(to_der)
    end
  end
end
