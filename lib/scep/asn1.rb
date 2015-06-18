# Add OpenSSL ASN1 objects here as needed

OpenSSL::ASN1::ObjectId.register('2.16.840.1.113733.1.9.2', 'messageType', 'scep-messageType')


module SCEP

  # Re-usable ASN1 compnents for some of the finer points of SCEP
  module ASN1

    MESSAGE_TYPE_PKCS_REQ = 19

    # Pre-made ASN1 value that identifies what type of message this is
    def self.message_type(type = MESSAGE_TYPE_PKCS_REQ)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::ObjectId.new('scep-messageType'),
        OpenSSL::ASN1::Set.new([
          OpenSSL::ASN1::PrintableString.new(type.to_s)
        ])
      ])
    end

    def self.pkcs7_signature_hash(hash, algorithm_name)
      OpenSSL::ASN1::Sequence.new([
        OpenSSL::ASN1::Sequence.new([
          OpenSSL::ASN1::ObjectId.new(algorithm_name),
          OpenSSL::ASN1::Null.new(nil)
        ]),
        OpenSSL::ASN1::OctetString.new(hash)
      ])
    end

    def self.calculate_and_generate_pkcs7_signature_hash(data, algorithm)
      hash = OpenSSL::Digest.digest(algorithm, data)
      pkcs7_signature_hash(hash, algorithm)
    end
  end
end
