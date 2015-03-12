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

  end
end
