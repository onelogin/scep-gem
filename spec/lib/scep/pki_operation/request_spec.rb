require 'spec_helper'

describe SCEP::PKIOperation::Request do

  let(:ra_keypair)   { generate_keypair }
  let(:misc_keypair) { generate_keypair}
  let(:csr)     { OpenSSL::X509::Request.new read_fixture('self-signed.csr') }
  let(:payload) { csr.to_der }
  let(:p7enc)   { OpenSSL::PKCS7.encrypt([ra_keypair.certificate], payload, SCEP::PKIOperation::Base.create_default_cipher, OpenSSL::PKCS7::BINARY) }
  let(:p7sign)  { OpenSSL::PKCS7.sign(misc_keypair.certificate, misc_keypair.private_key, p7enc.to_der, [misc_keypair.certificate], OpenSSL::PKCS7::BINARY) }

  subject { SCEP::PKIOperation::Request.new(ra_keypair) }

  before do
    subject.x509_store.add_cert(misc_keypair.certificate)
  end

  describe '#decrypt' do
    it 'decrypts the csr in its original format' do
      subject.decrypt(p7sign.to_der)
      expect(subject.csr.to_pem).to eql(csr.to_pem)
    end
  end

  describe '#encrypt' do
    context 'without message type tampering' do
      it 'encrypts and signs the CSR' do
        subject.csr = csr
        encrypted = subject.encrypt(misc_keypair.certificate)

        # Might as well use our already tested decryption method above
        request = SCEP::PKIOperation::Request.new(misc_keypair)
        request.add_verification_certificate(ra_keypair.certificate)
        request.decrypt(encrypted)
        expect(request.csr.to_pem).to eql(csr.to_pem)
      end
    end

    context 'with message type tampering' do
      it 'encrypts, but breaks verification' do
        subject.csr = csr
        subject.tamper_scep_message_type = true
        signed_and_encrypted = subject.encrypt(misc_keypair.certificate)

        p7sign = OpenSSL::PKCS7.new(signed_and_encrypted)
        store = OpenSSL::X509::Store.new
        store.add_cert(ra_keypair.certificate)
        verified = p7sign.verify([], store, nil, OpenSSL::PKCS7::BINARY)

        # Is this test failing?
        # Is #add_scep_message_type method adding the correct digest? Then this test is invalid - delete it!
        # Otherwise, you might be returning the pre-tampered message
        expect(verified).to eql(false)
      end
    end
  end

  describe '#proxy' do
    let(:final_keypair) { generate_keypair }

    it 'decrypts the csr and then re-encrypts it for another target cert' do
      subject.verify_against(ra_keypair.certificate)
      encrypted = subject.proxy(p7sign.to_der, final_keypair.certificate)
      expect(subject.csr.to_pem).to eql(csr.to_pem)

      # Now make sure our new keypair can access & decrypt it
      request = SCEP::PKIOperation::Request.new(final_keypair)
      request.verify_against(ra_keypair.certificate)
      request.decrypt(encrypted)
      expect(request.csr.to_pem).to eql(csr.to_pem)
      # As you can imagine, we should be able to do *n* number of proxies
    end
  end

  # The procedure of this test:
  #
  #  1 - Generate a PKCS7 request
  #  2 - Get it's original authenticatedAttributes digest
  #  3 - Re-calculate the authenticatedAttributes
  #  4 - Ensure new digest is exactly the same as the original
  #
  # Currently stuck, so commented out for now
  describe '#recalculate_authenticated_attributes_digest' do
    def pluck_digest(signer_info)
      encrypted_digest = signer_info.value.last.value
      decrypted_asn1_digest = subject.ra_keypair.private_key.public_decrypt(encrypted_digest)
      decrypted_asn1_digest = OpenSSL::ASN1.decode(decrypted_asn1_digest)
      return decrypted_asn1_digest.value.last.value
    end

    it 'correctly generates a new digest' do
      pending 'Need to figure out how to correctly generate a digest!'

      subject.csr = csr
      p7sign = subject.encrypt(misc_keypair.certificate)
      asn1 =  OpenSSL::ASN1.decode(p7sign.to_der)

      signer_info = asn1.value[1].value[0].value[4].value[0]
      original_digest = pluck_digest(signer_info)

      subject.send(:recalculate_authenticated_attributes_digest, signer_info)

      new_digest = pluck_digest(signer_info)

      expect(new_digest).to eql(original_digest)


    end

  end
end
