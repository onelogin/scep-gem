require 'spec_helper'

describe SCEP::PKIOperation::Base do
  let(:ca_keypair)      { generate_keypair}
  let(:signed_keypair)  { generate_keypair(ca_keypair) }
  let(:ra_keypair)      { generate_keypair }
  let(:payload)         { 'Hello World!' }
  let(:base)            { SCEP::PKIOperation::Base.new(ra_keypair) }

  describe '#x509_store' do
    it 'returns an OpenSSL::X509::Store object' do
      expect(base.x509_store).to be_a(OpenSSL::X509::Store)
    end
  end

  describe '#unsign_and_unencrypt_raw' do

    let(:p7enc)  { OpenSSL::PKCS7.encrypt([ra_keypair.certificate], payload, SCEP::PKIOperation::Base.create_default_cipher, OpenSSL::PKCS7::BINARY) }
    let(:p7sign) { OpenSSL::PKCS7.sign(signed_keypair.certificate, signed_keypair.private_key, p7enc.to_der, [signed_keypair.certificate], OpenSSL::PKCS7::BINARY) }

    context 'without verification' do
      it 'decrypts the paylaod without issue' do
        decrypted = base.send(:unsign_and_unencrypt_raw, p7sign.to_der, false)
        expect(decrypted).to eql(payload)
      end
    end

    context 'with verification enabled' do

      context 'when verification succeeds' do
        it 'decrypts the payload' do
          base.x509_store.add_cert signed_keypair.certificate
          decrypted = base.send(:unsign_and_unencrypt_raw, p7sign.to_der, true)
          expect(decrypted).to eql(payload)
        end
      end

      context 'when verification fails' do
        let(:unrelated_keypair) { generate_keypair }

        it 'raises VerificationFailed if it is not verified against the correct certificate' do
          base.x509_store.add_cert unrelated_keypair.certificate
          expect {
            base.send(:unsign_and_unencrypt_raw, p7sign.to_der, true)
          }.to raise_error(SCEP::PKIOperation::VerificationFailed)
        end

        it 'raises VerificationFailed if no certs are added to the x509_store' do
          expect {
            base.send(:unsign_and_unencrypt_raw, p7sign.to_der, true)
          }.to raise_error(SCEP::PKIOperation::VerificationFailed)
        end
      end
    end
  end

  describe '#check_if_recipient_matches_ra_certificate_name' do
    let(:misc_keypair) { generate_keypair(nil, nil, '/C=Asdf/O=Fake')  }
    let(:p7enc)        { OpenSSL::PKCS7.encrypt([target_cert], 'foo', base.class.create_default_cipher)}

    context 'with matching recipients' do
      let(:target_cert)  { ra_keypair.certificate }

      it 'returns true' do
        matches = base.send(:check_if_recipient_matches_ra_certificate_name, p7enc)
        expect(matches).to eql(true)
      end
    end

    context 'with non-matching recepients' do
      let(:target_cert) { misc_keypair.certificate }

      it 'returns false' do
        matches = base.send(:check_if_recipient_matches_ra_certificate_name, p7enc)
        expect(matches).to eql(false)
      end
    end

    context 'with no recepients' do
      let(:p7enc) { OpenSSL::PKCS7.new }

      it 'returns false' do
        matches = base.send(:check_if_recipient_matches_ra_certificate_name, p7enc)
        expect(matches).to eql(false)
      end
    end
  end
end
