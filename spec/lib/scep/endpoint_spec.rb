require 'spec_helper'

describe SCEP::Endpoint do

  # The CA and RA of our SCEP server
  let(:ca_keypair) { generate_keypair }
  let(:ra_keypair) { generate_keypair(ca_keypair)}

  # Not signed by CA!
  let(:invalid_ra_keypair) { generate_keypair }

  let(:base_url) { 'http://scep.server' }
  let(:p7certs_ca_ra) { SCEP::PKCS7CertOnly.new([ca_keypair.cert, ra_keypair.cert])}

  subject { SCEP::Endpoint.new(base_url) }

  # General-purpose stubs
  before do
    stub_request(:get, "http://scep.server/?operation=GetCACert").
      to_return(:status => 200, :body => p7certs_ca_ra.to_der, :headers => { 'Content-Type' => 'application/x-x509-ca-ra-cert'})
  end

  describe '#ca_certificate' do
    it 'calls #download_certificate when not previously called' do
      expect(subject).to receive(:download_certificates)
      subject.ca_certificate
    end
  end

  describe '#ra_certificate' do
    it 'calls #ca_certificate when not previously called' do
      expect(subject).to receive(:ca_certificate)
      subject.ra_certificate
    end
  end

  describe '#supports_ra_certificate?' do
    context 'when it does support an RA certificate' do
      it 'returns true' do
        expect(subject.supports_ra_certificate?).to eql(true)
      end
    end

  end


  describe '#download_certificates' do
    context 'with a valid response' do

      context 'with both an CA and RA certificate' do
        it 'successfully assigns #ca_certificate and #ra_certificate' do
          subject.download_certificates
          expect(subject.ca_certificate.to_s).to eql(ca_keypair.cert.to_s)
          expect(subject.ra_certificate.to_s).to eql(ra_keypair.cert.to_s)
        end
      end

      context 'with only a CA certificate' do
        before do
          stub_request(:get, "http://scep.server/?operation=GetCACert").
            to_return(:status => 200, :body => ca_keypair.cert.to_der, :headers => { 'Content-Type' => 'application/x-x509-ca-cert'})
        end

        it 'successfully assigns #ca_certificate' do
          subject.download_certificates
          expect(subject.ca_certificate.to_s).to eql(ca_keypair.cert.to_s)
        end

        it 'assigns #ca_certificate and #ra_certificate to be the same' do
          subject.download_certificates
          expect(subject.ca_certificate).to eql(subject.ra_certificate)
        end
      end

    end

    context 'with an invalid response' do
      context 'when RA cert is not signed by the CA cert' do
        let(:p7certs_ca_ra) { SCEP::PKCS7CertOnly.new([ca_keypair.cert, invalid_ra_keypair.cert])}

        it 'raises a SCEP::ProtocolError' do
          expect {
            subject.download_certificates
          }.to raise_error(SCEP::Endpoint::ProtocolError, 'RA certificate must be signed by CA certificate when using RA/CA cert combination')
        end
      end

      context 'when the content type is not correct' do
        before do
          stub_request(:get, "http://scep.server/?operation=GetCACert").
            to_return(:status => 200, :body => ca_keypair.cert.to_der, :headers => { 'Content-Type' => 'application/octet-stream'})
        end

        it 'raises a ProtocolError' do
          expect {
            subject.download_certificates
          }.to raise_error(SCEP::Endpoint::ProtocolError, 'SCEP server returned invalid content type of application/octet-stream')
        end
      end


    end

  end

end
