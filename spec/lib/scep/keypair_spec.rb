require 'spec_helper'

describe SCEP::Keypair do
  let(:certificate) { OpenSSL::X509::Certificate.new read_fixture('self-signed.crt') }
  let(:private_key) { OpenSSL::PKey.read read_fixture('self-signed.key') }

  describe '#initialize' do
    it 'creates a keypair with valid parameters' do
      SCEP::Keypair.new(certificate, private_key)
    end

    it 'fails with invalid arguments' do
      expect {
        SCEP::Keypair.new(private_key, private_key)
      }.to raise_error(ArgumentError)
    end
  end

  describe '.read' do
    it 'reads from the correct files' do
      keypair = SCEP::Keypair.read(
        fixture_path('self-signed.crt'),
        fixture_path('self-signed.key')
      )

      expect(keypair.certificate.to_pem).to eql(certificate.to_pem)
      expect(keypair.private_key.to_pem).to eql(private_key.to_pem)
    end
  end
end
