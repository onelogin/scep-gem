SCEP Gem
========
Libraries that allow you to be a SCEP server, be a SCEP proxy, etc.

If you believe you have discovered a security vulnerability in this gem, please email security@onelogin.com with a description. You can also use the form based submission located here: https://www.onelogin.com/security. We follow responsible disclosure guidelines, and will work with you to quickly find a resolution.

## Terminology

* CSR - Certificate Signing Request. "I want you to sign my public key so you know who I am in the future"
* CA - Certificate Authority. The ultimate authority who can sign certificates.
* RA - Registration Authority. RA Certificates must be signed by CA. Accepts CSR on behalf of CA.
  Forwards CSR to CA for signing. You can proxy through to multiple CA

Note that a CA can be an RA.


## SCEP Requests
Contains a CSR that requires signing

### Encrypt request
When we want to forward a CSR to a RA. We may or may not be an RA ourselves.

First,collect some certificates:

```ruby
their_ra_cert = OpenSSL::X509::Certificate.new File.read(their-ra.crt')
our_keypair   = SCEP::Keypair.read 'our.crt', 'our.key'
csr           = OpenSSL::X509::Request.new File.read('some.csr')
```

Now create a request object and get the encrypted result:

```ruby
request = SCEP::PKIOperation::Request.new(our_keypair)
request.csr = csr
encrypted = request.encrypt(their_ra_cert)
```

We can then send `encrypted` to an RA

### Decrypt Request
When we are an RA.

First, collect some certificates:

```ruby
their_cert     = OpenSSL::X509::Certificate.new File.read('their.crt')
our_ra_keypair = SCEP::Keypair.read 'our-ra.crt', 'our-ra.key'
```

Now we can make a request object and get the original CSR:

```ruby
request = SCEP::PKIOperation::Request.new(our_ra_keypair)
request.verify_against(their_cert) # Make sure the response was signed by someone we trust

# Fails decryption if not signed by `their_cert`
request.decrypt(encrypted_request)

# Will always decrypt and ignore signature verification
request.decrypt(encrypted_request, false)

# Now get the encoded CSR
puts request.csr # => OpenSSL::X509::Request
```

### Proxying a Request
If we are an RA, we can decrypt a request intended for us and re-encrypt it for another RA
and grab the CSR in the process


```ruby
their_cert     = OpenSSL::X509::Certificate.new File.read('their.crt')
their_ra_cert  = OpenSSL::X509::Certificate.new File.read('their-ra.crt')
our_ra_keypair = SCEP::Keypair.read 'our-ra.crt', 'our-ra.key'

request = SCEP::PKIOperation::Request.new(our_ra_keypair)
request.verify_against(their_cert)
newly_encrypted = request.proxy(original_encrypted_result, their_ra_cert)
p request.csr # => OpenSSL::X509::Request
```

## SCEP Response
Contains the signed X509 Certificate

### Encrypting a Response
When we are an RA

```ruby
their_cert     = OpenSSL::X509::Certificate.new File.read('their.crt')
our_ra_keypair = SCEP::Keypair.read 'our-ra.crt', 'our-ra.key'

signed_cert    = OpenSSL::X509::Certificate.new File.read('cert-signed-by-ca.crt')

response = SCEP::PKIOperation::Response.new(our_ra_keypair)
encrypted = response.encrypt(their_cert)
```

### Decrypting a Response
When we are decrypting information from an RA

```ruby
their_ra_cert = OpenSSL::X509::Certificate.new File.read(their-ra.crt')
our_keypair   = SCEP::Keypair.read 'our.crt', 'our.key'

response = SCEP::PKIOperation::Response.new(our_keypair)
response.verify_against(their_ra_cert)
response.decrypt(encrypted_response)
p response.signed_certificates  # => [OpenSSL::X509::Certificate]
```

## SCEP Proxy

Easily be a SCEP proxy (psuedo sinatra syntax):

```ruby
require 'scep'

ra_keypair = SCEP::Keypair.read('certs/ra.crt', 'certs/ra.key')
scep_server = SCEP::Endpoint.new 'https://some-final-endpoint.com'

post '/scep?operation=PKIOperation' do
  proxy = SCEP::PKIOperation::Proxy.new(server, ra_keypair)

  # Options to verify certificates:

  # Verify request came from apple certificate
  proxy.add_request_verification_certificate(@apple_cert) # OpenSSL::X509::Certificate

  # Verify response came from CA certificate
  proxy.add_response_verificaion_certificate(@ca_certificate) # OpenSSL::X509::Certificate

  # Or don't verify anything
  proxy.no_verify!

  result = proxy.forward_pki_request(request.raw_post)

  puts result.csr # The CSR they sent
  puts result.signed_certificates # Returned signed certs from the SCEP server

  headers['content-type'] = 'application/x-pki-message'
  render results.p7enc_response.to_der
end
```
