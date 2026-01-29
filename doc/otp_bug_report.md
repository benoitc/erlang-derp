# OTP Bug Report: public_key rejects certificates with CommonName > 64 characters

## Summary

OTP's `ssl` module rejects TLS connections to servers presenting certificates with CommonName
values longer than 64 characters, even with `{verify, verify_none}`. The failure occurs in
the ASN.1 decoder before any user-provided verification callbacks can run.

## Affected Versions

- OTP 28.0 through 28.3.1 (confirmed)
- Likely affects earlier OTP versions as well

## Reproduction

```erlang
%% Connect to Tailscale's DERP relay server
ssl:start().
ssl:connect("derp1.tailscale.com", 443, [{verify, verify_none}]).
%% Result: {error,{tls_alert,{handshake_failure,...}}}
```

Alternatively, fetch and decode the certificate:

```erlang
{ok, Sock} = gen_tcp:connect("derp1.tailscale.com", 443, [binary, {active, false}]),
gen_tcp:send(Sock, <<22,3,1,0,200,1,0,0,196,3,3,  %% ClientHello
                      0:256, 0,2,0,255, 1,0, 0,73, 0,0,0,26,0,24,0,0,21,
                      100,101,114,112,49,46,116,97,105,108,115,99,97,108,101,46,99,111,109,
                      0,11,0,4,3,0,1,2, 0,10,0,10,0,8,0,29,0,23,0,24,0,25,
                      0,35,0,0, 0,13,0,20,0,18,4,3,8,4,4,1,5,3,8,5,5,1,8,6,6,1,2,1>>),
{ok, ServerHello} = gen_tcp:recv(Sock, 0, 5000),
%% Extract Certificate message and decode...
```

## Root Cause

The server presents a certificate chain where the second certificate (a self-signed
ED25519 key certificate) has a 71-character CommonName:

```
CN=derpkey69dcb9a8b58dc832c30b8f892b0cd7f4b9a1c2e7f8d6a3e5b4c7d8e9f0a1b2c3d4
```

This is the hex-encoded hash of the DERP server's public key, used as a self-signed
certificate to authenticate the server.

OTP's ASN.1-generated decoder (`OTP-PKIX:decode('OTPCertificate', DerCert)`) enforces
the `ub-common-name = 64` SIZE constraint from X.520:

```asn1
ub-common-name INTEGER ::= 64
X520CommonName ::= DirectoryString {ub-common-name}
```

When the certificate is decoded, the constraint check fails:

```
** exception exit: {{asn1,{encode_error,{value_out_of_range,
    {size_constraint,64,71}}}},
  [{public_key,pkix_decode_cert,2,[...]},
   ...]}
```

## Why User Callbacks Cannot Help

The decode failure occurs at the lowest level of the ASN.1 decoder, before the `ssl`
module's verification pipeline begins. The `verify_fun`, `partial_chain`, and
`customize_hostname_check` callbacks all receive already-decoded certificates. When
a certificate fails to decode, these callbacks are never invoked.

There is no `ssl` option to skip or customize certificate decoding.

## Suggested Fix

Relax the `ub-common-name` constraint in `lib/public_key/asn1/OTP-PKIX.asn1` to
accept longer CommonName values. This is similar to the existing relaxation for
`ub-country-name` (which allows 3 characters instead of the strict 2):

```asn1
%% Current:
ub-common-name INTEGER ::= 64

%% Proposed:
ub-common-name INTEGER ::= 255  -- Or remove constraint entirely
```

## Justification

1. **Real-world compatibility**: Tailscale's DERP relay servers use 71-character CNs.
   This is a production service with millions of users.

2. **Security**: Certificate validation (signature, chain, expiry) should not depend
   on name length constraints. A 71-character CN is not a security risk.

3. **Precedent**: Other TLS implementations (BoringSSL, OpenSSL, Go's crypto/tls,
   browsers) accept certificates with long CommonNames without issue.

4. **Workaround burden**: The only workaround is to use a different TLS implementation
   (e.g., a BoringSSL NIF), which is significant engineering effort.

## References

- X.520 specification: ITU-T Rec. X.520 (defines `ub-common-name = 64`)
- Tailscale DERP protocol: https://tailscale.com/kb/1232/derp-servers
- RFC 5280 (X.509 PKI): Does not enforce CommonName length limits in the wire format

## Workaround

For now, users can work around this by using a custom TLS implementation that
doesn't enforce the X.520 size constraints. We implemented a BoringSSL-based
NIF (`derp_tls`) to bypass this issue:

https://github.com/benoitc/erlang-derp (see `c_src/derp_tls_nif.c`)
