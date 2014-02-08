gxmpp
=====

go xmpp server

First start in simple. Rfc6120

# Roadmap

## Milestone 1:
DO:
1. Xmpp Client-Server
2. TLS (if necessary)
3. SASL
4. Chating
5. Everything in memory.

## DOING NOW
TLS negotiation
Abstract plugin interface and apply to SASL 

## Note
This project is coding in action. Very unstable now.
Dirty code and modify structure in every commitment.


### Steps generate certificate
openssl genrsa 1024 -out gxmpp_test.key
openssl req -new -x509 -nodes -sha256 -days 3650 -key gxmpp_test.key > gxmpp_509.pem
