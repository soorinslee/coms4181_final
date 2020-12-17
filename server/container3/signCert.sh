#!/bin/bash

cd ca
cert_ext=usr_cert
cmn_name=final.com

if [ "$1" == "server" ]
then
    cert_ext=server_cert
    cmn_name=www.final.com
elif [ "$1" == "client" ]
then
    cert_ext=usr_cert
    cmn_name=final.com
else
    echo "Invalid command: $1"
    exit 1
fi

openssl genrsa -out intermediate/private/$cmn_name.key.pem 2048
chmod 400 intermediate/private/$cmn_name.key.pem

openssl req -config intermediate/openssl.cnf -passin pass:123456 -key intermediate/private/$cmn_name.key.pem -new -sha256 -subj /C=US/ST=NY/L=NYC/O=Final/OU=Final/CN=$cmn_name -out intermediate/csr/$cmn_name.csr.pem




openssl ca -config intermediate/openssl.cnf -passin pass:123456 -extensions $cert_ext -days 375 -notext -md sha256 -in intermediate/csr/$cmn_name.csr.pem -out intermediate/certs/$cmn_name.cert.pem -batch
chmod 444 intermediate/certs/$cmn_name.cert.pem
openssl x509 -noout -text -in intermediate/certs/$cmn_name.cert.pem
echo "Verify certificate chain of trust"
openssl verify -CAfile intermediate/certs/ca-chain.cert.pem intermediate/certs/$cmn_name.cert.pem
