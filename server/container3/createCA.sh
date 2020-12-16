#!/bin/bash

#Remove existing ca folder
rm -rf ca


#setup the directory for the CA
mkdir ./ca
cd ca/
mkdir certs private newcerts
chmod 700 private
touch index.txt
echo 1000 > serial


#Replace the empty openssl.cnf file with prepared file
cp ../ca_files/$1 openssl.cnf


#Create root key
openssl genrsa -aes256 -passout pass:123456 -out private/ca.key.pem 4096
chmod 400 private/ca.key.pem


#Using root key create root cert
openssl req -config openssl.cnf -passin pass:123456 -key private/ca.key.pem -new -x509 -days 7300 -sha256 -extensions v3_ca -subj /C=US/ST=NY/L=NYC/O=Final/OU=Final/CN=FinalCA -out certs/ca.cert.pem
chmod 444 certs/ca.cert.pem
echo -e "\n\n---------------Verifying the root CA-----------------\n"
openssl x509 -noout -text -in certs/ca.cert.pem

#Setup directory for the intermediate CA
mkdir intermediate
cd intermediate
mkdir certs csr private newcerts
chmod 700 private
touch index.txt
echo 1000 > serial


#Copy the prepared intermediate cnf file
cp ../../ca_files/$2 openssl.cnf


#Create intermediate key
cd ..
openssl genrsa -aes256 -passout pass:123456 -out intermediate/private/intermediate.key.pem 4096
chmod 400 intermediate/private/intermediate.key.pem


#Create intermediate cert
openssl req -config intermediate/openssl.cnf -new -sha256 -passin pass:123456 -key intermediate/private/intermediate.key.pem -subj /C=US/ST=NY/L=NYC/O=Final/OU=Final/CN=FinalINT -out intermediate/csr/intermediate.csr.pem
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 3650 -notext -md sha256 -passin pass:123456 -in intermediate/csr/intermediate.csr.pem -out intermediate/certs/intermediate.cert.pem -batch
chmod 444 intermediate/certs/intermediate.cert.pem
echo -e "\n\n----------------Verifying the intermediate CA-----------------\n"
openssl x509 -noout -text -in intermediate/certs/intermediate.cert.pem
openssl verify -CAfile certs/ca.cert.pem intermediate/certs/intermediate.cert.pem


#Create certificate chain
cat intermediate/certs/intermediate.cert.pem certs/ca.cert.pem > intermediate/certs/ca-chain.cert.pem
chmod 444 intermediate/certs/ca-chain.cert.pem


cd ..










