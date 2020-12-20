
USER=${1?Error: no variable given}

openssl genrsa -passout pass:password -aes256 -out keys/key.pem 4096
			
#openssl rsa -in keys/key.pem -passin pass:password -outform PEM -pubout -out keys/public.pem


openssl req -config openssl.cnf \
	  -passin pass:password\
	  -subj '/CN=${USER}/O=./C=US/ST=New York'\
      -key keys/key.pem \
      -new -sha256 -out csr/csr.pem
