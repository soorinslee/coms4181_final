#openssl genrsa -out keys/key.pem 2048
openssl genrsa -passout pass:password -aes256 -out keys/key.pem 4096
			
openssl rsa -in keys/key.pem -passin pass:password -outform PEM -pubout -out keys/public.pem

chmod 400 keys/key.pem