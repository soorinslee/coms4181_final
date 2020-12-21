
USER=${1?Error: no variable given}
PASSWORD=${2?Error: no variable given}

echo $PASSWORD
openssl genrsa -passout pass:$PASSWORD -aes256 -out keys/key.pem 4096
			
#openssl rsa -in keys/key.pem -passin pass:password -outform PEM -pubout -out keys/public.pem

#chmod 400 keys/key.pem

command="/CN=$USER/O=./C=US/ST=New York"
#echo $command

