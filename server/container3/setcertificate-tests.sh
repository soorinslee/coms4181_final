#!/bin/bash

echo "**** Valid user ****"

valgrind --leak-check=yes ./setcertificate user1

echo "**** Invalid user ****"

valgrind --leak-check=yes ./setcertificate user5

echo "**** No certificate ****"

valgrind --leak-check=yes ./setcertificate user2
