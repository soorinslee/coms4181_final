#!/bin/bash

echo "**** Valid user ****"

valgrind --leak-check=yes ./getcertificate user1

echo "**** Invalid user ****"

valgrind --leak-check=yes ./getcertificate user5

echo "**** No certificate ****"

valgrind --leak-check=yes ./getcertificate user2
