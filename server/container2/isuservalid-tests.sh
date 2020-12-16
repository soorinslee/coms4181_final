#!/bin/bash

echo "**** Valid user and password ****"

valgrind --leak-check=yes ./isuservalid user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab

echo "**** Valid user and invalid password ****"

valgrind --leak-check=yes ./isuservalid user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

echo "**** Invalid user and valid password ****"

valgrind --leak-check=yes ./isuservalid user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab

echo "**** Stored password invalid format ****"

valgrind --leak-check=yes ./isuservalid user2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab

rm -rf ./passwords

echo "**** No passwords directory ****"

valgrind --leak-check=yes ./isuservalid user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab

mkdir passwords
