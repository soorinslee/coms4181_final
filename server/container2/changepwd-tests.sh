#!/bin/bash

echo "**** Valid user, old password, and new password ****"

valgrind --leak-check=yes ./changepwd user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax

echo "**** Valid user and old password; invalid new password ****"

valgrind --leak-check=yes ./changepwd user1 aaaaaaaaaaaaaaa aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax

echo "**** Invalid user ****"

valgrind --leak-check=yes ./changepwd user5 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax

echo "**** Invalid old password ****"

valgrind --leak-check=yes ./changepwd user1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaq aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaax

