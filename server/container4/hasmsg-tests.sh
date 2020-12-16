#!/bin/bash

echo "**** Valid user with messages ****"

valgrind --leak-check=yes ./hasmsg user1

echo "**** Invalid user ****"

valgrind --leak-check=yes ./hasmsg user5

echo "**** Valid user with no messages ****"

valgrind --leak-check=yes ./hasmsg user2

