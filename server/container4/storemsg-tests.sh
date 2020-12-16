#!/bin/bash

echo "**** Valid user ****"

valgrind --leak-check=yes ./storemsg user1

echo "**** Invalid user ****"

valgrind --leak-check=yes ./storemsg user5

