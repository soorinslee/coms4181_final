#!/bin/bash

echo "**** Valid user ****"

valgrind --leak-check=yes ./getnextmsg user1

echo "**** Invalid user ****"

valgrind --leak-check=yes ./getnextmsg user5


