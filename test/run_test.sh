#!/bin/bash
#
#
# 

for i in 8 16 32 64
do

    if [ -e "test" ]
    then

        rm test

    fi

    make clean
    echo "make test$i"
    make test$i 

    if [ -e "test" ]
    then

        ./test

    else

        echo "Build failed"

    fi

done
