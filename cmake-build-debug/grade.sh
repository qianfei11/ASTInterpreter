#!/bin/bash

ASTI="./ast-interpreter"
LIBCODE="../lib/builtin.c"

TEST_DIR="../test"
file_list=$(ls $TEST_DIR)
# assume all the file in TEST_DIR is ``.c` file
total=$(echo "$file_list"|wc -w)
correct=0
echo "total test cases: $total"
for file in $file_list; do
    echo "testing $file"
    # result given by our interpreter
    filename="$TEST_DIR/$file"
    ccode=$(cat $filename)
    # make $correct as the user input, you can change it if you like
    actual=$(echo $correct|($ASTI "$ccode" 2>&1>/dev/null))
    # result given by gcc
    gcc $filename $LIBCODE -o x.out
    expected=$(echo $correct|./x.out)
    if [[ "$actual" = "$expected" ]]; then
        echo "$file passed"
        correct=$(( $correct + 1 ))
    fi
done
echo "$correct/$total"

