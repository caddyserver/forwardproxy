#!/bin/bash
set -e

make

PCAPFILE=$1
LEN=$2

TEMP=/tmp/spacesavingtemp

./readpcap $PCAPFILE > $TEMP-read
./perfect < $TEMP-read > $TEMP-perfect
./main $LEN < $TEMP-read > $TEMP-rate
python compare.py $TEMP-perfect $TEMP-rate 30
