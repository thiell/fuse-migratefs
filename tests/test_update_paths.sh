#!/bin/bash
# update_path() deadlock check

set -e

MOUNTPOINT=${MOUNTPOINT:-/merged}

cd $MOUNTPOINT/test
rm -rf interleave
mkdir interleave
cd interleave
mkdir dir1
mkdir newdir2

for i in {3..100}; do
  j=$(( $i - 1 ))
  k=$(( $i - 2 ))
  mkdir newdir$i
  for n in {1..100}; do
    touch newdir$i/file$n
  done
  ls newdir$i >/dev/null
  for n in {1..100..2}; do
    mv newdir$i/file$n newdir$i/file$((n+1000))
  done
  mv newdir$j dir$j
  touch newfile$k
  mv newfile$k file$k
  ls dir$j >/dev/null
done
