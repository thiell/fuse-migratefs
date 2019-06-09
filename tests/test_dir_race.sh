#!/bin/bash
# regression test for create/opendir race
# original reproducer from Andrew J. Beel, 2019/06/08

set -e
set -u

LOWERDIR=${LOWERDIR:-/lower}
UPPERDIR=${UPPERDIR:-/upper}
MOUNTPOINT=${MOUNTPOINT:-/merged}

typeset dir1="$MOUNTPOINT/tmp/1"
typeset dir2="$MOUNTPOINT/tmp/2"
typeset f1 f2 i
typeset n="1e4"

mkdir -p "$dir1" "$dir2"

for i in $(seq -w "$n"); do
  f1="$dir1/$i"
  f2="$dir2/$i"
  : > "$f1"
  mv -t "$dir2" -- "$f1"
  rm -- "$f2"
done &
job1pid=$!

for i in $(seq -w "$n"); do
  ls $dir1 $dir2 >/dev/null
done &
job2pid=$!

wait $job1pid
wait $job2pid
