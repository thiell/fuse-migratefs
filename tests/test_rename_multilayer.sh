#!/bin/bash
# test rename of directory in multiple layers

set -e

LOWERDIR=${LOWERDIR:-/lower}
UPPERDIR=${UPPERDIR:-/upper}
MOUNTPOINT=${MOUNTPOINT:-/merged}

rm -rf $MOUNTPOINT/multilayer

mkdir -p $UPPERDIR/multilayer/dir1/subdir1
mkdir -p $LOWERDIR/multilayer/dir1/subdir2
touch $UPPERDIR/multilayer/dir1/file1
touch $LOWERDIR/multilayer/dir1/file2

cd $MOUNTPOINT/multilayer/
mv dir1 dir2

! test -d $LOWERDIR/multilayer/dir1
! test -d $UPPERDIR/multilayer/dir1
! test -d dir1
test -d dir2
test -d dir2/subdir1
test -d dir2/subdir2
test -f dir2/file1
test -f dir2/file2
