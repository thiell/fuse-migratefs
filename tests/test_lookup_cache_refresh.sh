#!/bin/bash
# test do_lookup_file() proper cache refresh

# Original issue:
# $ mkdir d
# $ mkdir d/a
# $ ls -li d
# total 0
# 1152921504658396905 drwxr-xr-x 2 sthiell operator 6 May  5 20:35 a
# $ mv /upper/d/a /upper/d/b
# $ mkdir d/a
# mkdir: cannot create directory ‘d/a’: File exists

set -e

LOWERDIR=${LOWERDIR:-/lower}
UPPERDIR=${UPPERDIR:-/upper}
MOUNTPOINT=${MOUNTPOINT:-/merged}

echo "# upper"
rm -rf $MOUNTPOINT/d
mkdir $MOUNTPOINT/d
mkdir $MOUNTPOINT/d/a
ls -li $MOUNTPOINT/d
mv $UPPERDIR/d/a $UPPERDIR/d/b
mkdir $MOUNTPOINT/d/a
ls -li $MOUNTPOINT/d

echo "# lower"
rm -rf $MOUNTPOINT/d
mkdir $LOWERDIR/d
mkdir $LOWERDIR/d/a
ls -li $MOUNTPOINT/d
mv $LOWERDIR/d/a $LOWERDIR/d/b
mkdir $MOUNTPOINT/d/a
ls -li $MOUNTPOINT/d
