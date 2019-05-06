#!/bin/bash
# test du circular directory structure check when moving directories
# directly in upper or lower layers

# Original issue: https://srcc.uservoice.com/admin/tickets/31976
# $ cd /merged
# $ mkdir d
# $ mkdir d/a
# $ ls -li d
# total 0
# 1152921504624858001 drwxr-xr-x 2 sthiell operator 6 May  5 20:37 a
# $ mv /upper/d/a /upper/d/b
# $ mkdir /upper/d/a
# $ mv /upper/d/b /upper/d/a/
# $ du -sh d
# du: WARNING: Circular directory structure.
# This almost certainly means that you have a corrupted file system.
# NOTIFY YOUR SYSTEM MANAGER.
# The following directory is part of the cycle:
#   ‘d/a/b’

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
mkdir $UPPERDIR/d/a
mv $UPPERDIR/d/b $UPPERDIR/d/a/
du -sh $MOUNTPOINT/d
ls -li $MOUNTPOINT/d

echo "# lower"
rm -rf $MOUNTPOINT/d
mkdir $LOWERDIR/d
mkdir $LOWERDIR/d/a
ls -li $MOUNTPOINT/d
mv $LOWERDIR/d/a $LOWERDIR/d/b
mkdir $LOWERDIR/d/a
mv $LOWERDIR/d/b $LOWERDIR/d/a/
du -sh $MOUNTPOINT/d
ls -li $MOUNTPOINT/d
