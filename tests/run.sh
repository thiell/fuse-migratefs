#!/bin/bash

set -e

for t in test_*.sh; do
    echo "Running: $t"
    ./$t
done
