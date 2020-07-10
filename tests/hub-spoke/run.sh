#!/bin/sh
set -eu

xfce4-terminal -e 'python ../../src/runner.py --ip 127.0.1.10 --update 30 --startup hub.txt' -T '127.0.1.10'

for i in $(seq 1 5) ; do
    xfce4-terminal -e "python ../../src/runner.py --ip 127.0.1.$i --update 30 --startup spoke.txt" -T "127.0.1.$i"
done
