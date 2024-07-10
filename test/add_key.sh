#!/bin/sh

usage () {
    echo "usage: $0 <path>"
    exit 1
}

! [ $# -ne 1 ] || usage

ssh-keygen -t ed25519 -C "test" -D "$1" -v
