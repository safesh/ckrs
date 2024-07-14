#!/bin/sh

usage () {
    echo "usage: $0 <path>"
    exit 1
}

! [ $# -ne 1 ] || usage

ssh-keygen -v -D "$1" -e
