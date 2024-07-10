#!/bin/sh

usage () {
    echo "usage: $0 <path>"
    exit 1
}

! [ $# -ne 1 ] || usage

ssh-keygen -D "$1" -e
