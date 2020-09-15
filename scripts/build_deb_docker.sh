#!/bin/bash

VERSION="$1"
RELEASE="$2"

. ~/.cargo/env

cargo build --release

printf "Authentication service using actix\n" > description-pak
checkinstall --pkgversion ${VERSION} --pkgrelease ${RELEASE} -y
