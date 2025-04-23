#!/bin/bash

docker build -t vpnguin-build .
docker run --rm -v $PWD:/out -w /out vpnguin-build cp /app/vpn.tar.gz /out
