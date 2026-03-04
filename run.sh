#! /bin/bash

cargo build
cp target/debug/wifislam .

sudo ./wifislam "$@"