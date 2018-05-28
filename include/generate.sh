#!/bin/sh
./amalgamate roc.amalgamate roc.h
./amalgamate roc_interface.amalgamate roc_interface.h
cp ./roc.h ./../example/
