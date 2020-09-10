#!/bin/bash
gcc -pthread -lcurl -lcrypto attestor.c -ltspi -o attestor
