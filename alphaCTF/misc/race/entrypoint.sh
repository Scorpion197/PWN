#!/bin/bash

socat -dd -T60 TCP-LISTEN:9010,reuseaddr,fork,su=race EXEC:/home/race/chall,stderr