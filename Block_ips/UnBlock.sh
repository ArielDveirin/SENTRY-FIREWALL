#!/bin/bash

iptables -D INPUT -m set --match-set $1 src -j DROP
sleep .5
ipset x $1