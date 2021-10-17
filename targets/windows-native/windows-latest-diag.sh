#!/bin/sh

# curl -L https://www.libsdl.org/release/SDL2-devel-2.0.14-mingw.tar.gz | tar -xz

# cp -r SDL2-2.0.14/x86_64-w64-mingw32/* /mingw64/

df -hi

env

hostname

ipconfig

ps1 -Command "get-netfirewallrule -all"
ps1 -Command "get-netfirewallrule -policystore configurableservicestore -all"
