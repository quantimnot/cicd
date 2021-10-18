#!/bin/sh

df -hi

env

hostname

ipconfig

ps1 -Command "get-netfirewallrule -all"
ps1 -Command "get-netfirewallrule -policystore configurableservicestore -all"
