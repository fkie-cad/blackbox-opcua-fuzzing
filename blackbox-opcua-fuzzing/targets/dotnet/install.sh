#!/usr/bin/env bash

# Add dotnet mirror
apt-get update
apt-get install -y wget git
wget https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb

# Install dotnet SDK
apt-get update
apt-get install -y dotnet-sdk-3.1

# Patch port in config
git clone https://github.com/OPCFoundation/UA-.NETStandard.git
(
  cd "UA-.NETStandard/Applications/ConsoleReferenceServer" || return
  sed 's/opc.tcp:\/\/localhost:62541/opc.tcp:\/\/localhost:4840/' Quickstarts.ReferenceServer.Config.xml > tmpfile
  mv tmpfile Quickstarts.ReferenceServer.Config.xml
)

cp targets/dotnet/target target

exit 0