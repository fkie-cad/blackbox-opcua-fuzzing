#!/usr/bin/env bash

apt-get update && apt-get install -y npm

curl -sL https://deb.nodesource.com/setup_10.x | bash -
apt-get install -y nodejs

npm install node-opcua --save

git clone https://github.com/node-opcua/node-opcua

cp targets/node-opc/target target

exit 0