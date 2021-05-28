#!/usr/bin/env bash

apt-get update && apt-get install -y openjdk-8-jre wget unzip

wget https://github.com/digitalpetri/opc-ua-demo-server/releases/download/v0.2/milo-demo-server-linux.zip
unzip milo-demo-server-linux.zip
timeout 5 milo-demo-server/bin/milo-demo-server || true
sed -i 's/62541/4840/g' /root/.config/milodemoserver/server.json
sed -i 's/localhost:4840\//localhost:4840\/milo/g' /opt/app/parse/packet.py

ln -s /opt/app/milo-demo-server/bin/milo-demo-server /opt/app/target

exit 0