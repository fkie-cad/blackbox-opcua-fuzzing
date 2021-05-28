#!/usr/bin/env bash

pip3 install virtualenv

git clone https://github.com/FreeOpcUa/python-opcua.git
(
  cd python-opcua || return

  virtualenv .env

  .env/bin/pip install .
  .env/bin/pip install cryptography
)

cp targets/python-opcua/target target

exit 0