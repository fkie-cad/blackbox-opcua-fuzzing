# OPC UA Fuzzing targets

This directory holds the target setup for the blackbox fuzzing.
To work with the toolchain, a new implementation needs it's own subdirectory.
The subdirectory then needs to hold a shell script `install.sh` with the executable bit set.
The shell script needs to set up the docker container with everything needed to run an opcua server on port 4840.

The server has to be an executable (i.e. elf file or script with shebang an x bit) and it has to be stored at `/opt/app/target`.
This can be done by copying or linking an executable.
If the file or script needs parameters or has to be executed from another working directory you can use a shell wrapper.
This for example is the target for the node implementation:

```bash
#!/usr/bin/env bash

/usr/bin/node /opt/app/node-opcua/packages/node-opcua-samples/bin/simple_server.js -a localhost -p 4840

exit 0
```
