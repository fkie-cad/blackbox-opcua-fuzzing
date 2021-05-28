# Fuzz OPC UA implementations

This is a black box fuzzing solution targeting the OPC UA protocol.
The fuzzing is based on the mutational fuzzing engine [boofuzz](https://github.com/jtpereyda/boofuzz).

We contributed to boofuzz and provide a fork, that further supports json as crash format.
This allows for an automated collection of fuzzing results and makes the crash triage easier. 

## Process

To seamlessly support multiple target implementations and allow for scaling, the fuzzing takes place inside a container.
A simple python script is used to choose a target. The script then handles building the container and fuzzing the
target.
The process consists of the following steps:

0. Choose target implementation.
1. [Automated] Build container with target implementation and fuzzing tools.
2. [Automated] Run fuzzing on target implementation.
3. [Automated] Collect data from fuzzing and store crash information.
4. [Automated] Try to reproduce each crash.
5. [Automated] Transfer crash information, including reproducability, to host.
6. Review crash information, stored in json file.

So by using the container (powered by [docker](https://www.docker.com/)), most fuzzing steps are automated.

## Usage

The project includes an easy to use wrapper called `run_docker_fuzzing.py`.

```
$ python3 run_docker_fuzzing.py --help
usage: run_docker_fuzzing.py [-h] [-p PATH] {node-opc,open62541,python-opcua,dotnet,java}

Fuzz OPC UA

positional arguments:
  {node-opc,open62541,python-opcua,dotnet,java}
                        Target implementation

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  Path for output / results (Default: ./fuzzing_results)
```

**Requirements: The run_docker_fuzzing.py only depends on docker-py. Install with **`pip install docker`**.**

As of now, there are five supported OPC UA implementations (all are open source):

- [UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard)
- [open62541](https://github.com/open62541/open62541)
- [Eclipse Milo](https://projects.eclipse.org/projects/iot.milo)
- [python-opcua](https://github.com/FreeOpcUa/python-opcua)
- [node-opcua](https://github.com/node-opcua/node-opcua)

The complete result folder has a structure such as 

```
$ tree fuzzing_results 
fuzzing_results
├── boofuzz-crash-bin-2020-08-07T08-00-58
├── boofuzz-results
│   └── run-2020-08-07T08-00-58.db
└── crash_info_2020-08-07T08-00-58.json

1 directory, 3 files
```

where the `crash_info_*.json` file holds the comprehensive results.


## Replay crashes

The fuzzing toolchain incorporates a mechanism to replay crashes.
This mechanism is also provided as a standalone script called `reproduce_crashes.py`.
This script can replay or reproduce crashes based on three methods: Using the crash log from the blackbox fuzzing, given a single message as hexstring and given the id of a known crash.
Known crashes are kept in the `test_cases.json` file.
It lists crashes that have been produced during development of this toolchain.

To correctly reproduce the crashes, the script needs to know at which state the crashing message occurs.
E.g. a broken Hello message does not need any initialization, while a broken discovery service message usually needs a successful Hello/Acknowledgment and a OpenChannel handshake.
Furthermore all messages sent on an opened channel need to use the correct channel parameter.
To this point, the script infers the channel parameter from the previous paket and mutates the broken message to use them correctly.
This can be done since the fuzzing approach does not mutate the first 6 parameter of pakets on handshake level 2 or beyond.

The script has the following interface:

```
python3 reproduce_crashes.py --help 
usage: reproduce_crashes.py [-h] (-p PID | -t TARGET) (-m MESSAGE | -f FILE | -c CASE) [-d DEPTH]

optional arguments:
  -h, --help            show this help message and exit
  -p PID, --pid PID     PID to check if server is alive
  -t TARGET, --target TARGET
                        Target to run messages against
  -m MESSAGE, --message MESSAGE
                        Package to send as hexstring
  -f FILE, --file FILE  JSON crash log to collect messages from
  -c CASE, --case CASE  Replay known Testcase from test_cases.json. Options: [711, 713, 714, 844, 846, 7896]
  -d DEPTH, --depth DEPTH
                        Set Connection Level (0 - No Connection, 1 - Hello, 2 - Open Channel, 3 - Create Session)
```

The depth has to be given in combination with `--message`. The other two replay options (log, known case) known the correct depth from their data.
Independent of the replay method, the script does not provide a server.
The server can either be given as a file path with `--target` (note that this does not allow for comman line arguments) or if running as a process id with `--pid`.

The script does not have any external dependencies.

## Extend

You can add more fuzzing definitions in the `fuzzer/boofuzz_definition.py` file. The file currently includes definitions for:

- Hello
- OpenChannel
- CloseChannel
- FindServersRequest
- FindServersOnNetworkRequest
- GetEndpointsRequest
- RegisterServer2Request
- CreateSessionRequest
- ActivateSessionRequest

Some more helpful functions are included to e.g. parse channel parameter from previous requests and construct timestamps.

It is also possible to add more target implementations.
The steps to do that are listed [here](targets/README.md).

## Copyright

Fraunhofer FKIE 2020 - 2021
