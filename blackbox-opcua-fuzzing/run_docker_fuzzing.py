import argparse
import os
import random
import sys
from pathlib import Path
from typing import Union

import docker
from docker.errors import ImageNotFound

DEFAULT_DIR = './fuzzing_results'
BASE_TAG = 'opc-fuzzer/baseimage'
TARGETS = ['node-opc', 'open62541', 'python-opcua', 'dotnet', 'java']
SETUP_SH = '#!/usr/bin/env bash\n\ntargets/{target}/install.sh\n\nexit 0\n'


class ChangeDirectory:
    def __init__(self, target_directory: Union[str, Path]):
        self._current_working_dir = None
        self._target_directory = str(target_directory)

    def __enter__(self):
        self._current_working_dir = os.getcwd()
        os.chdir(self._target_directory)

    def __exit__(self, *args):
        os.chdir(self._current_working_dir)


def setup_argparse():
    parser = argparse.ArgumentParser(description='Fuzz OPC UA')
    parser.add_argument(
        '-p', '--path', type=Path, default=Path(DEFAULT_DIR), help=f'Path for output / results (Default: {DEFAULT_DIR})'
    )
    parser.add_argument(
        'target', choices=TARGETS, type=str, help='Target implementation'
    )
    return parser.parse_args()


def run_container(target: str, local_path: str):
    client = docker.from_env()

    try:
        client.images.get(BASE_TAG)
    except ImageNotFound:
        print('[INFO] First stage container missing. Building it now ...')
        client.images.build(path='.', tag=BASE_TAG, dockerfile='Dockerfile.pre')

    unique_tag = f'opc-fuzzer/{target}-{random.getrandbits(32)}'

    print('[INFO] Building container.')
    client.images.build(path='.', tag=unique_tag)

    print('[INFO] Start fuzzing.')
    client.containers.run(
        image=unique_tag,
        volumes={local_path: {'bind': '/tmp/results/', 'mode': 'rw'}},
        remove=True
    )
    print(f'[INFO] Finished fuzzing. Results can be found in {local_path}.')


def setup_target(target: str):
    Path('setup_target_auto.sh').write_text(SETUP_SH.format(target=target))
    os.chmod('setup_target_auto.sh', 0o755)


def start_fuzzing(target, local_path):
    with ChangeDirectory(Path(__file__).parent):
        setup_target(target)
        run_container(target, local_path)


def main():
    arguments = setup_argparse()

    if arguments.path.exists() and not arguments.path.is_dir():
        print('[ERROR] Target path is not a directory. Exiting ...')
        return 1
    if arguments.path.exists() and len(list(arguments.path.iterdir())) > 0:
        print('[ERROR] Target path not empty. Exiting ...')
        return 2

    os.makedirs(str(arguments.path.absolute()), exist_ok=True)

    try:
        start_fuzzing(arguments.target, str(arguments.path.absolute()))
    except Exception as exception:
        print(f'[ERROR] Unexpected error. Exiting ...\n\n{exception}\n')
        return 255

    return 0


if __name__ == '__main__':
    sys.exit(main())
