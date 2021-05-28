#!/usr/bin/env python3

import logging
import os
import sys
from argparse import ArgumentParser
from multiprocessing import Process
from pathlib import Path
from subprocess import run, PIPE
from time import sleep

from boofuzz import helpers
from boofuzz.constants import DEFAULT_PROCMON_PORT
from boofuzz.utils.debugger_thread_simple import DebuggerThreadSimple
from boofuzz.utils.process_monitor_pedrpc_server import ProcessMonitorPedrpcServer

from fuzzer.boofuzz_definition import fuzz_opcua
from replay.replay import replay_crash_log


def create_logger():
    fmt = '[%(asctime)s][%(module)s][%(levelname)s]: %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=fmt, datefmt=datefmt, level=logging.INFO)


def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument(
        '--reproduce', action='store_true', default=True, help='Try to reproduce found crashes'
    )
    parser.add_argument(
        '--target', type=Path, default=Path(__file__).parent / 'target', help='Path to server executable'
    )
    return parser.parse_args()


def process_monitor():
    helpers.mkdir_safe('coredumps')

    with ProcessMonitorPedrpcServer(
        host='0.0.0.0',
        port=DEFAULT_PROCMON_PORT,
        crash_filename='boofuzz-crash-bin',
        debugger_class=DebuggerThreadSimple,
        coredump_dir='coredumps',
        crash_format_json=True
    ) as monitor:
        monitor.serve_forever()


def run_fuzzing(target_path: Path):
    monitor = Process(target=process_monitor)
    monitor.start()

    session_id = fuzz_opcua(target_path)

    monitor.terminate()
    monitor.join()

    return session_id


def kill_still_running_server():
    sleep(1)
    lsof_result = run(
        'lsof -n -i :4840 | awk \'/LISTEN/ {print $2}\'| head -n 1', shell=True, stdout=PIPE
    ).stdout.decode()
    try:
        os.kill(int(lsof_result), 9)
        logging.info(f'Killed {int(lsof_result)}. Sleeping for a second.')
        sleep(1)
    except ValueError:
        pass


def main():
    arguments = parse_arguments()
    create_logger()

    session_id = run_fuzzing(arguments.target)

    if arguments.reproduce:
        kill_still_running_server()

        replay_crash_log(
            target='/opt/app/target',
            crash_log=Path(f'/tmp/results/crash_info_{session_id}.json'),
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
