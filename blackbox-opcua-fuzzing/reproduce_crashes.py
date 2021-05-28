import json
import logging
import sys
from argparse import ArgumentParser
from pathlib import Path

from replay.replay import replay_message, replay_crash_log, replay_known_case


def create_logger():
    fmt = '[%(asctime)s][%(module)s][%(levelname)s]: %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=fmt, datefmt=datefmt, level=logging.INFO)


def get_arguments():
    parser = ArgumentParser()

    cases = [case['case']['number'] for case in json.loads(Path('test_cases.json').read_text())]

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-p', '--pid', help='PID to check if server is alive', default=None)
    target_group.add_argument('-t', '--target', help='Target to run messages against', type=str, default=None)

    message_group = parser.add_mutually_exclusive_group(required=True)
    message_group.add_argument('-m', '--message', type=str, help='Package to send as hexstring')
    message_group.add_argument('-f', '--file', type=Path, help='JSON crash log to collect messages from')
    message_group.add_argument('-c', '--case', type=int, help=f'Replay known Testcase from test_cases.json. Options: {cases}')

    parser.add_argument(
        '-d',
        '--depth',
        type=int,
        help='Set Connection Level (0 - No Connection, 1 - Hello, 2 - Open Channel, 3 - Create Session)',
        default=0
    )

    return parser.parse_args()


def main():
    arguments = get_arguments()
    create_logger()

    if arguments.message:
        replay_message(
            message=arguments.message,
            depth=arguments.depth,
            pid=arguments.pid,
            target=arguments.target
        )
    elif arguments.file:
        replay_crash_log(
            crash_log=arguments.file,
            pid=arguments.pid,
            target=arguments.target)
    else:
        replay_known_case(
            case_id=arguments.case,
            pid=arguments.pid,
            target=arguments.target
        )

    return 0


if __name__ == '__main__':
    sys.exit(main())
