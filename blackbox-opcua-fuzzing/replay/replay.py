import json
import logging
import time
from pathlib import Path
from typing import Optional

from parse.crash import parse_crash_data
from replay.opc_tcp_connection import send_message_with_handshake
from parse.packet import log_packet_data
from replay.target import Target


def replay_crash_log(crash_log: Path, pid: Optional[int] = None, target: Optional[str] = None) -> None:
    crashes = json.loads(crash_log.read_text())
    for crash in crashes:
        print(f'[INFO] Replaying {crash["case_meta"]["name"]}')
        crash_depth, message = parse_crash_data(crash)
        crash['reproducible'] = replay_message(
            message=message,
            depth=crash_depth,
            pid=pid,
            target=target
        )
    crash_log.write_text(json.dumps(crashes, indent=2))


def replay_known_case(case_id: int, pid: Optional[int] = None, target: Optional[str] = None) -> None:
    logging.info(f'Running Test Case {case_id}')
    for case in json.loads(Path('test_cases.json').read_text()):
        if case['case']['number'] == int(case):
            replay_message(
                message=case['case']['message'],
                depth=case['case']['depth'],
                pid=pid,
                target=target
            )
            break


def replay_message(message: str, depth: int, pid: Optional[int] = None, target: Optional[str] = None) -> bool:
    server = None

    payload = bytes.fromhex(message)
    try:
        log_packet_data(payload)
    except RuntimeError:
        logging.debug('Could not parse sent message.')
    logging.debug(payload)

    if not pid:
        try:
            server = Target(target)
            pid = server.pid
        except (ChildProcessError, ConnectionAbortedError):
            raise RuntimeError('There is a problem spawning the Server, aborting')
    else:
        pid = int(pid)
    if not Target.is_alive(pid):
        raise RuntimeError(f'PID {pid} does not exist. Stopping...')

    try:
        poc_success = send_message_with_handshake(payload, pid, depth)
    finally:
        if server:
            server.terminate()

    time.sleep(1)  # Prevent braking pipes and stuff
    return poc_success
