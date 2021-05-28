import json
import logging
import os
import re
import shutil
import sqlite3
from binascii import hexlify
from pathlib import Path
from typing import List


def merge_boofuzz_data(boofuzz_log: dict, session_id: str) -> List[dict]:
    fails, stderr_json = _prepare_source_data(boofuzz_log, session_id)

    fail_infos = []
    for fail in fails:
        try:
            stderr = stderr_json.pop(0)
        except (IndexError, KeyError):
            logging.error(f'Could not get stderr from fail {str(fail)}')
            stderr = None

        case_meta = None
        for case_data in boofuzz_log['cases']:
            if case_data['case'] == fail:
                case_meta = case_data
                break
        if not case_meta:
            logging.error(f'Could not get meta data for test case {fail}')
            case_meta = {'error': 'Unable to get meta for this test case'}

        fail_info = {
            'case_meta': case_meta,
            'case_steps': [],
            'stderr': stderr
        }

        for log_step in boofuzz_log['logs']:
            if log_step['case'] == fail:
                fail_info['case_steps'].append(log_step)

        fail_infos.append(fail_info)

    return fail_infos


def _prepare_source_data(boofuzz_log: dict, session_id: str):
    stderr_path = Path(f'boofuzz-crash-bin-{session_id}')
    stderr_log = f'[\n{stderr_path.read_text()[:-2]}\n]' if stderr_path.exists() else '{}'
    stderr_json = json.loads(stderr_log)

    fails = [log_step['case'] for log_step in boofuzz_log['logs'] if log_step['type'] == 'fail']

    return fails, stderr_json


def store_crash_information(session_id: str, crashes: List[dict], target_folder: str = '/tmp/results'):
    os.makedirs(str(Path(target_folder) / 'boofuzz-results'), exist_ok=True)

    Path(target_folder, f'crash_info_{session_id}.json').write_text(json.dumps(crashes, indent=2))

    try:
        shutil.copy(
            Path(f'boofuzz-crash-bin-{session_id}'),
            Path(target_folder) / f'boofuzz-crash-bin-{session_id}'
        )
    except FileNotFoundError:
        logging.error(f'Was not able to find the file boofuzz-crash-bin-{session_id}.')

    try:
        shutil.copy(
            Path('boofuzz-results') / f'run-{session_id}.db',
            Path(target_folder) / 'boofuzz-results' / f'run-{session_id}.db'
        )
    except FileNotFoundError:
        logging.error(
            f'Was not able to find the file {str(Path("boofuzz-results", f"run-{session_id}.db"))}.'
        )


def parse_crash_data(crash: dict):
    # Case name has looks like 'Hello->OpenChannel->GetEndpoints.return diagnostics.348'
    crash_depth = len(list(re.findall(r'->', crash['case_meta']['name'])))

    sent_data = [step['data'] for step in crash['case_steps'] if step['type'] == 'send']
    if not sent_data:
        raise RuntimeError('No sent data found. Aborting replay.')

    if len(sent_data) != crash_depth + 1:
        logging.warning(
            f'Fuzzed node had depth {crash_depth + 1}, but {len(sent_data)} packets were sent.'
            f'Continuing replay with last sent packet and new depth {len(sent_data) - 1}.'
        )
        crash_depth = len(sent_data) - 1

    return crash_depth, sent_data[crash_depth]


def convert_boofuzz_sqlite_to_dict(session_id: str):
    database = Path('boofuzz-results', f'run-{session_id}.db')

    connection = sqlite3.connect(str(database))
    cursor = connection.cursor()

    cursor.execute('select name, number, timestamp from cases')
    cases = [
        {
            'case': number,
            'name': name,
            'timestamp': timestamp.strip('[]')
        }
        for name, number, timestamp in cursor.fetchall()
    ]

    cursor.execute('select test_case_index, type, description, data, timestamp, is_truncated from steps')
    logs = [
        {
            'case': test_case_index,
            'type': message_type,
            'message': description,
            'data': hexlify(data).decode(),
            'truncated': is_truncated,
            'timestamp': timestamp,
        }
        for test_case_index, message_type, description, data, timestamp, is_truncated in cursor.fetchall()
    ]

    return {
        'cases': cases,
        'logs': logs
    }
