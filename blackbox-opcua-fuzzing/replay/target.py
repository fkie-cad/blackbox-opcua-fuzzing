import logging
import psutil
import subprocess
import time
import socket
import sys


class Target:
    proc = None
    pid = None

    def __init__(self, target_command):
        if not self.port_available():
            logging.error('Port 4840 is already in use')
            raise ConnectionAbortedError

        logging.info('Creating Target')

        self.proc = subprocess.Popen(
            target_command.split(),
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            shell=False
        )

        self.pid = self.proc.pid

        self.process_info = psutil.Process(pid=self.pid)

        time.sleep(2)

        if not self.proc.poll():
            logging.info('Target created with PID: {}'.format(self.pid))
        else:
            self.proc.kill()
            self.proc.wait()
            raise ChildProcessError

    def get_output(self):
        try:
            self.proc.poll()
            sys.stdout.flush()
            sys.stderr.flush()
            stdout, stderr = self.proc.communicate(timeout=5)
            logging.info(f'STDOUT: {stdout}')
            logging.info(f'STDERR: {stderr}')
        except subprocess.TimeoutExpired:
            return None

    @staticmethod
    def port_available():
        connector = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return connector.connect_ex(('localhost', 4840))

    @staticmethod
    def is_alive(pid):
        alive = psutil.pid_exists(pid) and not Target.port_available()
        logging.info(f'PID {pid} alive: {alive}')
        return alive

    def terminate(self):
        terminate_children(self.process_info)
        try:
            self.proc.terminate()
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            logging.debug('Timeout. Attempting to terminate server ...')
            self.proc.kill()
            self.proc.wait(10)
        logging.info(f'Server with PID {self.pid} has been terminated')


def terminate_children(process: psutil.Process) -> None:
    for child in process.children():
        terminate_children(child)
        child.kill()
