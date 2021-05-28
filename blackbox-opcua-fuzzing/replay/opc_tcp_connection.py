import logging
import socket
import time

from parse.packet import (
    Hello, OpenChannelRequest, CreateSession, log_packet_data , parse_channel_parameter_from_open,
    parse_channel_parameter_from_create, update_packet_header
)
from replay.target import Target

HOST = 'localhost'
PORT = 4840


def send_message_with_handshake(message: bytes, pid: int, handshake_depth: int) -> bool:
    connection = create_tcp_connection()
    request_header = None

    if handshake_depth >= 1:
        logging.info('Connecting to Server: Hello')
        send_and_receive_message(connection, Hello())

        if handshake_depth >= 2:
            logging.info('Creating Secure Connection: OpenChannel')
            open_response = send_and_receive_message(connection, OpenChannelRequest())
            request_header = parse_channel_parameter_from_open(open_response)

            if handshake_depth >= 3:
                logging.info('Creating new Session: CreateSession')
                create_session_response = send_and_receive_message(connection, CreateSession(open_response))
                request_header = parse_channel_parameter_from_create(create_session_response)

    logging.info('Delivering payload')
    connection.send(update_packet_header(message, request_header))
    time.sleep(1)
    log_packet_data(receive_from_socket(connection))

    if not Target.is_alive(pid):
        logging.info('Payload Successful')
        return True

    connection.close()
    return False


def create_tcp_connection() -> socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((HOST, PORT))
    connection.settimeout(2)
    return connection


def receive_from_socket(socket_: socket.socket) -> bytes:
    try:
        return socket_.recv(512)
    except socket.timeout:
        logging.warning('Socket timeout while trying to receive response')
        return b''


def send_and_receive_message(socket_: socket.socket, message) -> bytes:
    logging.debug(f'Sending:\n{str(message)}')
    socket_.send(bytes(message))

    time.sleep(1)

    response = receive_from_socket(socket_)
    log_packet_data(response)

    return response
