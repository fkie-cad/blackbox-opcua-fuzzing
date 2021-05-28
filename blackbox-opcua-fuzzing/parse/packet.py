import binascii
import logging
import struct
from calendar import timegm
from datetime import datetime
from datetime import timedelta
from typing import Tuple

EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
OPCUA_EMPTY_BYTESTRING = b'\x00\x00\x00\x00'
OPCUA_NULL_STRING = b'\xFF\xFF\xFF\xFF'
ENDPOINT_STRING = 'opc.tcp://localhost:4840/'.encode('utf-8')


def log_packet_data(message: bytes) -> None:
    if not message or len(message) < 8:
        return
    if struct.unpack('<c', message[3:4])[0].decode(errors='ignore') == 'C':
        logging.warning('Encountered an intermediate chunk. This is not supported at this point.')
        return

    message_header, message_size = message[:3], struct.unpack('<i', message[4:8])[0]
    try:
        if message_header == b'ACK':
            log_acknowledgment(message, message_size)
        if message_header == b'ERR':
            log_error(message, message_size)
        if message_header == b'OPN':
            log_open_channel_response(message)
    except (struct.error, TypeError):
        logging.warning(f'Failed parsing {message_header} message:\n{binascii.b2a_hex(message)}')


def log_acknowledgment(message, message_size):
    protocol_version = struct.unpack('<i', message[8:12])[0]
    receive_buffer_size = struct.unpack('<i', message[12:16])[0]
    send_buffer_size = struct.unpack('<i', message[16:20])[0]
    max_message_size = struct.unpack('<i', message[20:24])[0]
    max_chunk_count = struct.unpack('<i', message[24:28])[0]

    logging.debug(
        'Acknowledge Message:\n'
        'MessageType: ACK\n'
        f'MessageSize: {message_size}\n'
        f'ProtocolVersion: {protocol_version}\n'
        f'ReceiveBufferSize: {receive_buffer_size}\n'
        f'SendBufferSize: {send_buffer_size}\n'
        f'MaxMessageSize: {max_message_size}\n'
        f'MaxChunkCount: {max_chunk_count}\n'
    )


def log_error(message, message_size):
    error = struct.unpack('<i', message[8:12])[0]
    reason = message[12:message_size]

    logging.debug(
        'Error Message:\n'
        'MessageType: ERR\n'
        f'Error: {error}\n'
        f'Reason: {reason}\n'
    )


def log_open_channel_response(message):
    is_final = struct.unpack('<c', message[3:4])[0]
    secure_channel_id = struct.unpack('<i', message[8:12])[0]
    security_policy_uri_length = struct.unpack('<i', message[12:16])[0]
    index = security_policy_uri_length + 16
    security_policy_uri = message[16:index]
    security_certificate_length = struct.unpack('<i', message[index:index+4])[0]
    index += 4
    if security_certificate_length == -1:
        security_certificate_length = 0
    security_certificate = message[index:index + security_certificate_length]
    index += security_certificate_length
    receiver_certificate_thumbprint_length = struct.unpack('<i', message[index:index+4])[0]
    index += 4
    if receiver_certificate_thumbprint_length == -1:
        receiver_certificate_thumbprint_length = 0
    receiver_certificate_thumbprint = message[index:index + receiver_certificate_thumbprint_length]
    index += receiver_certificate_thumbprint_length
    sequence_number = bytes_to_integer(message[index:index + 4])
    index += 4
    request_id = bytes_to_integer(message[index:index + 4])
    index += 4
    type_id, node_size = parse_node(message[index:])
    index += node_size
    timestamp = parse_timestamp(message[index:index + 8])
    index += 8
    request_handle = bytes_to_integer(message[index:index + 4])
    index += 4
    service_result = binascii.b2a_hex(message[index:index + 4])
    index += 4
    service_diagnostics = struct.unpack('b', message[index:index + 1])[0]
    index += 1
    string_table = bytes_to_integer(message[index:index + 4])
    index += 4
    additional_header, node_size = parse_node(message[index:])
    index += node_size + 1  # TypeID + One byte encoding mask
    server_protocol_version = bytes_to_integer(message[index:index + 4])
    index += 4
    channel_id = bytes_to_integer(message[index:index + 4])
    index += 4
    token_id = bytes_to_integer(message[index:index + 4])
    index += 4
    created_at = parse_timestamp(message[index:index + 8])
    index += 8
    revised_lifetime = bytes_to_integer(message[index:index + 4])
    index += 4
    server_nonce = bytes_to_integer(message[index:index + 4])

    logging.debug(
        f'OpenChannelResponse\n'
        f'MessageType: "OPN"\n'
        f'ChunkType: {is_final}\n'
        f'SecureChannelId: {secure_channel_id}\n'
        f'SecurityPolicyUri: {security_policy_uri}\n'
        f'SecurityCertificate: {security_certificate}\n'
        f'ReceiverCertificateThumbprint: {receiver_certificate_thumbprint}\n'
        f'SequenceNumber: {sequence_number}\n'
        f'RequestId: {request_id}\n'
        f'TypeID: {type_id}\n'
        f'Timestamp: {timestamp}\n'
        f'RequestHandle: {request_handle}\n'
        f'ServiceResult: {service_result}\n'
        f'ServiceDiagnostics: {service_diagnostics}\n'
        f'StringTable: {string_table}\n'
        f'AdditionalHeader: {additional_header}\n'
        f'ServerProtocolVersion: {server_protocol_version}\n'
        f'ChannelID: {channel_id}\n'
        f'TokenID: {token_id}\n'
        f'CreatedAt: {created_at}\n'
        f'RevisedLiftime: {revised_lifetime}\n'
        f'ServerNonce: {server_nonce}\n'
    )


def parse_node(message):
    encoding = struct.unpack('b', message[0:1])[0]
    if encoding == 0:
        identifier = struct.unpack('b', message[1:2])[0]
        return identifier, 2
    if encoding == 1:
        identifier = struct.unpack('h', message[2:4])[0]
        return identifier, 4


def parse_timestamp(message):
    raw_time = struct.unpack('q', message)[0]
    try:
        return datetime(1601, 1, 1) + timedelta(seconds=raw_time / 10000000)
    except OverflowError:
        logging.debug('Bad offset for timestamp. Defaulting to linux epoch.')
        return datetime(1970, 1, 1)


def get_weird_opc_timestamp():
    now = datetime.now()
    ft = EPOCH_AS_FILETIME + (timegm(now.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (now.microsecond * 10)


def integer_to_bytes(number, is_long=False, is_short=False, is_double=False):
    if is_long:
        return struct.pack('l', number)
    if is_short:
        return struct.pack('H', number)
    if is_double:
        return struct.pack('d', number)
    return struct.pack('i', number)


def bytes_to_integer(_bytes, is_long=False, is_short=False, is_double=False):
    if is_long:
        return struct.unpack('l', _bytes)[0]
    if is_short:
        return struct.unpack('H', _bytes)[0]
    if is_double:
        return struct.unpack('d', _bytes)[0]
    return struct.unpack('i', _bytes)[0]


def parse_channel_parameter_from_open(previous_response: bytes) -> Tuple[int, int, int, int]:
    '''
    Parse channel parameter from previous response. The problem is that these values are not stored at a fixed
    offset, but due to variable length fields the offsets have to be calculated.

    Example from wireshark trace:
        ..  8  9 10 11 12 13 14 15 16 17 ..  71 72 73 74 75 76 77 78 79 80 ..  06 07 08 09 10 11 12 13 14 15 16 ..
        .. 01 00 00 00 2f 00 00 00 68 74 ..  ff 01 00 00 00 01 00 00 00 01 ..  00 00 00 00 00 00 01 00 00 00 01 ..
           channel_id | policy len                seq_num  | req_id                  sec_ch_id  | token_id
                1          47                        1         1                         0           1

    Request Header:  8 + 4 + 4 + 1 + 4 + 3 = 24 Bytes
    Addtional fields before and after request header take 8 + 4 and 4 bytes, so total offset after request id is 40
    '''
    _, policy_len = struct.unpack('ii', previous_response[8:16])

    sequence_offset = policy_len + 24
    sequence_number, request_id = struct.unpack('ii', previous_response[sequence_offset:sequence_offset + 8])

    token_offset = sequence_offset + 40
    sec_channel_id, token_id = struct.unpack('ii', previous_response[token_offset:token_offset + 8])

    return sec_channel_id, token_id, sequence_number + 1, request_id + 1


def parse_channel_parameter_from_create(previous_response: bytes) -> Tuple[int, int, int, int]:
    sec_channel_id, token_id, sequence_number, request_id = struct.unpack('iiii', previous_response[8:24])
    return sec_channel_id, token_id, sequence_number + 1, request_id + 1


def update_packet_header(packet: bytes, request_header) -> bytes:
    if request_header:
        secure_channel_id, token_id, sequence_number, request_id = request_header
        new_header = struct.pack('i', secure_channel_id) + struct.pack('i', token_id) + struct.pack('i', sequence_number) + struct.pack('i', request_id)
        packet = packet[0:8] + new_header + packet[24:]
    return packet


class Hello:
    def __init__(self):
        self.message_type = b'HEL'
        self.chunk_type = b'F'
        self.message_size = integer_to_bytes(32 + len(ENDPOINT_STRING))
        self.protocol_version = integer_to_bytes(0)
        self.receive_buffer_size = integer_to_bytes(65536)
        self.send_buffer_size = integer_to_bytes(65536)
        self.max_message_size = integer_to_bytes(0)
        self.max_chunk_count = integer_to_bytes(0)
        self.endpoint_url = integer_to_bytes(len(ENDPOINT_STRING)) + ENDPOINT_STRING

    def __bytes__(self):
        return (
            self.message_type + self.chunk_type + self.message_size + self.protocol_version + self.receive_buffer_size +
            self.send_buffer_size + self.max_message_size + self.max_chunk_count + self.endpoint_url
        )

    def __str__(self):
        return (
            'Hello Message:\n'
            f'MessageType: {self.message_type}\n'
            f'ChunkType: {self.chunk_type}\n'
            f'MessageSize: {bytes_to_integer(self.message_size)}\n'
            f'ProtocolVersion: {bytes_to_integer(self.protocol_version)}\n'
            f'ReceiveBufferSize: {bytes_to_integer(self.receive_buffer_size)}\n'
            f'SendBufferSize: {bytes_to_integer(self.send_buffer_size)}\n'
            f'MaxMessageSize: {bytes_to_integer(self.max_message_size)}\n'
            f'MaxChunkCount: {bytes_to_integer(self.max_chunk_count)}\n'
            f'EndpointUrl: {self.endpoint_url[2:]}\n'
        )


class OpenChannelRequest:
    def __init__(self):
        # Header
        self.message_type = b'OPN'
        self.chunk_type = b'F'
        self.message_size = integer_to_bytes(132)
        self.secure_channel_id = integer_to_bytes(0)
        self.security_policy_uri = integer_to_bytes(47) + 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')
        self.sender_certificate = OPCUA_NULL_STRING
        self.receiver_certificate_thumbprint = OPCUA_NULL_STRING
        self.sequence_number = integer_to_bytes(1)
        self.request_id = integer_to_bytes(1)

        self.type_id = b'\x01\x00\xbe\x01'

        # RequestHeader
        self.authentication_token = b'\x00\x00'
        self.timestamp = integer_to_bytes(get_weird_opc_timestamp(), True)
        self.request_handle = integer_to_bytes(1)
        self.return_diagnostics = integer_to_bytes(0)
        self.audit_entry = OPCUA_NULL_STRING
        self.timeout_hint = integer_to_bytes(1000)
        self.additional_header = b'\x00\x00\x00'

        # Message
        self.client_protocol_version = integer_to_bytes(0)
        self.request_type = integer_to_bytes(0)
        self.security_mode = integer_to_bytes(1)
        self.client_nonce = OPCUA_EMPTY_BYTESTRING
        self.requested_lifetime = integer_to_bytes(3600000)

    def __bytes__(self):
        return (
            self.message_type + self.chunk_type + self.message_size + self.secure_channel_id +
            self.security_policy_uri + self.sender_certificate + self.receiver_certificate_thumbprint +
            self.sequence_number + self.request_id + self.type_id + self.authentication_token + self.timestamp +
            self.request_handle + self.return_diagnostics + self.audit_entry + self.timeout_hint +
            self.additional_header + self.client_protocol_version + self.request_type + self.security_mode +
            self.client_nonce + self.requested_lifetime
        )

    def __str__(self):
        return (
            f'OpenChannelRequest\n'
            f'MessageType: OPN\n'
            f'ChunkType: {self.chunk_type}\n'
            f'MessageSize: {bytes_to_integer(self.message_size)}\n'
            f'SecureChannelId: {bytes_to_integer(self.secure_channel_id)}\n'
            f'SecurityPolicyUri: {self.security_policy_uri[4:]}\n'
            f'SenderCertificate: {bytes_to_integer(self.sender_certificate)}\n'
            f'ReceiverCertificateThumbprint: {bytes_to_integer(self.receiver_certificate_thumbprint)}\n'
            f'SequenceNumber: {bytes_to_integer(self.sequence_number)}\n'
            f'RequestId: {bytes_to_integer(self.request_id)}\n'
            f'TypeID: {parse_node(self.type_id)[0]}\n'
            f'AuthenticationToken: {self.authentication_token}\n'
            f'Timestamp: {parse_timestamp(self.timestamp)}\n'
            f'RequestHandle: {bytes_to_integer(self.request_handle)}\n'
            f'ReturnDiagnostics: {bytes_to_integer(self.return_diagnostics)}\n'
            f'AuditEntry: {bytes_to_integer(self.audit_entry)}\n'
            f'TimeoutHint: {bytes_to_integer(self.timeout_hint)}\n'
            f'ExtensionHeader: {self.additional_header}\n'
            f'ClientProtocolVersion: {bytes_to_integer(self.client_protocol_version)}\n'
            f'RequestType: {bytes_to_integer(self.request_type)}\n'
            f'SecurityMode: {bytes_to_integer(self.security_mode)}\n'
            f'ClientNonce: {self.client_nonce}\n'
            f'RequestedLifetime: {bytes_to_integer(self.requested_lifetime)}\n'
        )


class CreateSession:
    def __init__(self, previous_response=None):
        if previous_response:
            sec_channel_id, token_id, seq_num, req_id = parse_channel_parameter_from_open(previous_response)
        else:
            sec_channel_id, token_id, seq_num, req_id = 0, 4, 2, 2
        # Header
        self.message_type = b'MSG'

        self.chunk_type = b'F'
        self.message_size = integer_to_bytes(142 + len(ENDPOINT_STRING))
        # Security
        self.secure_channel_id = integer_to_bytes(sec_channel_id)
        self.secure_token_id = integer_to_bytes(token_id)
        self.secure_sequence_number = integer_to_bytes(seq_num)
        self.secure_request_id = integer_to_bytes(req_id)

        self.type_id = b'\x01\x00' + integer_to_bytes(461, is_short=True)

        # Request Header
        self.authentication_token = integer_to_bytes(0, is_short=True)
        self.timestamp = integer_to_bytes(get_weird_opc_timestamp(), True)
        self.request_handle = integer_to_bytes(1)
        self.return_diagnostics = integer_to_bytes(0)
        self.audit_entry = OPCUA_NULL_STRING
        self.timeout_hint = integer_to_bytes(1000)
        self.additional_header = b'\x00\x00\x00'

        self.application_uri = integer_to_bytes(28) + 'urn:unconfigured:application'.encode('utf-8')
        self.product_uri = OPCUA_NULL_STRING
        self.application_name = b'\x00'
        self.application_type = integer_to_bytes(1)
        self.gateway_server_uri = OPCUA_NULL_STRING
        self.discovery_profile_uri = OPCUA_NULL_STRING
        self.discorvery_urls = OPCUA_NULL_STRING

        # Create Session Parameter
        self.server_uri = OPCUA_EMPTY_BYTESTRING
        self.endpoint_url = integer_to_bytes(len(ENDPOINT_STRING)) + ENDPOINT_STRING
        self.session_name = OPCUA_NULL_STRING
        self.client_nonce = OPCUA_NULL_STRING
        self.client_certificate = OPCUA_NULL_STRING
        self.requested_session_timeout = integer_to_bytes(1200000.0, is_double=True)
        self.max_response_message_size = integer_to_bytes(2147483647)

    def __bytes__(self):
        return (
            self.message_type + self.chunk_type + self.message_size + self.secure_channel_id +
            self.secure_token_id + self.secure_sequence_number + self.secure_request_id +
            self.type_id + self.authentication_token + self.timestamp +
            self.request_handle + self.return_diagnostics + self.audit_entry +
            self.timeout_hint + self.additional_header + self.application_uri +
            self.product_uri + self.application_name + self.application_type +
            self.gateway_server_uri + self.discovery_profile_uri +
            self.discorvery_urls + self.server_uri + self.endpoint_url +
            self.session_name + self.client_nonce + self.client_certificate +
            self.requested_session_timeout + self.max_response_message_size
        )

    def __str__(self):
        return (
                f'CreateSessionRequest\n'
                f'MessageType: MSG\n'
                f'ChunkType: {self.chunk_type}\n'
                f'MessageSize: {bytes_to_integer(self.message_size)}\n'
                f'SecureChannelId: {bytes_to_integer(self.secure_channel_id)}\n'
                f'SecureTokenId: {bytes_to_integer(self.secure_token_id)}\n'
                f'SecureSequenceNumber: {bytes_to_integer(self.secure_sequence_number)}\n'
                f'SecureRequestId: {bytes_to_integer(self.secure_request_id)}\n'
                f'TypeId: {parse_node(self.type_id)[0]}\n'
                f'AuthenticationToken: {bytes_to_integer(self.authentication_token,is_short=True)}\n'
                f'Timestamp: {parse_timestamp(self.timestamp)}\n'
                f'RequestHandle: {bytes_to_integer(self.request_handle)}\n'
                f'ReturnDiagnostics: {bytes_to_integer(self.return_diagnostics)}\n'
                f'AuditEntry: {bytes_to_integer(self.audit_entry)}\n'
                f'TimeOutHint: {bytes_to_integer(self.timeout_hint)}\n'
                f'AditionalHeader: {self.additional_header}\n'
                f'ApplicationURI: {self.application_uri[4:]}\n'
                f'ProductURI: {bytes_to_integer(self.product_uri)}\n'
                f'ApplicationName: {self.application_name}\n'
                f'ApplicationType: {bytes_to_integer(self.application_type)}\n'
                f'GateWayServerURI: {bytes_to_integer(self.gateway_server_uri)}\n'
                f'DiscoveryProfileURI: {bytes_to_integer(self.discovery_profile_uri)}\n'
                f'DiscoveryProfileURLs: {bytes_to_integer(self.discorvery_urls)}\n'
                f'ServerURI: {bytes_to_integer(self.server_uri)}\n'
                f'EndpointURL: {self.endpoint_url[4:]}\n'
                f'SessionName: {bytes_to_integer(self.session_name)}\n'
                f'ClientNonce: {bytes_to_integer(self.client_nonce)}\n'
                f'ClientCertificate: {bytes_to_integer(self.client_certificate)}\n'
                f'RequestedSessionTimeout: {(bytes_to_integer(self.requested_session_timeout, is_double=True))}\n'
                f'MaxResponseMessageSize: {bytes_to_integer(self.max_response_message_size)}\n'
        )