import struct
from calendar import timegm
from datetime import datetime
from pathlib import Path

from boofuzz import (
    s_initialize, s_bytes, s_dword, Session, s_get, s_block, Target, s_size, s_qword, exception, ProcessMonitor,
    TCPSocketConnection, s_byte
)

from parse.crash import merge_boofuzz_data, store_crash_information, convert_boofuzz_sqlite_to_dict
from parse.packet import ENDPOINT_STRING

# Weird OPC time stuff
EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000


def setup_session(ip: str, port: int, target_path: str) -> Session:
    '''
    The current number of mutations for each definition is
    - Hello 2261
    - OpenChannel 5287
    - CloseChannel 844
    - FindServers 2624
    - GetEndpoints 2624
    - FindServersOnNetwork 1264
    - RegisterServer2 6845
    - CreateSession 5984
    - ActivateSession 4032
    Total mutations: 31765

    You can narrow the fuzzing by using these values to set index_start and index_end in the Session definition.
    '''
    if target_path:
        procmon = ProcessMonitor('127.0.0.1', 26002)
        procmon.set_options(start_commands=[target_path.split(), ], capture_output=True)

        target = Target(
            connection=TCPSocketConnection(ip, port),
            monitors=[procmon, ]
        )
    else:
        target = Target(
            connection=TCPSocketConnection(ip, port),
        )

    return Session(
        target=target,
        sleep_time=0,
        index_start=0,
        index_end=None,
        receive_data_after_fuzz=True,
        keep_web_open=False,
        web_port=None
    )


def get_weird_opc_timestamp():
    now = datetime.now()
    ft = EPOCH_AS_FILETIME + (timegm(now.timetuple()) * HUNDREDS_OF_NANOSECONDS)
    return ft + (now.microsecond * 10)


def set_channel_parameter_from_open(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, policy_len = struct.unpack('ii', recv[8:16])
        sequence_offset = 24 + policy_len
        seq_num, req_id = struct.unpack('ii', recv[sequence_offset:sequence_offset + 8])

        request_header_length = 8 + 4 + 4 + 1 + 4 + 3
        token_offset = sequence_offset + 8 + 4 + request_header_length + 4
        sec_channel_id, token_id = struct.unpack('ii', recv[token_offset:token_offset + 8])
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')
    else:
        node.stack[1].stack[0]._value = sec_channel_id
        node.stack[1].stack[1]._value = token_id
        node.stack[1].stack[2]._value = seq_num + 1
        node.stack[1].stack[3]._value = req_id + 1


def set_channel_parameter_from_create(target, fuzz_data_logger, session, node, *_, **__):  # pylint: disable=protected-access
    recv = session.last_recv
    if not recv:
        fuzz_data_logger.log_fail('Empty response from server')
        return
    try:
        channel_id, token_id, seq_num, req_id = struct.unpack('iiii', recv[8:24])
    except struct.error:
        fuzz_data_logger.log_error('Could not unpack channel parameters for this test case')
    else:
        node.stack[1].stack[0]._value = channel_id
        node.stack[1].stack[1]._value = token_id
        node.stack[1].stack[2]._value = seq_num + 1
        node.stack[1].stack[3]._value = req_id + 1


def hello_definition():
    s_initialize('Hello')

    with s_block('h-header'):
        s_bytes(b'HEL', name='Hello magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('h-body', offset=8, name='body size', fuzzable=False)

    with s_block('h-body'):
        s_dword(0, name='Protocol version')
        s_dword(65536, name='Receive buffer size')
        s_dword(65536, name='Send buffer size')
        s_dword(0, name='Max message size')
        s_dword(0, name='Max chunk count')
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='Url length')
        s_bytes(endpoint, name='Endpoint url')


def open_channel_definition():
    '''
    Note: Message will be chunked. So chunk header included....
    '''
    s_initialize('OpenChannel')

    with s_block('o-header'):
        s_bytes(b'OPN', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('o-body', offset=8, name='body size', fuzzable=False)

    with s_block('o-body'):
        s_dword(0, name='channel id')

        # chunking encryption
        policy_uri = 'http://opcfoundation.org/UA/SecurityPolicy#None'.encode('utf-8')
        s_dword(len(policy_uri), name='uri length')
        s_bytes(policy_uri, name='security policy uri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='sender certificate')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='receiver certificate thumbprint')

        # chunking sequence
        s_dword(1, name='sequence number')
        s_dword(1, name='request id')

        # type id: OpenSecureChannel
        s_bytes(b'\x01\x00\xbe\x01', name='Type id')

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # open channel parameter
        s_dword(0, name='client protocol version')
        s_dword(0, name='request type')
        s_dword(1, name='security mode')
        s_bytes(b'\x00\x00\x00\x00', name='client nonce')
        s_dword(3600000, name='requested lifetime')


def close_channel_definition():
    s_initialize('CloseChannel')

    with s_block('c-header'):
        s_bytes(b'CLO', name='Close channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('c-body', offset=8, name='body size', fuzzable=False)

    with s_block('c-body'):
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        # type id: CloseSecureChannelRequest
        s_bytes(b'\x01\x00' + struct.pack('<H', 452), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(10000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')


def activate_session_definition():
    s_initialize('ActivateSession')

    with s_block('a-header'):
        s_bytes(b'MSG', name='Activate session magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('a-body', offset=8, name='body size', fuzzable=False)

    with s_block('a-body'):
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        # type id: OpenSecureChannel
        s_bytes(b'\x01\x00' + struct.pack('<H', 467), name='Type id', fuzzable=False)

        # request header
        s_dword(4, name='encoding mask guid')
        s_bytes(b'\x01\x00', name='namespace idx')
        s_bytes(b'\xcc\x8c\x09\xf9\x7b\x93\xd1\xb3\x10\xc1\x2c\x62\x3c\x43\x04\xb0', name='identifier guid')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(600000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # client signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client algorithm')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client signature')

        s_bytes(b'\xFF\xFF\xFF\xFF', name='locale id')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='client software certificates')

        # user identity token
        s_bytes(b'\x01\x00' + struct.pack('<H', 324), name='user type id', fuzzable=False)
        s_bytes(b'\x01', name='binary body')

        policy_id = 'open62541-username-policy'.encode('utf-8')
        username = 'user1'.encode('utf-8')
        password = 'password'.encode('utf-8')

        s_dword(len(policy_id) + len(username) + len(password) + 4 + 4 + 4 + 4,
                name='length user id token')  # 3 length fields + algorithm

        s_dword(len(policy_id), name='id length')
        s_bytes(policy_id, name='policy id', fuzzable=False)
        s_dword(len(username), name='username length')
        s_bytes(username, name='username')
        s_dword(len(password), name='password length')
        s_bytes(password, name='password')

        s_bytes(b'\xFF\xFF\xFF\xFF', name='encryption algorithm')

        # user token signature
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user sign algorithm')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='user signature')


def discovery_service_definition(service_name: str, request_type: int):
    s_initialize(service_name)

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', request_type), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='url length')
        s_bytes(endpoint, name='endpoint url')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='locale ids')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='profile ids')


def find_servers_on_network_definition():
    s_initialize('FindServersOnNetwork')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 12208), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # request parameter
        s_dword(0, name='starting record id')
        s_dword(0, name='max records to return')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='server capability filter')


def register_server_2_definition():
    s_initialize('RegisterServer2')

    with s_block('g-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('g-body', offset=8, name='body size', fuzzable=False)

    with s_block('g-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 12211), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        server_uri = 'urn:opcua.server'.encode('utf-8')
        s_dword(len(server_uri), name='server length')
        s_bytes(server_uri, name='server uri')

        product_uri = 'http://my.opcua-implementation.code'.encode('utf-8')
        s_dword(len(product_uri), name='product length')
        s_bytes(product_uri, name='product uri')

        # ('ServerNames', 'ListOfLocalizedText'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerNames')

        s_dword(0, name='server type')

        # ('GatewayServerUri', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')

        s_dword(1, name='Number of discovery uris')
        discovery_uri = ENDPOINT_STRING
        s_dword(len(discovery_uri), name='discovery length')
        s_bytes(discovery_uri, name='discovery url')

        # ('SemaphoreFilePath', 'String'),
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SemaphoreFilePath')

        s_byte(1, name='is online')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='discovery configuration')


def create_session_definition():
    s_initialize('CreateSession')

    with s_block('cs-header'):
        s_bytes(b'MSG', name='Open channel magic', fuzzable=False)
        s_bytes(b'F', name='Chunk type', fuzzable=False)
        s_size('cs-body', offset=8, name='body size', fuzzable=False)

    with s_block('cs-body'):
        # security
        s_dword(0, name='secure channel id', fuzzable=False)  # will be overwritten
        s_dword(4, name='secure token id', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure sequence number', fuzzable=False)  # will be overwritten
        s_dword(2, name='secure request id', fuzzable=False)  # will be overwritten

        s_bytes(b'\x01\x00' + struct.pack('<H', 461), name='Type id', fuzzable=False)

        # request header
        s_bytes(b'\x00\x00', name='authentication token')
        s_qword(get_weird_opc_timestamp(), name='timestamp')
        s_dword(1, name='request handle')
        s_dword(0, name='return diagnostics')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='audit entry id')
        s_dword(1000, name='timeout hint')
        s_bytes(b'\x00\x00\x00', name='additional header')

        # application description
        application = 'urn:unconfigured:application'.encode('utf-8')
        s_dword(len(application), name='UriLength')
        s_bytes(application, name='ApplicationUri')

        s_bytes(b'\xFF\xFF\xFF\xFF', name='ProductUri')
        s_byte(0, name='ApplicationName')
        s_dword(1, name='ApplicationType')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='GatewayServerUri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryProfileUri')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='DiscoveryUrls')

        # create session parameter
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ServerUri')
        endpoint = ENDPOINT_STRING
        s_dword(len(endpoint), name='UrlLength')
        s_bytes(endpoint, name='EndpointUrl')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='SessionName')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientNonce')
        s_bytes(b'\xFF\xFF\xFF\xFF', name='ClientCertificate')
        s_bytes(struct.pack('d', 1200000.0), name='RequestedSessionTimeout')
        s_dword(2147483647, name='MaxResponseMessageSize')


def fuzz_opcua(file_path: Path) -> str:
    session = setup_session('127.0.0.1', 4840, str(file_path.absolute()))

    hello_definition()
    open_channel_definition()
    close_channel_definition()
    create_session_definition()
    activate_session_definition()

    discovery_service_definition(service_name='FindServers', request_type=422)
    discovery_service_definition(service_name='GetEndpoints', request_type=428)
    find_servers_on_network_definition()
    register_server_2_definition()

    session.connect(s_get('Hello'))
    session.connect(s_get('Hello'), s_get('OpenChannel'))
    session.connect(s_get('OpenChannel'), s_get('CloseChannel'), callback=set_channel_parameter_from_open)

    session.connect(s_get('OpenChannel'), s_get('FindServers'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('GetEndpoints'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('FindServersOnNetwork'), callback=set_channel_parameter_from_open)
    session.connect(s_get('OpenChannel'), s_get('RegisterServer2'), callback=set_channel_parameter_from_open)

    session.connect(s_get('OpenChannel'), s_get('CreateSession'), callback=set_channel_parameter_from_open)
    session.connect(s_get('CreateSession'), s_get('ActivateSession'), callback=set_channel_parameter_from_create)

    try:
        session.fuzz()
    except KeyboardInterrupt:
        pass

    boofuzz_log = convert_boofuzz_sqlite_to_dict(session._run_id)
    crashes = merge_boofuzz_data(boofuzz_log, session._run_id)
    store_crash_information(session._run_id, crashes)

    return session._run_id
