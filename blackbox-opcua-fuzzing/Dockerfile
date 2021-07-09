FROM blackbox-fuzzer/baseimage

WORKDIR /opt/app

COPY setup_target_auto.sh /opt/app/

RUN ./setup_target_auto.sh

ENTRYPOINT ["/opt/app/fuzz_opcua_server.py"]
