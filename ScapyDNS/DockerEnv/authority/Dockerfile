FROM alpine:3.19

RUN apk add --update bash python3 py3-pip && \
    python3 -m venv /opt/venv && \
    . /opt/venv/bin/activate && \
    pip install scapy

# Make sure scripts in the virtualenv are available in the PATH
ENV PATH="/opt/venv/bin:$PATH"