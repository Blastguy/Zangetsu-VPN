import argparse
import asyncio
import json
import logging
import pickle
import ssl
import base64
from typing import Optional, cast, Dict

from dnslib.dns import QTYPE, DNSQuestion, DNSRecord

import fcntl
import struct
import os
import socket
import threading
import sys
import pytun

from pytun import TunTapDevice

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicLogger
from aioquic.tls import SessionTicket

try:
    import uvloop
except ImportError:
    uvloop = None

#Classes for Server
COUNT_SERVER = 0

class VPNServerProtocol(QuicConnectionProtocol):

    # -00 specifies 'dq', 'doq', and 'doq-h00' (the latter obviously tying to
    # the version of the draft it matches). This is confusing, so we'll just
    # support them all, until future drafts define conflicting behaviour.
    SUPPORTED_ALPNS = ["dq", "doq", "doq-h00"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vpn = None

    def tun_read(self):
        global tun, STREAM_ID
        while True:
            # intercept packets that are about to be sent
            packet = tun.read(tun.mtu)
            end_stream = False
            # send them through the appropriate QUIC Stream
            self._quic.send_stream_data(STREAM_ID, bytes(packet), end_stream)
            self.transmit()

    def quic_event_received(self, event):
        global COUNT_SERVER, tun, STREAM_ID
        if isinstance(event, StreamDataReceived):

            if COUNT_SERVER == 0:
                # authentication check
                data = self.auth_check(event.data)
                end_stream = False
                STREAM_ID = event.stream_id
                self._quic.send_stream_data(event.stream_id, data, end_stream)
                self.transmit()

                # if auth successful, start reading on local tun interface and
                # prepare to receive QUIC|IP|QUIC
                if data == bytes("Authentication_succeeded", "utf-8"):
                    t = threading.Thread(target=self.tun_read)
                    t.start()
                    COUNT_SERVER = 1
            else:
                # QUIC event received => decapsulate and write to local tun
                answer = event.data
                tun.write(bytes(answer))

    def auth_check(self, payload):
        decoded_auth = base64.b64decode(payload).decode("utf-8", "ignore")
        login = decoded_auth.partition(":")[0]
        password = decoded_auth.partition(":")[2]
        print("login = ", login)
        print("password = ", password)
        bool = login == "root" and password == "toor"
        if bool:
            return bytes("Authentication_succeeded", "utf-8")
        else:
            return bytes("Authentication_failed", "utf-8")


class SessionTicketStore:
    """
    Simple in-memory store for session tickets.
    """

    def __init__(self):
        self.tickets = {}

    def add(self, ticket):
        self.tickets[ticket.ticket] = ticket

    def pop(self, label):
        return self.tickets.pop(label, None)

#Class for CLient
logger = logging.getLogger("client")

COUNT_CLIENT = 0

class VPNClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_waiter: Optional[asyncio.Future[None]] = None

    async def query(self) -> None:
        # client authentication using login/password, clear text because already encrypted by QUIC
        global STREAM_ID
        login = input("login: ")
        password = input("password: ")
        conc = login + ":" + password
        conc = conc.encode("utf-8")
        auth = base64.b64encode(conc)
        query = auth
        stream_id = self._quic.get_next_available_stream_id()
        STREAM_id = stream_id
        end_stream = False
        self._quic.send_stream_data(stream_id, bytes(query), end_stream)
        waiter = self._loop.create_future()
        self._ack_waiter = waiter
        self.transmit()

        return await asyncio.shield(waiter)

    def tun_read(self) -> None:
        global tun, STREAM_ID
        while True:
            # QUIC encapsulation 
            packet = tun.read(tun.mtu)
            end_stream = False
            self._quic.send_stream_data(STREAM_ID, bytes(packet), end_stream)
            waiter = self._loop.create_future()
            self._ack_waiter = waiter
            self.transmit()

    def quic_event_received(self, event: QuicEvent) -> None:
        global COUNT_CLIENT, tun
        if self._ack_waiter is not None:
            if isinstance(event, StreamDataReceived):
                if COUNT_CLIENT == 0:
                    # authentication succeeded or failed
                    COUNT_CLIENT = 1
                    answer = event.data.decode("utf-8", "ignore")
                    waiter = self._loop.create_future()
                    self._ack_waiter = waiter
                    t = threading.Thread(target=self.tun_read)
                    t.start()
                else:
                    # decapsulate QUIC and write to internal tun
                    answer = event.data
                    tun.write(answer)
                    waiter = self._loop.create_future()
                    self._ack_waiter = waiter


def save_session_ticket(ticket):
    """
    Callback which is invoked by the TLS engine when a new session ticket
    is received.
    """
    logger.info("New session ticket received")
    if args.session_ticket:
        with open(args.session_ticket, "wb") as fp:
            pickle.dump(ticket, fp)


async def run(
    configuration: QuicConfiguration,
    host: str,
    port: int,
    # query_type: str,
    # dns_query: str,
) -> None:
    logger.debug(f"Connecting to {host}:{port}")
    async with connect(
        host,
        port,
        configuration=configuration,
        session_ticket_handler=save_session_ticket,
        create_protocol=VPNClient,
    ) as client:
        client = cast(VPNClient, client)
        logger.debug("Sending connection query")
        await client.query()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VPN over QUIC")

    parser.add_argument(
        "--server",
        action="store_true",
        help="Enable the server code!"
    )
    parser.add_argument(
        "--client",
        action="store_true",
        help="Enable the client code!"
    )    

    parser.add_argument(
        "--host",
        type=str,
        default="::",
        help="For Server: Listen to the specified address (defaults to ::), For Client: Server's Host name or IP address ",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="For Server: Listen on the specified port (defaults to 443), For Client: Hosts port number",
    )
    parser.add_argument(
        "-key",
        "--private-key",
        type=str,
        #required=True,
        help="load the TLS private key from the specified file",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        #required=True,
        help="load the TLS certificate from the specified file",
    )
    parser.add_argument(
        "-q",
        "--quic-log",
        type=str,
        help="log QUIC events to a file in QLOG format"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="increase logging verbosity"
    )

    parser.add_argument("-t", "--type", type=str, help="Type of record to ")
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not validate server certificate",
    )
    parser.add_argument(
        "-l",
        "--secrets-log",
        type=str,
        help="log secrets to a file, for use with Wireshark",
    )
    parser.add_argument(
        "-s",
        "--session-ticket",
        type=str,
        help="read and write session ticket from the specified file",
    )

    args = parser.parse_args()

    if args.server:
        # initialize virtual interface tun for server
        tun = TunTapDevice(name="mytun_serv", flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        tun.addr = "10.10.10.2"
        tun.dstaddr = "10.10.10.1"
        tun.netmask = "255.255.255.0"
        tun.mtu = 1048
        tun.persist(True)
        tun.up()
        STREAM_ID = 100

        logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        )

        if args.quic_log:
            quic_logger = QuicLogger()
        else:
            quic_logger = None

        configuration = QuicConfiguration(
            alpn_protocols=["dq"],
            is_client=False,
            max_datagram_frame_size=65536,
            quic_logger=quic_logger,
        )

        configuration.load_cert_chain(args.certificate, args.private_key)

        ticket_store = SessionTicketStore()

        if uvloop is not None:
            uvloop.install()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            serve(
                args.host,
                args.port,
                configuration=configuration,
                create_protocol=VPNServerProtocol,
                session_ticket_fetcher=ticket_store.pop,
                session_ticket_handler=ticket_store.add,
                # stateless_retry=args.stateless_retry,
            )
        )
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if configuration.quic_logger is not None:
                with open(args.quic_log, "w") as logger_fp:
                    json.dump(configuration.quic_logger.to_dict(), logger_fp, indent=4)

    if args.client:
        # initialize virtual interface tun for client
        tun = TunTapDevice(name="mytunnel", flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        tun.addr = "10.10.10.1"
        tun.dstaddr = "10.10.10.2"
        tun.netmask = "255.255.255.0"
        tun.mtu = 1048
        tun.persist(True)
        tun.up()
        STREAM_ID = 100

        logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        )

        configuration = QuicConfiguration(
            alpn_protocols=["dq"], is_client=True, max_datagram_frame_size=65536
        )
        if args.insecure:
            configuration.verify_mode = ssl.CERT_NONE
        if args.quic_log:
            configuration.quic_logger = QuicLogger()
        if args.secrets_log:
            configuration.secrets_log_file = open(args.secrets_log, "a")
        if args.session_ticket:
            try:
                with open(args.session_ticket, "rb") as fp:
                    configuration.session_ticket = pickle.load(fp)
            except FileNotFoundError:
                logger.debug(f"Unable to read {args.session_ticket}")
                pass
        else:
            logger.debug("No session ticket defined...")

        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(
                run(
                    configuration=configuration,
                    host=args.host,
                    port=args.port,
                )
            )
        finally:
            if configuration.quic_logger is not None:
                with open(args.quic_log, "w") as logger_fp:
                    json.dump(configuration.quic_logger.to_dict(), logger_fp, indent=4)