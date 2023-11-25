import argparse
import asyncio
import json
import logging
import pickle
import ssl
from typing import cast
import threading
import pytun

from pytun import TunTapDevice

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ProtocolNegotiated, QuicEvent, StreamDataReceived
from aioquic.quic.logger import QuicLogger
from aioquic.tls import SessionTicket
logger = logging.getLogger("Zangetsu")

class ZangetsuProtocol(QuicConnectionProtocol):
    def __init__(self, is_client:bool, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_client = is_client
        self.stream_id = self._quic.get_next_available_stream_id() if is_client else None
        self.tun = TunTapDevice
        tun = TunTapDevice(name="tunnel" + ("_client" if is_client else "_server"), flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        tun.addr = "10.11.12.2"
        tun.dstaddr = "10.11.12.1"
        tun.netmask = "255.255.255.0"
        tun.mtu = 1048
        tun.persist(True)
        tun.up()
        self._tun = tun
        t = threading.Thread(target=self.tun_read)
        t.start()

    def tun_read(self):
        while True:
            # reroute packets, no proper termination protocol
            packet = tun.read(tun.mtu)
            self._quic.send_stream_data(self.stream_id, bytes(packet), False)
            self.transmit()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            tun.write(event.data)


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
        create_protocol=ZangetsuProtocol,
    ) as client:
        client = cast(ZangetsuProtocol, client)

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

    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    if args.server:

        configuration = QuicConfiguration(
            alpn_protocols=["dq"],
            is_client=False,
            max_datagram_frame_size=65536,
            quic_logger=quic_logger,
        )

        configuration.load_cert_chain(args.certificate, args.private_key)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            serve(
                args.host,
                args.port,
                configuration=configuration,
                create_protocol=ZangetsuProtocol,
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