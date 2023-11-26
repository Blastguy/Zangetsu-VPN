import argparse
import asyncio
import logging
import ssl
import threading
import pytun

from pytun import TunTapDevice

from aioquic.asyncio.client import connect
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived

logger = logging.getLogger("Zangetsu")

class ZangetsuProtocol(QuicConnectionProtocol):
    def __init__(self, is_client:bool, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_client = is_client
        self.stream_id = self._quic.get_next_available_stream_id() if is_client else None
        tun = TunTapDevice(name="tunnel" + ("_client" if is_client else "_server"), flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
        tun.addr = "10.11.12.1" if is_client else "10.11.12.2"
        tun.dstaddr = "10.11.12.2" if is_client else "10.11.12.1"
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
            packet = self._tun.read(self._tun.mtu)
            self._quic.send_stream_data(self.stream_id, bytes(packet), False)
            self.transmit()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            if not self.stream_id:
                self.stream_id = event.stream_id
            self._tun.write(bytes(event.data))

class ZangetsuClientProtocol(ZangetsuProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(True, *args, **kwargs)

class ZangetsuServerProtocol(ZangetsuProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(False, *args, **kwargs)

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
        create_protocol=ZangetsuClientProtocol
        ) as client:
        logger.info("Connected")
        await asyncio.shield(asyncio.get_event_loop().create_future())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VPN over QUIC")

    parser.add_argument(
        "--server",
        action="store_true",
        help="This process is Server"
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
        "-k",
        "--private-key",
        type=str,
        #required=True,
        help="TLS Private Key Path",
    )
    parser.add_argument(
        "-c",
        "--certificate",
        type=str,
        #required=True,
        help="TLS Public Certificate Path",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose Logging"
    )

    parser.add_argument(
        "-i",
        "--insecure",
        action="store_true",
        help="Client Only: No verification of server Certificate",
    )

    args = parser.parse_args()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )
    configuration = QuicConfiguration(
        alpn_protocols=["doq"], is_client=False if args.server else True, max_datagram_frame_size=65536
    )
    if args.server:

        configuration.load_cert_chain(args.certificate, args.private_key)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            serve(
                args.host,
                args.port,
                configuration=configuration,
                create_protocol=ZangetsuServerProtocol,
            )
        )
        loop.run_forever() #//figure out why this is needed, to reconnect? if so not needed, if server terminates with client, fine with us.
    if not args.server:
        if args.insecure:
            configuration.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            run(
                configuration=configuration,
                host=args.host,
                port=args.port,
            )
        )