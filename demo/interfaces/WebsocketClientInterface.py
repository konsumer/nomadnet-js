import threading
import time
import RNS
from RNS.Interfaces.Interface import Interface
from websockets.sync.client import connect


class WebsocketClientInterface(Interface):
    MAX_CHUNK = 32768
    BITRATE_GUESS = 1*1000*1000
    DEFAULT_IFAC_SIZE = 16

    def __init__(self, owner, configuration):
        super().__init__()


        # Parse configuration
        c = Interface.get_config_obj(configuration)
        self.name = c["name"]
        self.target_url = c["target_url"] if "target_url" in c else None

        if not self.target_url:
            raise ValueError(f"No target_url specified for {self.name}")

        # Set required interface properties
        self.rxb = 0
        self.txb = 0
        self.owner = owner
        self.HW_MTU = 262144  # 256KiB
        self.bitrate = WebsocketClientInterface.BITRATE_GUESS

        # Interface flags
        self.IN = True
        self.OUT = True
        self.mode = RNS.Interfaces.Interface.Interface.MODE_FULL

        # Connection state
        self.online = False
        self.websocket = None
        self.should_reconnect = True
        self.detached = False

        # Try to connect immediately with a short timeout
        try:
            RNS.log(f"Attempting initial connection to {self.target_url}", RNS.LOG_INFO)
            RNS.log(f"Interface {self.name} initializing with target URL: {self.target_url}", RNS.LOG_DEBUG)
            import websockets.sync.client
            # Set a short timeout for initial connection
            self.websocket = websockets.sync.client.connect(self.target_url, open_timeout=2.0)
            self.online = True
            RNS.log(f"Initial connection successful to {self.target_url}", RNS.LOG_INFO)
            RNS.log(f"Websocket object created: {self.websocket}", RNS.LOG_EXTREME)
        except Exception as e:
            RNS.log(f"Initial connection failed: {e}, will retry in background", RNS.LOG_DEBUG)
            RNS.log(f"Exception type: {type(e).__name__}", RNS.LOG_EXTREME)

        # Start background thread for reading and reconnection
        RNS.log(f"Starting connection thread for {self.name}", RNS.LOG_DEBUG)
        self.connection_thread = threading.Thread(target=self.connection_loop)
        self.connection_thread.daemon = True
        self.connection_thread.start()
        RNS.log(f"Connection thread started for {self.name}, thread ID: {self.connection_thread.ident}", RNS.LOG_EXTREME)

    def connection_loop(self):
        """Main connection loop that handles reading and reconnecting"""
        RNS.log(f"Connection loop started for {self.name}", RNS.LOG_DEBUG)
        while self.should_reconnect:
            RNS.log(f"Connection loop iteration - online: {self.online}, websocket: {self.websocket is not None}, should_reconnect: {self.should_reconnect}", RNS.LOG_EXTREME)
            if self.online and self.websocket:
                # We have a connection, just read
                RNS.log(f"Already connected, starting read loop for {self.name}", RNS.LOG_DEBUG)
                self.read_loop()
            else:
                # Need to connect/reconnect
                try:
                    RNS.log(f"Connecting to {self.target_url}", RNS.LOG_INFO)
                    RNS.log(f"Creating new websocket connection for {self.name}", RNS.LOG_DEBUG)
                    self.websocket = connect(self.target_url)
                    self.online = True
                    RNS.log(f"Connected to {self.target_url}", RNS.LOG_INFO)
                    RNS.log(f"Websocket connected, object: {self.websocket}", RNS.LOG_EXTREME)

                    # Start read loop
                    self.read_loop()

                except Exception as e:
                    RNS.log(f"Connection failed: {e}", RNS.LOG_ERROR)
                    RNS.log(f"Full exception details: {type(e).__name__}: {str(e)}", RNS.LOG_DEBUG)
                    self.online = False
                    self.websocket = None

                    if self.should_reconnect:
                        RNS.log(f"Reconnecting in 5 seconds...", RNS.LOG_DEBUG)
                        time.sleep(5)
        RNS.log(f"Connection loop ended for {self.name}", RNS.LOG_INFO)

    def read_loop(self):
        """Read messages from websocket"""
        RNS.log(f"Starting read loop for {self.name}", RNS.LOG_DEBUG)
        message_count = 0
        try:
            while self.online and self.websocket:
                RNS.log(f"Waiting for message on {self.name}...", RNS.LOG_EXTREME)
                message = self.websocket.recv()
                if message is None:
                    RNS.log(f"Received None from websocket, connection may be closing", RNS.LOG_DEBUG)
                    break
                if isinstance(message, bytes):
                    message_count += 1
                    self.rxb += len(message)
                    RNS.log(f"Received message #{message_count}: {len(message)} bytes on {self.name}", RNS.LOG_DEBUG)
                    RNS.log(f"Total bytes received: {self.rxb}", RNS.LOG_EXTREME)
                    RNS.log(f"Message preview (first 50 bytes): {message[:50].hex()}", RNS.LOG_EXTREME)
                    self.owner.inbound(message, self)
                else:
                    RNS.log(f"Received non-bytes message type: {type(message)}", RNS.LOG_WARNING)
        except Exception as e:
            RNS.log(f"Read error: {e}", RNS.LOG_ERROR)
            RNS.log(f"Read error details: {type(e).__name__}: {str(e)}", RNS.LOG_DEBUG)
            self.online = False
        RNS.log(f"Read loop ended for {self.name} after {message_count} messages", RNS.LOG_DEBUG)

    def process_outgoing(self, data):
        """Send data over websocket"""
        RNS.log(f"process_outgoing called with {len(data)} bytes on {self.name}", RNS.LOG_DEBUG)
        if self.online and self.websocket:
            try:
                RNS.log(f"Sending {len(data)} bytes over {self.name}", RNS.LOG_DEBUG)
                RNS.log(f"Data preview (first 50 bytes): {data[:50].hex()}", RNS.LOG_EXTREME)
                self.websocket.send(data)
                self.txb += len(data)
                RNS.log(f"Successfully sent {len(data)} bytes, total sent: {self.txb}", RNS.LOG_DEBUG)
                return True
            except Exception as e:
                RNS.log(f"Send error: {e}", RNS.LOG_ERROR)
                RNS.log(f"Send error details: {type(e).__name__}: {str(e)}", RNS.LOG_DEBUG)
                self.online = False
                return False
        else:
            RNS.log(f"Cannot send: online={self.online}, websocket={self.websocket is not None}", RNS.LOG_DEBUG)
        return False

    def detach(self):
        """Shutdown the interface"""
        RNS.log(f"Detaching {self.name}", RNS.LOG_DEBUG)
        RNS.log(f"Current state before detach - online: {self.online}, websocket: {self.websocket is not None}", RNS.LOG_EXTREME)
        self.should_reconnect = False
        self.online = False
        self.detached = True
        if self.websocket:
            try:
                RNS.log(f"Closing websocket for {self.name}", RNS.LOG_DEBUG)
                self.websocket.close()
                RNS.log(f"Websocket closed successfully for {self.name}", RNS.LOG_DEBUG)
            except Exception as e:
                RNS.log(f"Error closing websocket: {e}", RNS.LOG_DEBUG)
                pass
        RNS.log(f"Interface {self.name} detached", RNS.LOG_INFO)

    def __str__(self):
        status = "online" if self.online else "offline"
        return f"WebsocketClientInterface[{self.name}|{status}]"


# Set interface class RNS should use when importing this external interface
interface_class = WebsocketClientInterface
