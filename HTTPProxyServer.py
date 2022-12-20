# Provides functionality to the proxy from various endpoints
from twisted.internet import protocol,reactor

# For resolving addresses and interface to listen on
import dns.resolver
import netifaces

import logging as Log

DST_HOST = ""
DST_IP = ""

class TCPProxyProtocol(protocol.Protocol):
    # This class listens for TCP connections from a client and forwards them to the specified destination
    # It does so with the help of ProxyToServerProtocol Class

    def __init__(self) -> None:
        super().__init__()
        self.buffer = None
        self.ProxyToServerProtocol = None

    def write(self,data) -> None:
        if data:
            self.transport.write(data)

    def connectionMade(self) -> None:
    # Called by twisted when the client makes connection to the proxy
    #  Makes a TCP connection from the proxy to server to complete the chain
        Log.info("[INFO - TCPProxyProtocol]: Connection made from Client to Proxy")
        ProxyToServerFactory = protocol.ClientFactory()
        ProxyToServerFactory.protocol = ProxyToServerProtocol
        ProxyToServerFactory.server = self
        reactor.connectTCP(DST_IP,DST_PORT,ProxyToServerFactory)

    def dataReceived(self, data: bytes) -> None:
    # Called by twisted when the proxy recieves data from the client 
    # Sends the data to the server
        global DST_HOST
        global DST_IP
        DST_HOST = str(data).split("\\r\\n")[1][5:].strip()
        DST_IP = getHostIP(DST_HOST)
        if self.ProxyToServerProtocol:
            self.ProxyToServerProtocol.write(data)
        else:
            self.buffer = data

class ProxyToServerProtocol(protocol.Protocol):
    # This class connects to the destination server over TCP 
    # It makes use of data from TCPProxyProtocol class
    # After recieving a response sends back to client using TCPProxyProtocol

    def write(self,data) -> None:
        if data:
            self.transport.write(data)
    
    def connectionMade(self) -> None:
        # Called by twisted when the proxy connects to the server
        # Flushes previously buffered data
        Log.info("[INFO - ProxyToServerProtocol]: Connection made from Proxy to destination server")
        self.factory.server.ProxyToServerProtocol = self
        self.write(self.factory.server.buffer)
        self.factory.server.buffer = ""

    def dataReceived(self, data: bytes) -> None:
        # Called by twisted when proxy recieves data from the server. 
        # Sends data back to the client
        Log.info("[INFO - ProxyToServerProtocol]: Forwarding traffic from Proxy to client")
        self.factory.server.write(data)


def getLocalIP(interface) -> str:
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def getHostIP(HostName):
        Log.info("[INFO]: Querying DNS for host {}".format(HostName))
        DNSResolver = dns.resolver.Resolver()
        DNSResolver.nameservers = ['1.1.1.1','8.8.8.8']
        DNSResponse = DNSResolver.resolve(HostName)
        if len(DNSResponse) == 0:
            Log.error("[ERROR] : The lookup for host {} returned no records... Might be a invalid host".format(HostName))
            raise Exception("HostNotFound") 
        returnIP = DNSResponse[0].address
        Log.info("[INFO]: DNS Lookup for {} returned {}".format(HostName,returnIP))
        return returnIP

if __name__ == "__main__":
    Log.basicConfig(level=Log.INFO,filename="HTTPProxyServer.log",filemode="a",format="%(asctime)s: %(message)s")
    LISTEN_PORT = 80
    DST_PORT = 80
    LocalIP = getLocalIP("eth0")
    factory = protocol.ServerFactory()
    factory.protocol = TCPProxyProtocol
    reactor.listenTCP(LISTEN_PORT,factory)
    reactor.run()