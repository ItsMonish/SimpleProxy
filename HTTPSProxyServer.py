# For Functionalities to access filesystem to provide for the Certificate Authority
import tempfile
import os
import logging as Log

# For resolving addresses and interface to listen on
import dns.resolver
import netifaces
import requests

# Impelementations of OpenSSL to create the Fake Certificate Authority
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import (X509,X509Extension,X509Req,dump_privatekey,dump_certificate,load_certificate,PKey,TYPE_RSA)

# Provides functionality to the proxy from various endpoints
from twisted.internet import protocol,reactor
from twisted.internet import ssl as TwistedSSL


class TLSProxyProtocol(protocol.Protocol):
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
    #  Makes a TLS connection from the proxy to server to complete the chain
        Log.info("[INFO - TLSProxyProtocol]: Connection made from Client to Proxy")
        ProxyToServerFactory = protocol.ClientFactory()
        ProxyToServerFactory.protocol = ProxyToServerProtocol
        ProxyToServerFactory.server = self

        reactor.connectSSL(DST_IP,DST_PORT,ProxyToServerFactory,TwistedSSL.CertificateOptions())

    def dataReceived(self, data: bytes) -> None:
    # Called by twisted when the proxy recieves data from the client 
    # Sends the data to the server
        if self.ProxyToServerProtocol:
            self.ProxyToServerProtocol.write(data)
        else:
            self.buffer = data

class ProxyToServerProtocol(protocol.Protocol):
    # This class connects to the destination server over TCP 
    # It makes use of data from TLSProxyProtocol class
    # After recieving a response sends back to client using TLSProxyProtocol

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

class FakeCA(object):
    # A class that is going to govern the fake certificate authority
    # It wraps a root CA TLS certificate and signs certificates 
    # using the root CA TLS certificate

    CertificatePrefix = "fake-cert"
    def __init__(self, CAFile, CacheDir = tempfile.mkdtemp()) -> None:
        Log.info("[INFO - CA]: CA initialized with CAFile: {} and CacheDir: {}".format(CAFile,CacheDir))
        self.CAFile = CAFile
        self.CacheDir = CacheDir
        if not os.path.exists(CAFile):
            Log.error("[ERROR - CA]: No CA certificate located at {}".format(CAFile))
            raise Exception("CertificateNotFound")
        else:
            self.ReadCA(CAFile)

    def getCertificatePath(self,CommonName) -> str:
        # Function to return the file names of the root CA certificate and key folder
        # Generates them if not found in the specified directory
        CommonNamePath = os.path.sep.join([self.CacheDir,"{}-{}.pem".format(self.CertificatePrefix,CommonName)])
        if os.path.exists(CommonNamePath):
            Log.info("[INFO - CA]: Certificate Exists at the path {}".format(CommonNamePath))
        else:
            Log.info("[INFO - CA]: Certificate not found in {}".format(CommonNamePath))
            Log.info("[INFO - CA]: Generating Certificate")
            newKey = PKey()
            newKey.generate_key(TYPE_RSA, 2048)

            # To Generate Certificate Signing Request a.k.a CSR
            ReqObject = X509Req()
            ReqObject.get_subject().CN = CommonName
            ReqObject.set_pubkey(newKey)
            ReqObject.sign(newKey,'sha256')

            # Signing CSR
            CertificateObj = X509()
            CertificateObj.set_subject(ReqObject.get_subject())
            CertificateObj.set_serial_number(1856)
            CertificateObj.gmtime_adj_notBefore(0)
            CertificateObj.gmtime_adj_notAfter(31536000)
            CertificateObj.set_issuer(self.cert.get_subject())
            CertificateObj.set_pubkey(ReqObject.get_pubkey())
            CertificateObj.sign(newKey,'sha256')

            # Dumping generated keys in the file system
            with open(CommonNamePath,"wb+") as fileWriter:
                fileWriter.write(dump_privatekey(FILETYPE_PEM, newKey))
                fileWriter.write(dump_certificate(FILETYPE_PEM, CertificateObj))
            
            Log.info("[INFO]: New key and certificate generated at {}".format(CommonNamePath))
        
        return CommonNamePath

    def ReadCA(self, fileName) -> None:
        self.cert = load_certificate(FILETYPE_PEM,open(fileName).read())
        self.key = load_certificate(FILETYPE_PEM,open(fileName).read())

    @staticmethod
    def GenerateCertificate(filePath, fileCommonName) -> None:
        # Static method to generate certificates for session that will be verified by root 
        # certificate at client side
        if os.path.exists(filePath):
            Log.info('[INFO - CAGen]: Certificates already created at {}'.format(filePath))
            return
        
        # Generate Key
        key = PKey()
        key.generate_key(TYPE_RSA, 2048)

        # Generate Certificate
        cert = X509()
        cert.set_version(2)
        cert.add_extensions([X509Extension(b'basicConstraints',True,b'CA:TRUE, pathlen:0'),
                             X509Extension(b'keyUsage',True,b'keyCertSign, cRLSign'),
                             X509Extension(b'subjectKeyIdentifier',False,b'hash',subject=cert)])
        cert.get_subject().C = "IN"
        cert.get_subject().ST = "TamilNadu"
        cert.get_subject().L = "Chennai"
        cert.get_subject().O = "Simple Proxy Trust Certificate Authority"
        cert.get_subject().OU = "Simple Proxy Trust Certificate Authority"
        cert.set_serial_number(1)
        cert.get_subject().CN = fileCommonName
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(315360000)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        with open(filePath, 'wb+') as f:
            f.write(dump_privatekey(FILETYPE_PEM, key))
            f.write(dump_certificate(FILETYPE_PEM, cert))

def getLocalIP(interface) -> str:
    return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']

def getIP() -> str:
    reqURL = 'https://ipinfo.io/json'
    response = requests.get(reqURL,verify=True)
    return response.json()['ip']

if __name__ == "__main__":
    Log.basicConfig(level=Log.INFO,filename="HTTPSProxyServer.log",filemode="a",format="%(asctime)s: %(message)s")
    CA_CERTIFICATE_PATH = "./ca.crt"
    LISTEN_PORT = 443
    DST_PORT = 443
    DST_HOST = "youtube.com"
    LocalIP = getLocalIP("eth0")
    Log.info("[INFO]: Querying DNS for host {}".format(DST_HOST))
    DNSResolver = dns.resolver.Resolver()
    DNSResolver.nameservers = ['1.1.1.1','8.8.8.8']
    DNSResponse = DNSResolver.resolve(DST_HOST)
    if len(DNSResponse) == 0:
        Log.error("[ERROR] : The lookup for host {} returned no records... Might be a invalid host".format(DST_HOST))
        raise Exception("HostNotFound") 
    DST_IP = DNSResponse[0].address
    Log.info("[INFO]: DNS Lookup for {} returned {}".format(DST_HOST,DST_IP))
    FakeCA.GenerateCertificate(CA_CERTIFICATE_PATH,"Simple Proxy Trust Certificate Authority")
    CA = FakeCA(CA_CERTIFICATE_PATH)
    CertificateFile = CA.getCertificatePath(DST_HOST)
    with open(CertificateFile) as fileIn:
        cert = TwistedSSL.PrivateCertificate.loadPEM(fileIn.read())
    print(cert)
    # if not os.path.exists(CA_CERTIFICATE_PATH):
    #     os.system('openssl genrsa -out ca_private.key')
    #     os.system('openssl req -x509 -new -sha256 -nodes -key ca_private.key -days 3650 -addext basicConstraints=critical,CA:TRUE,pathlen:1 -out ca_public.crt -subj \"/C=IN/ST=TN/L=TamilNadu/O=Simple Proxy/CN=Simple Proxy\"')
    #     os.system('cat ca_private.key > ca.crt')
    #     os.system('cat ca_public.crt >> ca.crt')
    # if not os.path.exists('./certs/'):
    #     os.mkdir('certs')
    # os.system('openssl genrsa -out ./certs/{}.key 2048'.format(DST_HOST+'_private'))
    # os.system('openssl req -new -key ./certs/{}.key -out ./certs/{}.csr -nodes -addext basicConstraints=critical,CA:FALSE,pathlen:1 -addext keyUsage=digitalSignature,keyEncipherment,dataEncipherment -subj \"/C=IN/ST=TN/L=TamilNadu/O=Simple Proxy/CN={}\"'   \
    #             .format(DST_HOST+'_private',DST_HOST+'_public',DST_HOST))
    # os.system('openssl x509 -req -sha256 -in ./certs/{}.csr -CA ca_public.crt -CAkey ca_private.key     \
    #             -CAcreateserial -out ./certs/{}.crt -days 365'.                                         \
    #             format(DST_HOST+'_public',DST_HOST))
    # os.system('cat ./certs/{}.key > ./certs/{}.pem'.format(DST_HOST+'_private',DST_HOST))
    # os.system('cat ./certs/{}.crt >> ./certs/{}.pem'.format(DST_HOST,DST_HOST))
    with open('./certs/{}.pem'.format(DST_HOST)) as fileIn:
        cert = TwistedSSL.PrivateCertificate.loadPEM(fileIn.read())
    factory = protocol.ServerFactory()
    factory.protocol = TLSProxyProtocol
    reactor.listenSSL(LISTEN_PORT,factory,cert.options(),interface=LocalIP)
    reactor.run()