import configparser
import requests

def getIP() -> str:
    reqURL = 'https://ipinfo.io/json'
    response = requests.get(reqURL,verify=True)
    return response.json()['ip']

if __name__ == "__main__":
    thisIP = getIP()
    configObject = configparser.ConfigParser()
    configObject.read('ProxyDNS.conf')
    interface = configObject['DNS']['interface']
    port = configObject['DNS']['port']
    domains = configObject['DNS']['domains'].split(',')
    nameservers = configObject['DNS']['defaultDNS'].split(',')
    fileWriter = open('dnsmasq.conf','w')
    fileWriter.write("listen-address={}\n".format(thisIP))
    fileWriter.write("port={}\n".format(port))
    fileWriter.write("interface={}\n".format(interface))
    if 'loadresolv' in configObject['DNS'] and configObject['DNS']['loadresolv'] == 'false':
        fileWriter.write("no-resolv\n")
    if 'loadhosts' in configObject['DNS'] and configObject['DNS']['loadhosts'] == 'false':
        fileWriter.write("no-hosts\n")
    for domain in domains:
        fileWriter.write("address=/{}/{}\n".format(domain,thisIP))
    for nameserver in nameservers:
        fileWriter.write("nameserver={}\n".format(nameserver))
    fileWriter.close()