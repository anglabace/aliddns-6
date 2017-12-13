#!/bin/env python
import socket,ssl,struct

def getifaddr(ifname):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode('utf-8'))
        )[20:24])
    except ImportError:
        print('Can not load module fcntl')
        raise

def getip(host,port,cert,key,ca):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.protocol = ssl.PROTOCOL_SSLv23
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.load_verify_locations(ca)
    # ctx.load_verify_locations('E:\\pki\\temp\\cacert.pem')
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    conn.connect((host, port))
    # cert = conn.getpeercert()
    # pprint(cert)
    rsp = b''
    while True:
        buf = conn.recv(1024)
        if len(buf) == 0:
            break
        rsp = rsp + buf
    conn.close()
    return rsp.decode('utf-8')

if __name__ == '__main__':
    ip = getip('proxy.ywh1357.com',1234,'clientcert.pem','clientkey.pem','cacert.pem')
    print(ip)
    try:
        print("get ifaddr: " + getifaddr('wlp3s0'))
    except Exception as e:
        print("getifaddr failed: " + repr(e))
