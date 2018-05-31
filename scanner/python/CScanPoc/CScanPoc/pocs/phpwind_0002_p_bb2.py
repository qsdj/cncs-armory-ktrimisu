# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'phpwind_0002_p_bb2' # 平台漏洞编号，留空
    name = 'phpwind 9.0 /res/js/dev/util_libs/syntaxHihglighter/scripts/clipboard.swf 跨站脚本漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2013-12-27'  # 漏洞公布时间
    desc = '''
        phpwind9.0 res/js/dev/util_libs/syntaxHihglighter/scripts/clipboard.swf文件存在FlashXss漏洞。    
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=038433' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'phpwind'  # 漏洞应用名称
    product_version = '9.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b66bcd8-3a0b-4faa-b407-def816649a53'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            flash_md5 = "e971c772b2df839298a8f8f9451f1eda"
            verify_url = '{target}'.format(target=self.target)+"/res/js/dev/util_libs/syntaxHihglighter/scripts/clipboard.swf"
            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            md5_value = hashlib.md5(content).hexdigest()
            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()