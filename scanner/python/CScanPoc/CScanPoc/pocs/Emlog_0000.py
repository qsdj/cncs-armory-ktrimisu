# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import hashlib

class Vuln(ABVuln):
    vuln_id = 'Emlog_0000' # 平台漏洞编号，留空
    name = 'Emlog 5.3.1 /include/lib/js/uploadify/uploadify.swf XSS' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-10-26'  # 漏洞公布时间
    desc = '''
        Emlog include/lib/js/uploadify/uploadify.swf文件存在FlashXss漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=069818' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Emlog'  # 漏洞应用名称
    product_version = '5.3.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '94b86fe3-631e-4358-99fb-a2a69a96f691'
    author = '国光'  # POC编写者
    create_date = '2018-05-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            verify_url = '{target}'.format(target=self.target) + "/include/lib/js/uploadify/uploadify.swf"
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