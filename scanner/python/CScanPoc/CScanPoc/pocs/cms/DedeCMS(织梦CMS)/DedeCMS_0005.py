# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib
import urllib2
import re


class Vuln(ABVuln):
    vuln_id = 'DedeCMS_0005'  # 平台漏洞编号，留空
    name = '织梦CMS /images/swfupload/swfupload.swf XSS'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2013-11-19'  # 漏洞公布时间
    desc = '''
        DedeCMS 5.7 /images/swfupload/swfupload.swf 文件 movieName 参数没有合适过滤，导致跨站脚本漏洞。
    '''  # 漏洞描述
    ref = 'https://wooyun.shuimugan.com/bug/view?bug_no=038593'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DedeCMS(织梦CMS)'  # 漏洞应用名称
    product_version = '5.7'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '503a2106-a56c-4b73-8bca-8c8707c38719'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            file_path = "/images/swfupload/swfupload.swf"
            verify_url = '{target}'.format(target=self.target)+file_path
            req = urllib2.Request(verify_url)
            content = urllib2.urlopen(req).read()
            md5_value = hashlib.md5(content).hexdigest()

            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
