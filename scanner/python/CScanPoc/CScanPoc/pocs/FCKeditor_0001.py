# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import socket
import urllib2

class Vuln(ABVuln):
    vuln_id = 'FCKeditor_0001' # 平台漏洞编号，留空
    name = 'FCKeditor <= 2.4.3 /upload.asp File Upload'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD # 漏洞类型
    disclosure_date = '2011-03-22'  # 漏洞公布时间
    desc = '''
        fckeditor <= 2.4.3版本, upload.asp文件为黑名单过滤, 可绕过上传。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = 'FCKeditor'  # 漏洞应用名称
    product_version = '<= 2.4.3'  # 漏洞应用版本



class Poc(ABPoc):
    poc_id = 'c1538086-8fe9-4303-a7d8-e50550f86163'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            url_dic = dict()
            version_url = self.target + '/editor/dialog/fck_about.html'
            print version_url
            version_resp = urllib2.urlopen(version_url).read()
            re_version = re.compile('<b>(\d\.\d[\.\d]*).{0,10}<\/b>')
            parr = re_version.findall(version_resp)
            version_number = parr[0]

            if version_number <= '2.4.3':
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
