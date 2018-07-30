# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import hashlib


class Vuln(ABVuln):
    vuln_id = 'Discuz_0017'  # 平台漏洞编号，留空
    name = 'Discuz! X3.0 static/image/common/focus.swf文件存在FlashXss漏洞。'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.XSS  # 漏洞类型
    disclosure_date = '2016-05-12'  # 漏洞公布时间
    desc = '''
        Discuz! x3.0 版本
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-62509'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Discuz!'  # 漏洞应用名称
    product_version = 'Discuz! x3.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0798c41b-bf45-400d-9494-f2b1d7195695'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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
            flash_md5 = "c16a7c6143f098472e52dd13de85527f"
            file_path = "/static/image/common/focus.swf"

            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.get('{target}{payload}'.format(
                target=self.target, payload=file_path))
            md5_value = hashlib.md5(request.text).hexdigest()

            if md5_value in flash_md5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
