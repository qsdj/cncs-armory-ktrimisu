# CScan

- [CScanPoc](./CScanPoc): POC 编写框架
- [pocs](./pocs): POC 代码
- [vulns](./vulns): 漏洞说明
- [utility](./utility): 系统功能（资产发现，资产识别等）

## POC 开发说明

POC 现在放在 `pocs` 目录下，和主体框架 `CScanPoc` 代码分离，开发时还是使用 `CScanPoc` 的虚拟环境。

1. 添加环境变量 `PIPENV_VENV_IN_PROJECT=1` （比如在 `~/.bashrc` 中加 `export PIPENV_VENV_IN_PROJECT=1`），这样虚拟环境将被安装到项目根目录 `.venv` 中。
2. 重启 `shell` 或者运行 `source ~/.bashrc`
3. 进入 `CScanPoc` 下运行 `pipenv install --dev`
4. 运行 `pipenv shell`，获得的 shell 可以进行 POC 的执行测试

如果用的是 PyCharm，在开发的时候需要选择解释器为虚拟环境中的解释器 `CScanPoc/CScanPoc/.venv/bin/python`。
