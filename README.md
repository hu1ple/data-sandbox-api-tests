# 数据沙箱接口测试脚本

当前用例来自《数据沙箱平台-接口测试用例-v1.3.xlsx》，依据《数据沙箱-前端接口清单 v4》和《接口清单-测试参考-20261110》。共 135 条当前用例，沿用 Excel 编号。脚本适用 Python 3.10+，使用标准库。

## 运行

在脚本目录打开 PowerShell。

~~~powershell
python .\run.py --list
python .\run.py --self-test
python .\run.py --show --case TC-V4-SBX04-04
Copy-Item .\fixtures.example.json .\fixtures.local.json
~~~

1. 填写本地配置中的测试 API 地址（包含 /api/v1）、后端契约 profile、运行模式 environment，以及确认就绪的接口编号 ready_interfaces。
2. 在当前终端设置登录账号和口令。A 为分析员，M 为管理员，E 为指定沙箱内的非拥有者 EDITOR，OTHER 为独立对照账号。变量名为 SANDBOX_QA_角色_USER、SANDBOX_QA_角色_PASSWORD。账号和口令从测试环境领取。
3. 用 --show 查看必填夹具，用 --fixture-template 生成所选用例的配置草稿。将每条用例使用的独立数据填写在 cases 下。具体形状见《夹具说明》。
4. 先用 --probe 核对匿名获取 CSRF Token 与匿名访问 /me。含写入尝试的用例需在隔离环境加 --allow-write。重复执行前按测试环境约定恢复夹具，特别是建箱、加成员和注销。

~~~powershell
python .\run.py --probe
python .\run.py --case TC-V4-AUTH03-01 --report .\reports\auth-v4-mock.json
python .\run.py --fixture-template --case TC-V4-SBX04-04
python .\run.py --case TC-V4-SBX04-04 --allow-write --report .\reports\create-replay-v4-mock.json
~~~

支持 --case "TC-V4-SBX06-*"、--layer contract 和 --layer business。报告路径需是新文件，避免覆盖已有证据。报告记录版本配置、运行模式、用例、HTTP 状态、业务码、requestId 和回查路径。报告不记录口令、Cookie、CSRF、请求体、响应体和查询参数。

## 版本和执行门槛

| 配置 profile | 默认账号登录入口 | 默认操作单前缀 | 用法 |
| --- | --- | --- | --- |
| v4-20261110 | /auth/dev-login | /operations | 按 v4 联调契约，environment 选 MOCK 或 REAL。 |
| b20ab05-20261110 | /auth/login | /sandboxes/operations | 用于已确认的 b20ab05 参考包 MOCK。 |

部署说明与参考包的登录写法有差异。请以测试环境实际配置为准，必要时显式填写 login_path 和 operation_path。正式 SSO 的浏览器回调另行验证。参考包的账号密码验证与 v4 正式 SSO 分开记录。

- 预期明确的用例可在接口、账号及夹具就绪后执行。参考包验证只在 b20ab05 配置中运行。
- 待确认和待联调的脚本须先确认环境及验收口径，再将编号加入 confirmed_cases，并按用例配置补齐数据和状态码。ready_interfaces 检查主接口及必要回查接口。
- 当前索引有 126 条提供脚本入口，其中部分需补证或联调条件。7 条浏览器用例和 2 条外部依赖／待定契约用例用 --show 查看步骤、预期和关联事项。
- 脚本的状态为通过、失败、阻塞、需复核、人工验证或脚本／数据错误。需复核表示已执行自动部分，仍应补充页面、审计或底层运行证据。MOCK 和 REAL 分开出具结果。
- 退出码 0 表示所选项均通过，1 表示有失败或脚本／数据错误，2 表示存在待处理项。本地自检使用脚本启动的临时回环模拟服务。

## 新版沙箱的判定

建箱首次为 201，回查沙箱和环境的开通状态。整箱和单环境启停以 202 受理，终态需回查。单环境只验证目标发生变化。注销按 query 中的 version 传入乐观锁，回查已注销历史。加成员直接写入，成员事件通过 member-events 核对。参考包字段、HTTP 或回执仍有差异的部分使用明确的配置，并在报告标出适用版本。
