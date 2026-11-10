# 数据沙箱接口测试脚本

测试基线为「后端交付-20261027」及《数据沙箱平台-接口测试用例-20261027.xlsx》。脚本以 Excel 的 TC 编号运行，分为**接口契约**和**业务规则**两层。运行环境为 Python 3.10 或更高版本，只使用 Python 标准库。

## 首次运行

在 PowerShell 进入解压后的脚本目录。

~~~powershell
python .\run.py --self-test
python .\run.py --list
python .\run.py --show --case TC-12-08
~~~

本地自检启动临时回环服务，验证脚本自己的会话、失败断言、重放和记录逻辑。输出仅代表本地脚本自检。

1. 将 fixtures.example.json 复制为 fixtures.local.json。填写测试环境的完整 base_url（含 /api/v1）。把 environment 设为后端环境提供方确认的 MOCK 或 REAL。
2. ready_interfaces 填该环境确认就绪的接口编号，例如模板中的 [1, 2, 3, 4]。当指定了接口清单时，脚本会预检所选用例和已知回查依赖。接口都已就绪时可填写 null。前端内存 Mock 不能直接运行这些 HTTP 脚本。
3. 从测试环境管理员处领取账号，通过进程环境变量提供。SANDBOX_QA_A_USER 和 SANDBOX_QA_A_PASSWORD 对应分析员，SANDBOX_QA_M_USER 和 SANDBOX_QA_M_PASSWORD 对应管理员。按需设置同样命名格式的 M2（第二位管理员）、E（非 OWNER 的 EDITOR）、OTHER（另一沙箱的合法用户）。
4. 用 --show 查看单条用例的必填夹具及操作步骤。可用 --fixture-template 生成选中用例的空配置，再按「夹具说明」填写。写入与拒绝写入的用例须加 --allow-write，并使用隔离的测试环境和独立测试数据。

~~~powershell
Copy-Item .\fixtures.example.json .\fixtures.local.json
python .\run.py --probe --config .\fixtures.local.json
python .\run.py --case TC-01-01 --case TC-02-01 --config .\fixtures.local.json --report .\reports\auth-mock.json
python .\run.py --fixture-template --case TC-12-08 --case TC-30-10
python .\run.py --case TC-12-08 --config .\fixtures.local.json --allow-write --report .\reports\sandbox-mock.json
~~~

--case 支持通配符，例如 --case "TC-30-*"。--layer contract 筛选接口契约，--layer business 筛选业务规则。可以组合 --layer 与 --case。报告文件使用新路径保存，以便区分多次运行。配置和报告可能包含内部地址或业务对象 ID，按团队约定流转。

## 结果判定

| 结果 | 含义 |
| --- | --- |
| 通过 | 本用例的脚本断言全部通过 |
| 失败 | 观察到 HTTP、业务码、响应字段或业务副作用与断言不符 |
| 阻塞 | 缺少服务、账号、夹具、就绪接口或确认后的契约 |
| 需复核 | 已自动检查接口部分，浏览器、外部数据或待确认条件仍需补充证据 |
| 人工验证 | 通过 --show 获取浏览器操作步骤和断言 |
| 脚本或数据错误 | 运行未完成，检查配置结构、夹具与脚本 |

退出码 0 表示所选测试全部通过。1 表示有失败或执行错误。2 表示所选范围仍有阻塞或待复核。报告记录用例、环境、HTTP 状态、业务码、requestId 及回查路径。口令、会话 Cookie、CSRF Token、响应体与查询参数不写入报告。业务环境的实际执行结果需填回 Excel 的「执行结果」和「实际结果及证据」。

配置变更用例会尝试恢复基线，环境启停会尝试恢复初始状态。建箱、申请、审批、违规处理、成员移除等操作会使用实际测试数据。每轮使用独立夹具，并按测试环境约定重置数据。交付接口缺少沙箱删除及通用数据清理操作，清理由测试环境方完成。

## 与本周 MVP 的边界

本套脚本使用 Excel 对应的交付契约。项目的第 2 周工作计划另有一套后端 MVP 口径。两套环境先由项目组确认各自部署版本，再选对应的验收依据。

| 项目 | Excel 交付契约 | 第 2 周后端 MVP 计划 |
| --- | --- | --- |
| 登录 | POST /auth/dev-login | POST /auth/login |
| 当前用户 | roles 与 permissions 数组 | 单字段 role 与 username |
| 建箱 | POST /sandboxes 提交待审批申请 | 仅管理员创建并异步受理 |
| 沙箱删除 | 交付清单无对应接口 | 计划提供 DELETE /sandboxes/{sandboxId} |

上传会话、分片与完成，下载消费入口和有效期，实际清理与导出水印，按 Excel「待确认项」及 --show 的条件安排。用例索引保留了这些场景的前置条件、操作步骤与预期。部分契约分歧已接入参数化脚本，必须填入项目组确认后的口径才能执行。
