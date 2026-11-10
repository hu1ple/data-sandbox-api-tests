"""Cases whose uncertain HTTP assertions can run after the team supplies a confirmed oracle."""
from catalog import case
from core import Blocked, check, equal
from auth_sandbox import account
from operations import put_settings


def agreed(c, key, labels):
    value = c.fixture(key)
    if not isinstance(value, dict) or set(value) != set(labels):
        raise Blocked(f'请按已确认契约填写 {key}，所需键为 {list(labels)}')
    if not all(type(x) is int and (x == 200 or 400 <= x < 500) for x in value.values()):
        raise Blocked(f'{key} 的值应为确认后的 HTTP 200 或具体 4xx 状态')
    return value


@case('TC-05-04', writes=True, needs='account_inputs single_name_http',
      remainder='浏览器是否放行单字姓名需另复核。')
def single_char_name(c):
    statuses = agreed(c,'single_name_http',('single','double'))
    check(statuses['double']==200 and statuses['single'] in (200,400),'姓名口径配置不符合正对照')
    for body,name,kind in zip(c.many('account_inputs',2),('王','王晓'),('single','double')):
        account(c,{**body,'displayName':name},valid=statuses[kind]==200)


@case('TC-27-04', writes=True, needs='default_days_http')
def default_days_disagreement(c):
    days = (1,6,91,365)
    outcomes = agreed(c,'default_days_http',map(str,days))
    with c.saved_settings() as baseline:
        for value in days:
            payload = {**baseline,'defaultSandboxDays':value}
            previous = c.get('/settings',role='M')
            if outcomes[str(value)]==200:
                put_settings(c,payload)
            else:
                c.send('PUT','/settings',role='M',body=payload).error(outcomes[str(value)])
                equal(c.get('/settings',role='M'),previous,'拒绝后的配置')
