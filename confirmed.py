"""Cases whose uncertain HTTP assertions can run after the team supplies a confirmed oracle."""
from catalog import case
from core import Blocked, check, equal, id_segment as s, snapshot_ids, subset, unique
from auth_sandbox import account, env_action, env_status, rejected_sandbox, sbx_create, audit_has, user
from operations import put_settings
from approvals import approval, decide, decision_body, data_submit
from data_exports import export, export_decide, reject_data


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


@case('TC-12-10', layer='业务', writes=True, needs='sandbox_mismatch_inputs sandbox_mismatch_http')
def environment_mismatch(c):
    outcomes = agreed(c,'sandbox_mismatch_http',('flavor','image'))
    for payload,key in zip(c.many('sandbox_mismatch_inputs',2),('flavor','image')):
        http = outcomes[key]
        if http==200:
            sbx_create(c,payload)
        else:
            rejected_sandbox(c,payload,http)


@case('TC-13-05', layer='业务', writes=True, needs='sandbox_owned environment_running environment_stopped repeated_env_http',
      remainder='下游是否重复执行启停需查操作事件。')
def repeat_env_action(c):
    sid = c.fixture('sandbox_owned')
    outcomes = agreed(c,'repeated_env_http',('START','STOP'))
    for action,state,key in [('START','RUNNING','environment_running'),('STOP','STOPPED','environment_stopped')]:
        eid = c.fixture(key)
        previous = env_status(c,sid,eid)
        equal(previous['status'],state,'初始环境状态')
        response = env_action(c,sid,eid,action)
        if outcomes[action]==200:
            subset(response.success(),{'id':eid})
        else:
            response.error(outcomes[action])
        after = env_status(c,sid,eid)
        equal((after['status'],after.get('operationId')),(state,previous.get('operationId')),'重复启停后的环境与操作')


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


@case('TC-30-13', layer='业务', writes=True, needs='approval_comment_ids approval_comment_http')
def optional_comment_and_self(c):
    variants = ('omitted','empty','self')
    outcomes = agreed(c,'approval_comment_http',variants)
    for aid,label in zip(c.many('approval_comment_ids',len(variants)),variants):
        previous = approval(c,aid,status='PENDING')
        is_self = previous['applicantId']==user(c.get('/me',role='M'))['id']
        equal(is_self,label=='self','审批人与申请人的夹具关系')
        body = decision_body(previous['version'])
        if label=='omitted':
            del body['comment']
        elif label=='empty':
            body['comment']=''
        response = decide(c,aid,body)
        if outcomes[label]==200:
            subset(response.success(),{'approvalId':aid,'status':'APPROVED'})
            approval(c,aid,status='APPROVED')
        else:
            response.error(outcomes[label])
            equal(approval(c,aid,status='PENDING'),previous,'原审批')


@case('TC-34-06', writes=True, needs='data_inputs data_min_http',
      remainder='按需对照浏览器实际表单校验。')
def minimum_data_description(c):
    variants = [(key,value) for key in ('dataSource','purpose') for value in (1,9,10)]
    names = [f'{k}_{n}' for k,n in variants]
    outcomes = agreed(c,'data_min_http',names)
    for body,(key,length),label in zip(c.many('data_inputs',len(variants)),variants,names):
        payload = {**body,key:'测'*length}
        if length==10 and outcomes[label]!=200:
            raise Blocked('10 字对照样本须按交付共同边界接受')
        if outcomes[label]==200:
            data_submit(c,payload)
        elif outcomes[label]==400:
            reject_data(c,payload)
        else:
            raise Blocked('字段校验的确认配置应为 HTTP 200 或 400')


@case('TC-41-01', layer='业务', writes=True, needs='grant_cases grant_http',
      remainder='地址、TTL 和签发按钮需按 G-09 复核。')
def grant_state_matrix(c):
    combos = ('approved_unused','approved_none','approved_expired','pending_approval','delivered')
    outcomes = agreed(c,'grant_http',combos)
    if outcomes['pending_approval']==200:
        raise Blocked('待审批样本不应取得可用下载凭证')
    cases = c.fixture('grant_cases')
    for label in combos:
        sample = cases[label]
        target = sample['id']
        previous = export(c,target)
        subset(previous,sample,'凭证状态夹具')
        response = c.send('POST','/exports/'+s(target)+'/download-grants')
        if outcomes[label]==200:
            subset(response.success(),{'id':target,'grantStatus':'UNUSED'})
            subset(export(c,target),{'grantStatus':'UNUSED'})
            audit_has(c,target,user(c.get('/me'))['displayName'])
        else:
            response.error(outcomes[label])
            equal(export(c,target),previous,'拒绝签发后的出箱记录')


def confirmed_export_case(c, action, outcome):
    target = c.fixture('export_pending')
    previous = export(c,target,role='M',status='PENDING_APPROVAL')
    body = {**c.fixture('confirmed_export_payload'),'decision':action}
    body.pop('_confirmed',None)
    response = export_decide(c,target,body,'M').success()
    subset(response,{'id':target,'status':outcome,'resultId':previous['resultId']})
    current = export(c,target,role='M')
    subset(current,{'resultId':previous['resultId']})
    if outcome=='REJECTED':
        subset(current,{'status':'REJECTED'})
        check(current.get('grantStatus')!='UNUSED','驳回仍有可用下载凭证')
    else:
        check(current['status'] in ('APPROVED','DELIVERING','DELIVERED','DELIVERY_FAILED'),'批准未进入批准或交付状态')
    audit_has(c,target,user(c.get('/me',role='M'))['displayName'])


@case('TC-43-01', layer='业务', writes=True, needs='export_pending confirmed_export_payload approved_reply_state',
      remainder='下游交付事件与状态按已确认状态口径复核。')
def approve_export(c):
    reply_state = c.fixture('approved_reply_state')
    if reply_state not in ('APPROVED','DELIVERING','DELIVERED'):
        raise Blocked('请配置联调确认后的批准响应状态')
    confirmed_export_case(c,'APPROVE',reply_state)


@case('TC-43-02', layer='业务', writes=True, needs='export_pending confirmed_export_payload',
      remainder='驳回后无交付任务需查下游事件。')
def reject_export(c):
    confirmed_export_case(c,'REJECT','REJECTED')


@case('TC-43-04', layer='业务', writes=True, needs='export_rejected confirmed_export_payload')
def repeat_export_decision(c):
    target = c.fixture('export_rejected')
    before = export(c,target,role='M',status='REJECTED')
    payload = {k:v for k,v in c.fixture('confirmed_export_payload').items() if k!='_confirmed'}
    export_decide(c,target,{**payload,'decision':'APPROVE'},'M').error(409,'EXPORT_ALREADY_DECIDED')
    equal(export(c,target,role='M',status='REJECTED'),before,'已处理出箱单')


@case('TC-43-06', layer='业务', writes=True, needs='export_review_checks')
def export_review_and_version(c):
    items = c.fixture('export_review_checks')
    if set(items) != {'under_review','old_version'}:
        raise Blocked('export_review_checks 须提供已确认的 under_review 与 old_version 两组口径')
    for label,fixture in items.items():
        target = fixture['id']
        before = export(c,target,role='M',status='PENDING_REVIEW' if label=='under_review' else 'PENDING_APPROVAL')
        http = fixture['http']
        if type(http) is not int or not (http==200 or 400<=http<500):
            raise Blocked('请输入确认后的响应 HTTP')
        response = export_decide(c,target,fixture['body'],'M')
        if http==200:
            subset(response.success(),{'id':target,'status':fixture['status']})
        else:
            response.error(http,fixture.get('code'))
            equal(export(c,target,role='M'),before,'出箱审批拒绝后记录')
