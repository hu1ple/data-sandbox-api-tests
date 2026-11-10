"""v4 task, ingestion, export, audit, integration and platform cases."""
from catalog import case
from core import Blocked, absent, check, equal, field, id_segment as s, row, snapshot_ids, subset, unique
from data_exports import export_ids


def expected_http(sample,key='http'):
    status=sample.get(key)
    if type(status) is not int or status not in (200,201,202):
        raise Blocked(f'{key} 须填已确认的成功 HTTP 状态（200、201、202）')
    return status


def filtered(c,path,sample,*,role='A',must=()):
    query=sample['query']
    check(all(name in query for name in must),'夹具缺少指定筛选参数')
    entries=c.all(path,role=role,query=query,page_size=1)
    equal(snapshot_ids(entries),snapshot_ids(sample['items']),'过滤后精确记录集合')
    for item in sample['items']:
        subset(row(entries,'id',item['id']),item)
    return entries


def detail_pair(c, path, samples, *, role='A', required=()):
    for sample in samples:
        item=c.get(path+s(sample['id']),role=role)
        subset(item,sample)
        for key,kind in required:
            field(item,key,kind)


@case('TC-V4-TSK01-01', needs='task_filters')
def tasks_by_dates(c):
    filtered(c,'/tasks',c.fixture('task_filters'),must=('sandboxId','type','startDate','endDate'))


@case('TC-V4-TSK02-01', needs='task_detail_samples')
def task_details(c):
    samples=c.many('task_detail_samples',2)
    for expected in samples:
        data=c.get('/tasks/'+s(expected['id']))
        subset(data,expected)
        field(data,'logs',list)
        equal(len(field(data,'phases',list)),3,'任务三环节')
        field(data,'params',dict)


@case('TC-V4-TSK03-01', layer='业务', writes=True, needs='task_submission_samples', requires='TSK01 TSK02',
      remainder='调度器实际执行次数和外部引擎结果另以环境证据核对。')
def tasks_submit(c):
    sample=c.fixture('task_submission_samples')
    http=expected_http(sample)
    replay_http=expected_http(sample,'replayHttp')
    inputs=sample['inputs']
    equal(sorted(x['type'] for x in inputs),['PYTHON','R','SQL'],'测试任务类型')
    c.client('OTHER')
    for body in inputs:
        before=snapshot_ids(c.all('/tasks',query={'sandboxId':body['sandboxId'],'keyword':body['name']}))
        key=unique()
        first=c.send('POST','/tasks',body=body,key=key).success(status=http)
        tid=field(first,'id',str)
        detail=c.get('/tasks/'+s(tid))
        subset(detail,{k:body[k] for k in ('sandboxId','type','params')})
        if body['type']=='PYTHON':
            replay=c.send('POST','/tasks',body=body,key=key).success(status=replay_http)
            equal(replay['id'],tid,'任务重放 ID')
        result=c.all('/tasks',query={'sandboxId':body['sandboxId'],'keyword':body['name']})
        equal(snapshot_ids(result),sorted([*before,tid]),'任务实际创建次数')
    denied=sample['denied']
    scope={'sandboxId':denied['sandboxId'],'keyword':denied['name']}
    before=snapshot_ids(c.all('/tasks',role='OTHER',query=scope))
    c.send('POST','/tasks',body=denied,key=unique()).error((403,404))
    equal(snapshot_ids(c.all('/tasks',role='OTHER',query=scope)),before,'他人沙箱任务没有新增')


def task(c,tid):
    return c.get('/tasks/'+s(tid))


@case('TC-V4-TSK04-01', layer='业务', writes=True, needs='task_cancel_fixture', requires='TSK02',
      remainder='外部执行器取消和无额外产出需要联调事件补证。')
def cancel_task(c):
    fixture=c.fixture('task_cancel_fixture')
    http=expected_http(fixture)
    tid=fixture['id']
    original=task(c,tid)
    equal(original['status'],fixture['initialStatus'],'可取消任务初始状态')
    c.send('POST','/tasks/'+s(tid)+'/cancel').success(status=http)
    item=c.poll(lambda:task(c,tid),lambda obj:obj.get('status')==fixture['terminalStatus'],'任务取消')
    equal(item.get('resultId'),original.get('resultId'),'取消后无新增产出')
    terminal=fixture['terminalId']
    before=task(c,terminal)
    c.send('POST','/tasks/'+s(terminal)+'/cancel').error(fixture['terminalError'])
    equal(task(c,terminal),before,'终态任务拒绝取消后的快照')


def new_task(c, fixture, action):
    tid=fixture['id']
    http=expected_http(fixture)
    before=task(c,tid)
    equal(before['status'],fixture['sourceStatus'],'原任务状态')
    returned=c.send('POST','/tasks/'+s(tid)+'/'+action).success(status=http)
    new_id=field(returned,'id',str)
    check(new_id!=tid,'重复执行使用了原任务 ID')
    fresh=task(c,new_id)
    subset(fresh,{key:before[key] for key in ('sandboxId','type','params')})
    equal(task(c,tid),before,'原任务及输出关联')
    return before


@case('TC-V4-TSK05-01', layer='业务', writes=True, needs='task_retry_fixture', requires='TSK02')
def retry_task(c):
    fixture=c.fixture('task_retry_fixture')
    new_task(c,fixture,'retry')
    control=fixture['controlId']
    before=task(c,control)
    c.send('POST','/tasks/'+s(control)+'/retry').error(fixture['controlError'])
    equal(task(c,control),before,'成功任务不通过失败重试修改')


@case('TC-V4-TSK06-01', layer='业务', writes=True, needs='task_rerun_fixture', requires='TSK02')
def rerun_task(c):
    new_task(c,c.fixture('task_rerun_fixture'),'rerun')


@case('TC-V4-TSK07-01', needs='task_template_samples', remainder='任务表单选项与 templateId 由浏览器复核。')
def templates(c):
    expected=c.many('task_template_samples',2)
    data=field(c.get('/task-templates'),'items',list)
    for sample in expected:
        subset(row(data,'id',sample['id']),sample)


@case('TC-V4-DAT02-01', remainder='数据源选项的前端展示需浏览器复核。')
def reference_sources_empty(c):
    equal(field(c.get('/data-sources'),'items',list),[],'参考包数据源目录')


@case('TC-V4-DAT04-01', needs='ingestion_filter_sample')
def filter_ingestion(c):
    filtered(c,'/ingestions',c.fixture('ingestion_filter_sample'),
             must=('projectId','sandboxId','environmentId','status'))


@case('TC-V4-DAT05-01', layer='业务', writes=True, needs='ingestion_create_sample',
      requires='DAT04 DAT06 DAT12', remainder='重放后的实际入箱行数由下游数据或运行记录复核。')
def submit_ingestion(c):
    sample=c.fixture('ingestion_create_sample')
    body=sample['body']
    http,replay=expected_http(sample),expected_http(sample,'replayHttp')
    c.client('OTHER')
    query={'environmentId':body['environmentId'],'sandboxId':body['sandboxId']}
    before=snapshot_ids(c.all('/ingestions',query=query))
    key=unique()
    first=c.send('POST','/ingestions',body=body,key=key).success(status=http)
    tid=field(first,'id',str)
    again=c.send('POST','/ingestions',body=body,key=key).success(status=replay)
    equal(field(again,'id',str),tid,'入箱幂等 ID')
    subset(c.get('/ingestions/'+s(tid)),query)
    equal(snapshot_ids(c.all('/ingestions',query=query)),sorted([*before,tid]),'批次写入次数')
    denied=sample['denied']
    other={'environmentId':denied['environmentId']}
    previous=snapshot_ids(c.all('/ingestions',role='OTHER',query=other))
    existing=snapshot_ids(c.all('/ingest/data',role='OTHER',query=other))
    c.send('POST','/ingestions',body=denied,key=unique()).error((400,403,404,422))
    equal(snapshot_ids(c.all('/ingestions',role='OTHER',query=other)),previous,'他人批次未变')
    equal(snapshot_ids(c.all('/ingest/data',role='OTHER',query=other)),existing,'他人数据未变')


@case('TC-V4-DAT06-01', needs='ingestion_detail_samples')
def ingestion_details(c):
    detail_pair(c,'/ingestions/',c.many('ingestion_detail_samples',2))


@case('TC-V4-DAT08-01', needs='sampling_filter_sample')
def sampling_list(c):
    filtered(c,'/sampling-tasks',c.fixture('sampling_filter_sample'),must=('sourceType','status'))


@case('TC-V4-DAT09-01', writes=True, needs='sampling_submit_sample', requires='DAT08',
      remainder='抽样算法、比例误差和实际输出需用固定样本另验证。')
def submit_sampling(c):
    sample=c.fixture('sampling_submit_sample')
    body=sample['body']
    http,replay=expected_http(sample),expected_http(sample,'replayHttp')
    filters={'keyword':body['name']}
    baseline=snapshot_ids(c.all('/sampling-tasks',query=filters))
    key=unique()
    first=c.send('POST','/sampling-tasks',body=body,key=key).success(status=http)
    tid=field(first,'id',str)
    repeat=c.send('POST','/sampling-tasks',body=body,key=key).success(status=replay)
    equal(repeat['id'],tid,'抽样重放 ID')
    expected=sorted([*baseline,tid])
    for invalid in sample['invalid']:
        c.send('POST','/sampling-tasks',body={**body,**invalid},key=unique()).error(sample['invalidHttp'])
        equal(snapshot_ids(c.all('/sampling-tasks',query=filters)),expected,'抽样任务仅新增一条')


@case('TC-V4-DAT10-01', needs='pipeline_expected')
def read_pipeline(c):
    subset(c.get('/ingest-pipeline/config',role='M'),c.fixture('pipeline_expected'))


@case('TC-V4-DAT11-01', layer='业务', writes=True, needs='pipeline_update', requires='DAT10')
def update_pipeline(c):
    path='/ingest-pipeline/config'
    sample=c.fixture('pipeline_update')
    http=expected_http(sample)
    c.client('A')
    before=c.get(path,role='M')
    baseline={k:before[k] for k in sample['writableKeys']}
    changed={**baseline,**sample['changes']}
    check(changed!=baseline,'必须改变一个配置值')
    try:
        subset(c.send('PUT',path,role='M',body=changed).success(status=http),changed)
        subset(c.client('M',fresh=True).request('GET',path).success(),changed)
        c.send('PUT',path,body=baseline).error(403)
        subset(c.get(path,role='M'),changed)
    finally:
        if any(c.get(path,role='M').get(k)!=v for k,v in baseline.items()):
            c.send('PUT',path,role='M',body=baseline).success(status=http)
            subset(c.get(path,role='M'),baseline)


@case('TC-V4-DAT12-01', needs='dataset_filter_sample', remainder='用浏览器复核实际列表请求路径。')
def datasets(c):
    filtered(c,'/ingest/data',c.fixture('dataset_filter_sample'),must=('sandboxId','environmentId','batchId'))


@case('TC-V4-DAT13-01', layer='业务', needs='dataset_detail_sample dataset_other')
def dataset_visibility(c):
    sample=c.fixture('dataset_detail_sample')
    subset(c.get('/ingest/data/'+s(sample['id'])),sample)
    foreign='/ingest/data/'+s(c.fixture('dataset_other'))
    c.get(foreign,role='OTHER')
    c.send('GET',foreign).error((403,404))


@case('TC-V4-DAT14-01', layer='业务', writes=True, needs='dataset_action_samples dataset_forbidden',
      requires='DAT13', remainder='删除取消和二次确认必须用浏览器抓包复核。')
def dataset_actions(c):
    samples=c.many('dataset_action_samples',3)
    c.client('E')
    protected='/ingest/data/'+s(c.fixture('dataset_forbidden'))
    previous=c.get(protected)
    c.send('POST',protected+'/actions',role='E',body={'action':'DELETE'}).error((403,404))
    equal(c.get(protected),previous,'拒绝删除后数据集快照')
    for sample,action in zip(samples,('OFFLINE','ARCHIVE','DELETE')):
        path='/ingest/data/'+s(sample['id'])
        c.get(path)
        c.send('POST',path+'/actions',body={'action':action}).success(status=expected_http(sample))
        if action=='DELETE' and sample.get('detailHttp')==404:
            def removed():
                return c.send('GET',path)
            after=c.poll(removed,lambda item:item.status==404,'删除后详情不可查')
            after.error(404)
        else:
            after=c.poll(lambda:c.get(path),lambda item:item.get('status')==sample['status'],'数据集状态')
            equal(after['id'],sample['id'],'操作数据集 ID')


@case('TC-V4-DAT15-01', needs='capacity_samples')
def capacity(c):
    for expected in c.many('capacity_samples',2):
        items=field(c.get('/ingest/capacity'),'items',list)
        subset(row(items,'sandboxId',expected['sandboxId']),expected)


@case('TC-V4-EXP01-01', layer='业务', needs='result_review_samples',
      requires='TSK02')
def results_by_review(c):
    samples=c.fixture('result_review_samples')
    for state in ('PENDING','PASSED','BLOCKED'):
        sample=samples[state]
        equal(sample['query']['reviewStatus'],state,'审核筛选值')
        filtered(c,'/results',sample,must=('sandboxId','reviewStatus'))
        for expected in sample['items']:
            task_id=sample['taskIds'][expected['id']]
            subset(task(c,task_id),{'resultId':expected['id'],'resultReviewStatus':state})


@case('TC-V4-EXP02-01', layer='业务', needs='result_preview_sample result_other preview_redaction_samples')
def preview_result(c):
    sample=c.fixture('result_preview_sample')
    data=c.get('/results/'+s(sample['id'])+'/preview')
    subset(data,sample['expected'])
    tokens=c.fixture('preview_redaction_samples')
    def has_token(obj, marker):
        if isinstance(obj,dict):
            return any(has_token(v,marker) for v in obj.values())
        if isinstance(obj,list):
            return any(has_token(v,marker) for v in obj)
        return isinstance(obj,str) and marker in obj
    check(not any(has_token(data,marker) for marker in tokens),'预览包含明文测试标识')
    c.send('GET','/results/'+s(c.fixture('result_other'))+'/preview').error((403,404))


@case('TC-V4-EXP03-01', layer='业务', writes=True, needs='export_review_fixture', requires='EXP04 EXP05',
      remainder='页面发起出箱按钮的隐藏状态按联调版浏览器另测。')
def only_passed_export(c):
    sample=c.fixture('export_review_fixture')
    http,replay=expected_http(sample),expected_http(sample,'replayHttp')
    for state in ('PASSED','PENDING','BLOCKED'):
        body=sample[state]
        before=export_ids(c,body['resultId'])
        key=unique()
        response=c.send('POST','/exports',body=body,key=key)
        if state=='PASSED':
            first=response.success(status=http)
            first_id=field(first,'exportId',str)
            field(first,'approvalId',str)
            repeat=c.send('POST','/exports',body=body,key=key).success(status=replay)
            equal(repeat['exportId'],first_id,'出箱申请重放 ID')
            subset(c.get('/exports/'+s(first_id)),{'id':first_id,'resultId':body['resultId']})
            equal(export_ids(c,body['resultId']),sorted([*before,first_id]),'同一结果新增出箱数')
        else:
            response.error(sample['denialHttp'])
            equal(export_ids(c,body['resultId']),before,'审核未通过时无出箱记录')


@case('TC-V4-EXP04-01', needs='export_filter_sample')
def export_statuses(c):
    sample=c.fixture('export_filter_sample')
    equal(set(sample['query']['statuses'].split(',')),{'PENDING_REVIEW','DELIVERED'},'多状态查询参数')
    entries=filtered(c,'/exports',sample,must=('statuses',))
    check(all(e['status'] in ('PENDING_REVIEW','DELIVERED') for e in entries),'出箱记录超出状态范围')


@case('TC-V4-EXP05-01', layer='业务', needs='export_detail_sample export_other')
def export_visibility(c):
    sample=c.fixture('export_detail_sample')
    subset(c.get('/exports/'+s(sample['id'])),sample)
    foreign='/exports/'+s(c.fixture('export_other'))
    c.get(foreign,role='OTHER')
    c.send('GET',foreign).error((403,404))


@case('TC-V4-EXP06-01', layer='业务', writes=True, needs='grant_fixture', requires='EXP05',
      remainder='凭证的有效期及消费行为由已确认下载契约覆盖。')
def grant_once(c):
    sample=c.fixture('grant_fixture')
    good,bad=sample['id'],sample['deniedId']
    previous=c.get('/exports/'+s(bad))
    c.send('POST','/exports/'+s(bad)+'/download-grants').error(sample['denialHttp'])
    equal(c.get('/exports/'+s(bad)),previous,'未签发对象保持')
    response=c.send('POST','/exports/'+s(good)+'/download-grants').success(status=expected_http(sample))
    subset(response,sample['expected'])
    subset(c.get('/exports/'+s(good)),sample['detailExpected'])


@case('TC-V4-SEC01-01', needs='audit_categories')
def audit_categories(c):
    samples=c.fixture('audit_categories')
    for name in ('OPERATION','DATA','TASK','RESULT'):
        sample=samples[name]
        equal(sample['query']['category'],name,'审计类别')
        entries=filtered(c,'/audit-logs',sample,role='M',must=('category',))
        check(all(item.get('category')==name for item in entries),'分类返回错误')
        for expected in sample['items']:
            check(any(key.startswith('evidence') for key in expected),'审计样本须配置待核对的存证字段')


@case('TC-V4-INT03-01', needs='dead_letter_sample')
def dead_letters(c):
    fixture=c.fixture('dead_letter_sample')
    items=field(c.get('/integrations/dead-letters',role='M'),'items',list)
    subset(row(items,'id',fixture['failed']['id']),fixture['failed'])
    absent(items,'id',fixture['recoveredId'])


@case('TC-V4-INT04-01', layer='业务', writes=True, needs='project_link_sample')
def project_links(c):
    path='/project-sandbox-links'
    sample=c.fixture('project_link_sample')
    body=sample['body']
    created_http,released_http=expected_http(sample),expected_http(sample,'releaseHttp')
    query={'projectId':body['projectId']}
    before=snapshot_ids(c.all(path,role='M',query=query))
    item=c.send('POST',path,role='M',body=body,key=unique()).success(status=created_http)
    mid=field(item,'id',str)
    actual=c.all(path,role='M',query=query)
    equal(snapshot_ids(actual),sorted([*before,mid]),'新增项目沙箱关联')
    subset(row(actual,'id',mid),{'projectId':body['projectId'],'sandboxId':body['sandboxId']})
    released=c.send('POST',path+'/'+s(mid)+'/release',role='M').success(status=released_http)
    subset(released,sample['released'])
    subset(row(c.all(path,role='M',query=query),'id',mid),sample['released'])


@case('TC-V4-INT05-01', layer='业务', writes=True, needs='identity_sync_sample')
def sync_identity(c):
    path='/integrations/identity'
    sample=c.fixture('identity_sync_sample')
    subset(c.get(path,role='M'),sample['summary'])
    query=sample['query']
    before=c.all(path+'/triples',role='M',query=query)
    absent(before,'id',sample['added']['id'])
    result=c.send('POST',path+'/sync',role='M').success(status=expected_http(sample))
    subset(result,sample['sync'])
    subset(row(c.all(path+'/triples',role='M',query=query),'id',sample['added']['id']),sample['added'])


@case('TC-V4-INT06-01', layer='业务', writes=True, needs='authorization_sync_sample')
def resync_authorization(c):
    sample=c.fixture('authorization_sync_sample')
    path='/integrations/authorization-sync'
    query=sample['query']
    before=c.all(path,role='M',query=query)
    target=sample['id']
    row(before,'id',target)
    c.send('POST',path+'/'+s(target)+'/resync',role='M').success(status=expected_http(sample))
    after=c.all(path,role='M',query=query)
    subset(row(after,'id',target),sample['expected'])
    equal({x['id']:x for x in after if x['id']!=target},
          {x['id']:x for x in before if x['id']!=target},'非目标授权同步状态')


@case('TC-V4-INT07-01', layer='业务', writes=True, needs='result_delivery_sample',
      remainder='下游实际投递次数由联调日志复核。')
def retry_result_delivery(c):
    sample=c.fixture('result_delivery_sample')
    path='/integrations/result-deliveries'
    query=sample['query']
    before=c.all(path,role='M',query=query)
    target=sample['id']
    subset(row(before,'id',target),sample['before'])
    c.send('POST',path+'/'+s(target)+'/retry',role='M').success(status=expected_http(sample))
    def read():
        return row(c.all(path,role='M',query=query),'id',target)
    after=c.poll(read,lambda item:all(item.get(k)==v for k,v in sample['expected'].items()),'回传到确认终态')
    subset(after,sample['expected'])


@case('TC-V4-INT08-01', layer='业务', writes=True, needs='visibility_matrix_sample', requires='SBX01')
def visibility_matrix(c):
    sample=c.fixture('visibility_matrix_sample')
    path='/visibility-matrix'
    original=field(c.get(path,role='M'),'items',list)
    equal(len({entry[sample['roleField']] for entry in original}),6,'可见矩阵角色数')
    changes=sample['items']
    check(changes!=original,'须提供单一角色变更后的矩阵')
    expected=sample['expectByRole']
    for role in expected:
        c.client(role)
    http=expected_http(sample)
    try:
        c.send('PUT',path,role='M',body={'items':changes}).success(status=http)
        equal(field(c.get(path,role='M'),'items',list),changes,'矩阵读回')
        for role,ids in expected.items():
            equal(snapshot_ids(c.all('/sandboxes',role=role,query=sample['query'])),
                  sorted(ids),'角色可见范围')
    finally:
        c.send('PUT',path,role='M',body={'items':original}).success(status=http)
        equal(field(c.get(path,role='M'),'items',list),original,'还原可见矩阵')


@case('TC-V4-PLT02-01', needs='catalog_filter_samples')
def catalog_filters(c):
    for sample in c.many('catalog_filter_samples',3):
        filtered(c,'/catalog/resources',sample,must=('type','keyword'))


@case('TC-V4-PLT03-01', needs='metrics_sample metrics_detail_path')
def usage_metrics(c):
    sample=c.fixture('metrics_sample')
    path=c.confirmation('metrics_detail_path',('/usage/sandboxes','/metrics/usage/sandboxes'))
    summary=field(c.get('/metrics/usage'),'items',list)
    equal(summary,sample['summary'],'月汇总')
    items=filtered(c,path,sample['details'])
    check(items or not sample['details']['items'],'没有返回预置明细')
