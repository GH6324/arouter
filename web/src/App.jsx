import React, { useEffect, useState } from 'react';
import { Layout, Table, Button, Modal, Form, Input, Space, message, Tabs, Card, Descriptions } from 'antd';
import { api } from './api';

const { Header, Content } = Layout;

function NodeList({ onSelect }) {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();

  const load = async () => {
    setLoading(true);
    try {
      setData(await api('GET', '/api/nodes'));
    } catch (e) { message.error(e.message); }
    setLoading(false);
  };
  useEffect(() => { load(); }, []);

  const cols = [
    { title: '名称', dataIndex: 'name' },
    { title: 'WS监听', dataIndex: 'ws_listen' },
    { title: 'Metrics', dataIndex: 'metrics_listen' },
    {
      title: '操作',
      render: (_, r) => (
        <Space>
          <Button size="small" onClick={() => onSelect(r)}>管理</Button>
          <Button size="small" href={`/nodes/${r.id}/config`} target="_blank">配置</Button>
          <Button size="small" href={`/nodes/${r.id}/install.sh`} target="_blank">安装脚本</Button>
        </Space>
      )
    }
  ];

  const onCreate = async () => {
    try {
      const v = await form.validateFields();
      await api('POST', '/api/nodes', v);
      message.success('节点已创建');
      setModalOpen(false);
      form.resetFields();
      load();
    } catch (e) { message.error(e.message); }
  };

  return (
    <Card title="节点列表" extra={<Button type="primary" onClick={()=>setModalOpen(true)}>新建节点</Button>}>
      <Table rowKey="id" dataSource={data} columns={cols} loading={loading} pagination={false}/>
      <Modal open={modalOpen} onCancel={()=>setModalOpen(false)} onOk={onCreate} title="新建节点">
        <Form layout="vertical" form={form} initialValues={{ ws_listen: ":18080", metrics_listen: ":19090" }}>
          <Form.Item name="name" label="节点名称" rules={[{required:true}]}><Input/></Form.Item>
          <Form.Item name="ws_listen" label="WS监听"/><Form.Item name="metrics_listen" label="Metrics监听"/>
        </Form>
      </Modal>
    </Card>
  );
}

function NodeDetail({ node, onBack, refreshList }) {
  const [detail, setDetail] = useState(node);
  const [entryOpen, setEntryOpen] = useState(false);
  const [peerOpen, setPeerOpen] = useState(false);
  const [entryForm] = Form.useForm();
  const [peerForm] = Form.useForm();

  const load = async () => {
    try {
      setDetail(await api('GET', `/api/nodes/${node.id}`));
      refreshList();
    } catch (e) { message.error(e.message); }
  };
  useEffect(() => { load(); }, [node.id]);

  const addEntry = async () => {
    try {
      const v = await entryForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/entries`, v);
      message.success('入口已添加'); setEntryOpen(false); entryForm.resetFields(); load();
    } catch (e) { message.error(e.message); }
  };
  const addPeer = async () => {
    try {
      const v = await peerForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/peers`, v);
      message.success('对端已添加'); setPeerOpen(false); peerForm.resetFields(); load();
    } catch (e) { message.error(e.message); }
  };
  const removeNode = async () => {
    Modal.confirm({
      title: '确认删除节点？',
      onOk: async () => {
        await api('DELETE', `/api/nodes/${node.id}`);
        message.success('已删除'); onBack(); refreshList();
      }
    });
  };

  const entryCols = [
    { title: '监听', dataIndex: 'listen' },
    { title: '协议', dataIndex: 'proto' },
    { title: '出口节点', dataIndex: 'exit' },
    { title: '远端', dataIndex: 'remote' },
  ];
  const peerCols = [
    { title: '名称', dataIndex: 'peer_name' },
    { title: '入口IP', dataIndex: 'entry_ip' },
    { title: '出口IP', dataIndex: 'exit_ip' },
    { title: 'WS地址', dataIndex: 'endpoint' },
  ];

  return (
    <Card title={`节点：${detail.name}`} extra={<Space>
      <Button onClick={onBack}>返回</Button>
      <Button href={`/nodes/${detail.id}/config`} target="_blank">下载配置</Button>
      <Button href={`/nodes/${detail.id}/install.sh`} target="_blank">安装脚本</Button>
      <Button danger onClick={removeNode}>删除</Button>
    </Space>}>
      <Descriptions column={2} bordered size="small">
        <Descriptions.Item label="WS监听">{detail.ws_listen}</Descriptions.Item>
        <Descriptions.Item label="Metrics">{detail.metrics_listen}</Descriptions.Item>
        <Descriptions.Item label="AuthKey">{detail.auth_key}</Descriptions.Item>
        <Descriptions.Item label="UDP TTL">{detail.udp_session_ttl}</Descriptions.Item>
      </Descriptions>
      <Tabs style={{marginTop:16}} items={[
        { key:'entries', label:'入口', children:<>
          <Button type="primary" onClick={()=>setEntryOpen(true)} style={{marginBottom:8}}>添加入口</Button>
          <Table rowKey="id" dataSource={detail.entries||[]} columns={entryCols} pagination={false}/>
        </>},
        { key:'peers', label:'对端', children:<>
          <Button type="primary" onClick={()=>setPeerOpen(true)} style={{marginBottom:8}}>添加对端</Button>
          <Table rowKey="id" dataSource={detail.peers||[]} columns={peerCols} pagination={false}/>
        </>}
      ]}/>

      <Modal open={entryOpen} onCancel={()=>setEntryOpen(false)} onOk={addEntry} title="添加入口">
        <Form layout="vertical" form={entryForm} initialValues={{ proto:"tcp" }}>
          <Form.Item name="listen" label="监听" rules={[{required:true}]}><Input placeholder=":10080"/></Form.Item>
          <Form.Item name="proto" label="协议"><Input/></Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{required:true}]}><Input placeholder="node-b"/></Form.Item>
          <Form.Item name="remote" label="远端" rules={[{required:true}]}><Input placeholder="1.1.1.1:3389"/></Form.Item>
        </Form>
      </Modal>

      <Modal open={peerOpen} onCancel={()=>setPeerOpen(false)} onOk={addPeer} title="添加对端">
        <Form layout="vertical" form={peerForm}>
          <Form.Item name="peer_name" label="对端名称" rules={[{required:true}]}><Input/></Form.Item>
          <Form.Item name="entry_ip" label="入口IP"><Input placeholder="10.0.0.2"/></Form.Item>
          <Form.Item name="exit_ip" label="出口IP"><Input placeholder="10.0.0.1"/></Form.Item>
          <Form.Item name="endpoint" label="WS地址" rules={[{required:true}]}><Input placeholder="wss://host:port/mesh"/></Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

export default function App() {
  const [selected, setSelected] = useState(null);
  const [tick, setTick] = useState(0);
  const refreshList = ()=> setTick(t=>t+1);
  return (
    <Layout style={{minHeight:'100vh'}}>
      <Header style={{color:'#fff', fontSize:18}}>ARouter 控制台</Header>
      <Content style={{padding:24}}>
        {selected
          ? <NodeDetail key={selected.id} node={selected} onBack={()=>setSelected(null)} refreshList={refreshList}/>
          : <NodeList key={tick} onSelect={setSelected}/>
        }
      </Content>
    </Layout>
  );
}
