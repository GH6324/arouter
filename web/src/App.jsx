import React, { useEffect, useMemo, useState } from 'react';
import { AutoSizer, Grid as VirtualGrid, WindowScroller } from 'react-virtualized';
import {
  Layout,
  Table,
  Button,
  Modal,
  Form,
  Input,
  Space,
  message,
  Tabs,
  Card,
  Descriptions,
  Select,
  Tag,
  Divider,
  Tooltip,
  Row,
  Col,
  Statistic,
  Progress,
  Drawer,
  Menu,
  Switch,
  Grid,
  Typography,
  Badge,
} from 'antd';
import { api, API_BASE, joinUrl } from './api';
import './App.css';

const { Header, Content, Sider } = Layout;
const { useBreakpoint } = Grid;
const { Text } = Typography;
const ONLINE_WINDOW_MS = 15000;

const GearIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M19.4 13a7.2 7.2 0 0 0 .05-1 7.2 7.2 0 0 0-.05-1l2.03-1.58a.5.5 0 0 0 .12-.64l-1.92-3.32a.5.5 0 0 0-.6-.22l-2.4.96a7.4 7.4 0 0 0-1.73-1l-.36-2.54a.5.5 0 0 0-.5-.42h-3.84a.5.5 0 0 0-.5.42l-.36 2.54a7.4 7.4 0 0 0-1.73 1l-2.4-.96a.5.5 0 0 0-.6.22L2.45 7.78a.5.5 0 0 0 .12.64L4.6 10a7.2 7.2 0 0 0-.05 1 7.2 7.2 0 0 0 .05 1l-2.03 1.58a.5.5 0 0 0-.12.64l1.92 3.32a.5.5 0 0 0 .6.22l2.4-.96a7.4 7.4 0 0 0 1.73 1l.36 2.54a.5.5 0 0 0 .5.42h3.84a.5.5 0 0 0 .5-.42l.36-2.54a7.4 7.4 0 0 0 1.73-1l2.4.96a.5.5 0 0 0 .6-.22l1.92-3.32a.5.5 0 0 0-.12-.64L19.4 13Z"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.4" />
  </svg>
);

const UserIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <circle cx="12" cy="8" r="4" stroke="currentColor" strokeWidth="1.4" />
    <path
      d="M4 20c1.8-3.6 5-5 8-5s6.2 1.4 8 5"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
    />
  </svg>
);

const PowerIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 3v8"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
    />
    <path
      d="M6.3 6.3a8 8 0 1 0 11.4 0"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
    />
  </svg>
);

const GithubIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true">
    <path
      d="M12 2.5a9.5 9.5 0 0 0-3 18.5c.5.1.7-.2.7-.5v-1.8c-2.8.6-3.4-1.2-3.4-1.2-.4-1.1-1-1.4-1-1.4-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.5 2.4 1 3 0 .1-.7.4-1 .7-1.3-2.2-.2-4.4-1.1-4.4-4.8 0-1 .4-1.9 1-2.6-.1-.2-.4-1.2.1-2.4 0 0 .8-.2 2.6 1a8.7 8.7 0 0 1 4.8 0c1.8-1.2 2.6-1 2.6-1 .5 1.2.2 2.2.1 2.4.7.7 1 1.6 1 2.6 0 3.7-2.2 4.6-4.4 4.8.4.3.7.8.7 1.7v2.6c0 .3.2.6.7.5A9.5 9.5 0 0 0 12 2.5Z"
      stroke="currentColor"
      strokeWidth="1.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
  </svg>
);

const formatBytes = (n = 0) => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = n;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val.toFixed(1)} ${units[idx]}`;
};
const formatUptime = (sec = 0) => {
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}天${h}小时`;
  if (h > 0) return `${h}小时${m}分`;
  return `${m}分`;
};
const isOnline = (ts) => {
  if (!ts) return false;
  const last = new Date(ts).getTime();
  if (!last) return false;
  return Date.now() - last <= ONLINE_WINDOW_MS;
};
const loadColor = (percent = 0) => {
  if (percent >= 85) return '#ef4444';
  if (percent >= 70) return '#f59e0b';
  if (percent >= 50) return { '0%': '#0a66ff', '100%': '#22c55e' };
  return '#0a66ff';
};

function NodeList({ onSelect, onShowInstall, refreshSignal }) {
  const [data, setData] = useState([]);
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();
  const screens = useBreakpoint();
  const [isScrolling, setIsScrolling] = useState(false);

  const load = async () => {
    if (document.hidden || isScrolling) return;
    try {
      const list = await api('GET', '/api/nodes');
      const sorted = [...(list || [])].sort((a, b) => (a.name || '').localeCompare(b.name || ''));
      setData(sorted);
    } catch (e) {
      message.error(e.message);
    }
  };
  useEffect(() => {
    load();
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    if (refreshSignal > 0) load();
  }, [refreshSignal]);

  useEffect(() => {
    let t = 0;
    const onScroll = () => {
      setIsScrolling(true);
      if (t) window.clearTimeout(t);
      t = window.setTimeout(() => setIsScrolling(false), 200);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      if (t) window.clearTimeout(t);
    };
  }, []);

  const columns = useMemo(() => {
    if (screens.xl) return 4;
    if (screens.lg) return 3;
    if (screens.md) return 2;
    if (screens.sm) return 2;
    return 1;
  }, [screens]);

  const rowHeight = 340;
  const gutter = 16;

  const summary = useMemo(() => {
    const total = data.length;
    const online = data.filter((n) => isOnline(n.last_seen_at)).length;
    const totalIn = data.reduce((sum, n) => sum + (n.net_in_bytes || 0), 0);
    const totalOut = data.reduce((sum, n) => sum + (n.net_out_bytes || 0), 0);
    const totalMem = data.reduce((sum, n) => sum + (n.mem_total_bytes || 0), 0);
    const usedMem = data.reduce((sum, n) => sum + (n.mem_used_bytes || 0), 0);
    const avgCpu = total
      ? data.reduce((sum, n) => sum + (n.cpu_usage || 0), 0) / total
      : 0;
    return { total, online, totalIn, totalOut, totalMem, usedMem, avgCpu };
  }, [data]);

  const onCreate = async () => {
    try {
      const v = await form.validateFields();
      await api('POST', '/api/nodes', v);
      message.success('节点已创建');
      setModalOpen(false);
      form.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        className="page-card"
        title="节点概览"
        extra={<Button type="primary" onClick={() => setModalOpen(true)}>新建节点</Button>}
      >
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={8} lg={4}>
            <Statistic title="节点总数" value={summary.total} />
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Statistic title="在线" value={summary.online} suffix={`/ ${summary.total}`} />
          </Col>
          <Col xs={12} sm={8} lg={4}>
            <Statistic title="平均CPU" value={summary.avgCpu.toFixed(1)} suffix="%" />
          </Col>
          <Col xs={12} sm={8} lg={6}>
            <Statistic
              title="内存" 
              value={`${formatBytes(summary.usedMem)} / ${formatBytes(summary.totalMem)}`}
            />
          </Col>
          <Col xs={12} sm={8} lg={3}>
            <Statistic title="上行" value={formatBytes(summary.totalOut)} />
          </Col>
          <Col xs={12} sm={8} lg={3}>
            <Statistic title="下行" value={formatBytes(summary.totalIn)} />
          </Col>
        </Row>
      </Card>
      <Card className="page-card" title="节点列表">
        <div className="node-list-viewport">
          <WindowScroller scrollElement={window}>
            {({ height, isScrolling, onChildScroll, scrollTop }) => (
              <AutoSizer disableHeight>
                {({ width }) => {
                  const columnWidth = Math.max(260, Math.floor((width - gutter * (columns - 1)) / columns));
                  const rowCount = Math.ceil(data.length / columns) || 1;
                  return (
                    <VirtualGrid
                      autoHeight
                      height={height}
                      width={width}
                      rowHeight={rowHeight}
                      columnWidth={columnWidth + gutter}
                      rowCount={rowCount}
                      columnCount={columns}
                      overscanRowCount={2}
                      overscanColumnCount={1}
                      isScrolling={isScrolling}
                      onScroll={onChildScroll}
                      scrollTop={scrollTop}
                      cellRenderer={({ columnIndex, rowIndex, key, style }) => {
                        const index = rowIndex * columns + columnIndex;
                        if (index >= data.length) return null;
                        const n = data[index];
                        const online = isOnline(n.last_seen_at);
                        const cellStyle = {
                          ...style,
                          width: style.width - gutter,
                          height: style.height - gutter,
                          paddingRight: gutter,
                          paddingBottom: gutter,
                          boxSizing: 'border-box',
                        };
                        return (
                          <div key={key} style={cellStyle}>
                            <Card
                              className="node-card"
                              title={
                                <Space size={8}>
                                  <Badge status={online ? 'success' : 'default'} />
                                  <span>{n.name}</span>
                                </Space>
                              }
                              size="small"
                              extra={<Tag color="blue">{n.transport?.toUpperCase() || 'QUIC'}</Tag>}
                            >
                              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                                <Row gutter={[12, 12]}>
                                  <Col span={12}>
                                    <Space direction="vertical" size={4} style={{ width: '100%' }}>
                                      <Text type="secondary">CPU</Text>
                                      {(() => {
                                        const cpu = n.cpu_usage?.toFixed ? Number(n.cpu_usage.toFixed(1)) : 0;
                                        return (
                                          <>
                                            <Text type="secondary">占用：{cpu}%</Text>
                                            <Progress
                                              percent={cpu}
                                              size="small"
                                              strokeLinecap="round"
                                              strokeColor={loadColor(cpu)}
                                              trailColor="rgba(15, 23, 42, 0.06)"
                                              showInfo={false}
                                            />
                                          </>
                                        );
                                      })()}
                                    </Space>
                                  </Col>
                                  <Col span={12}>
                                    <Space direction="vertical" size={4} style={{ width: '100%' }}>
                                      <Text type="secondary">内存</Text>
                                      {(() => {
                                        const memPct = n.mem_total_bytes
                                          ? Math.min(100, Math.round((n.mem_used_bytes || 0) / n.mem_total_bytes * 100))
                                          : 0;
                                        const memTip = `${formatBytes(n.mem_used_bytes || 0)} / ${formatBytes(n.mem_total_bytes || 0)}`;
                                        return (
                                          <Tooltip title={memTip}>
                                            <>
                                              <Text type="secondary">占用：{memPct}%</Text>
                                              <Progress
                                                percent={memPct}
                                                size="small"
                                                strokeLinecap="round"
                                                strokeColor={loadColor(memPct)}
                                                trailColor="rgba(15, 23, 42, 0.06)"
                                                showInfo={false}
                                              />
                                            </>
                                          </Tooltip>
                                        );
                                      })()}
                                    </Space>
                                  </Col>
                                </Row>
                                <Row gutter={[8, 8]}>
                                  <Col span={12}>
                                    <Text type="secondary">运行：{formatUptime(n.uptime_sec || 0)}</Text>
                                  </Col>
                                  <Col span={12}>
                                    <Text type="secondary">
                                      网络：↑{formatBytes(n.net_out_bytes || 0)} ↓{formatBytes(n.net_in_bytes || 0)}
                                    </Text>
                                  </Col>
                                </Row>
                                <Text type="secondary">版本：{n.node_version || '-'}</Text>
                                <Text type="secondary">系统/架构：{n.os_name || '-'} / {n.arch || '-'}</Text>
                                <Tooltip title={n.last_seen_at ? new Date(n.last_seen_at).toLocaleString() : '-'}>
                                  <Text type="secondary">
                                    上次心跳：{n.last_seen_at ? new Date(n.last_seen_at).toLocaleString() : '-'}
                                  </Text>
                                </Tooltip>
                                <Space>
                                  <Button size="small" type="primary" onClick={() => onSelect(n)}>管理</Button>
                                  <Button size="small" onClick={() => onShowInstall(n)}>安装</Button>
                                </Space>
                              </Space>
                            </Card>
                          </div>
                        );
                      }}
                    />
                  );
                }}
              </AutoSizer>
            )}
          </WindowScroller>
        </div>
      </Card>
      <Modal open={modalOpen} onCancel={() => setModalOpen(false)} onOk={onCreate} title="新建节点">
        <Form layout="vertical" form={form} initialValues={{ ws_listen: ":18080", metrics_listen: ":19090" }}>
          <Form.Item name="name" label="节点名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="ws_listen" label="WS监听"><Input /></Form.Item>
          <Form.Item name="metrics_listen" label="Metrics监听"><Input /></Form.Item>
          <Form.Item name="quic_listen" label="QUIC监听 (可选)"><Input placeholder="不填则与WS相同" /></Form.Item>
          <Form.Item name="wss_listen" label="WSS监听 (可选)" tooltip="如需同时启用 WSS，请填写监听端口"><Input placeholder="例如 :18443" /></Form.Item>
          <Form.Item name="quic_server_name" label="QUIC Server Name (可选)" tooltip="空则跳过证书校验，可用IP直连；填域名则按域名校验">
            <Input placeholder="如需校验证书请填写域名" />
          </Form.Item>
          <Form.Item name="transport" label="传输" rules={[{ required: true }]}>
            <Select options={[{ value: 'wss', label: 'WSS' }, { value: 'quic', label: 'QUIC(TCP)' }]} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}

function NodeDetail({ node, onBack, refreshList, onShowInstall }) {
  const [detail, setDetail] = useState(node);
  const [entryOpen, setEntryOpen] = useState(false);
  const [peerOpen, setPeerOpen] = useState(false);
  const [allNodes, setAllNodes] = useState([]);
  const [routeOpen, setRouteOpen] = useState(false);
  const [routeEditOpen, setRouteEditOpen] = useState(false);
  const [routeForm] = Form.useForm();
  const [routeEditForm] = Form.useForm();
  const [editOpen, setEditOpen] = useState(false);
  const [entryForm] = Form.useForm();
  const [peerForm] = Form.useForm();
  const [peerEditOpen, setPeerEditOpen] = useState(false);
  const [peerEditForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [peerIPOptions, setPeerIPOptions] = useState([]);
  const [peerEditIPOptions, setPeerEditIPOptions] = useState([]);
  const [ipModalOpen, setIpModalOpen] = useState(false);
  const [ipForm] = Form.useForm();

  const load = async () => {
    try {
      setDetail(await api('GET', `/api/nodes/${node.id}`));
      refreshList();
      setAllNodes(await api('GET', '/api/nodes'));
    } catch (e) {
      message.error(e.message);
    }
  };
  useEffect(() => {
    load();
  }, [node.id]);

  const nodePublicIPs = (name) => {
    const n = (allNodes || []).find((x) => x.name === name);
    if (!n || !Array.isArray(n.public_ips)) return [];
    return n.public_ips.filter(Boolean);
  };

  useEffect(() => {
    const name = peerForm.getFieldValue('peer_name');
    if (name) setPeerIPOptions(nodePublicIPs(name));
    const editName = peerEditForm.getFieldValue('peer_name');
    if (editName) setPeerEditIPOptions(nodePublicIPs(editName));
  }, [allNodes]);

  const addEntry = async () => {
    try {
      const v = await entryForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/entries`, v);
      message.success('入口已添加');
      setEntryOpen(false);
      entryForm.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };
  const addPeer = async () => {
    try {
      const v = await peerForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/peers`, v);
      message.success('对端已添加');
      setPeerOpen(false);
      peerForm.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };
  const addRoute = async () => {
    try {
      const v = await routeForm.validateFields();
      await api('POST', `/api/nodes/${node.id}/routes`, v);
      message.success('线路已添加');
      setRouteOpen(false);
      routeForm.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };
  const removeNode = async () => {
    Modal.confirm({
      title: '确认删除节点？',
      onOk: async () => {
        await api('DELETE', `/api/nodes/${node.id}`);
        message.success('已删除');
        onBack();
        refreshList();
      },
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
    {
      title: '操作',
      render: (_, r) => (
        <Space>
          <Button
            size="small"
            onClick={() => {
              peerEditForm.setFieldsValue(r);
              setPeerEditIPOptions(nodePublicIPs(r.peer_name));
              setPeerEditOpen(true);
            }}
          >
            编辑
          </Button>
          <Button
            danger
            size="small"
            onClick={() => {
              Modal.confirm({
                title: '确认删除对端？',
                onOk: async () => {
                  try {
                    await api('DELETE', `/api/nodes/${node.id}/peers/${r.id}`);
                    message.success('已删除');
                    load();
                  } catch (e) {
                    message.error(e.message);
                  }
                },
              });
            }}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ];
  const routeCols = [
    { title: '名称', dataIndex: 'name' },
    { title: '出口', dataIndex: 'exit' },
    { title: '远端', dataIndex: 'remote' },
    { title: '优先级', dataIndex: 'priority' },
    { title: '路径', dataIndex: 'path', render: (p = []) => p.map((n) => <Tag key={n}>{n}</Tag>) },
    {
      title: '操作',
      render: (_, r) => (
        <Space>
          <Button size="small" onClick={() => { routeEditForm.setFieldsValue({ ...r }); setRouteEditOpen(true); }}>编辑</Button>
          <Button
            danger
            size="small"
            onClick={() => {
              Modal.confirm({
                title: '确认删除线路？',
                onOk: async () => {
                  try {
                    await api('DELETE', `/api/nodes/${node.id}/routes/${r.id}`);
                    message.success('已删除');
                    load();
                  } catch (e) {
                    message.error(e.message);
                  }
                },
              });
            }}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <Card
      className="page-card"
      title={`节点：${detail.name}`}
      extra={(
        <Space>
          <Button onClick={onBack}>返回</Button>
          <Button href={joinUrl(API_BASE, `/nodes/${detail.id}/config`)} target="_blank">下载配置</Button>
          <Button onClick={() => onShowInstall(detail)}>安装脚本</Button>
          <Button
            onClick={() => {
              editForm.setFieldsValue({
                ws_listen: detail.ws_listen,
                wss_listen: detail.wss_listen,
                metrics_listen: detail.metrics_listen,
                poll_period: detail.poll_period || '5s',
                quic_listen: detail.quic_listen || detail.ws_listen,
                quic_server_name: detail.quic_server_name || '',
              });
              setEditOpen(true);
            }}
          >
            编辑监听
          </Button>
          <Button danger onClick={removeNode}>删除</Button>
        </Space>
      )}
    >
      <Descriptions column={{ xs: 1, sm: 2, md: 3, lg: 4 }} bordered size="small">
        <Descriptions.Item label="WS监听">{detail.ws_listen}</Descriptions.Item>
        <Descriptions.Item label="Metrics">{detail.metrics_listen}</Descriptions.Item>
        <Descriptions.Item label="AuthKey">{detail.auth_key}</Descriptions.Item>
        <Descriptions.Item label="UDP TTL">{detail.udp_session_ttl}</Descriptions.Item>
        <Descriptions.Item label="Poll周期">{detail.poll_period || '5s'}</Descriptions.Item>
        <Descriptions.Item label="压缩(全局)">{detail.compression || 'gzip'}</Descriptions.Item>
        <Descriptions.Item label="压缩阈值(全局)">{detail.compression_min_bytes || 0} Bytes</Descriptions.Item>
        <Descriptions.Item label="传输(全局)">{(detail.transport || 'wss').toUpperCase()}</Descriptions.Item>
        <Descriptions.Item label="QUIC监听">{detail.quic_listen || detail.ws_listen}</Descriptions.Item>
        <Descriptions.Item label="WSS监听">{detail.wss_listen || '-'}</Descriptions.Item>
        <Descriptions.Item label="CPU">{(detail.cpu_usage || 0).toFixed ? `${detail.cpu_usage.toFixed(1)}%` : '-'}</Descriptions.Item>
        <Descriptions.Item label="内存">{`${formatBytes(detail.mem_used_bytes || 0)} / ${formatBytes(detail.mem_total_bytes || 0)}`}</Descriptions.Item>
        <Descriptions.Item label="运行时长">{formatUptime(detail.uptime_sec || 0)}</Descriptions.Item>
        <Descriptions.Item label="网络累计">{`↑${formatBytes(detail.net_out_bytes || 0)} ↓${formatBytes(detail.net_in_bytes || 0)}`}</Descriptions.Item>
        <Descriptions.Item label="版本">{detail.node_version || '-'}</Descriptions.Item>
        <Descriptions.Item label="最后心跳">{detail.last_seen_at ? new Date(detail.last_seen_at).toLocaleString() : '-'}</Descriptions.Item>
      </Descriptions>
      <Space style={{ marginTop: 8, marginBottom: 8 }} wrap>
        <span>
          公网IP：
          {(detail.public_ips || []).length
            ? (detail.public_ips || []).map((ip) => <Tag key={ip}>{ip}</Tag>)
            : '未上报'}
        </span>
        <Button size="small" onClick={() => { ipForm.setFieldsValue({ ips: (detail.public_ips || []).join('\n') }); setIpModalOpen(true); }}>手动设置</Button>
      </Space>
      <Tabs
        style={{ marginTop: 16 }}
        items={[
          {
            key: 'entries',
            label: '入口',
            children: (
              <>
                <Button type="primary" onClick={() => setEntryOpen(true)} style={{ marginBottom: 8 }}>添加入口</Button>
                <Table
                  rowKey="id"
                  dataSource={detail.entries || []}
                  columns={[
                    ...entryCols,
                    {
                      title: '操作',
                      render: (_, r) => (
                        <Button
                          danger
                          size="small"
                          onClick={() => {
                            Modal.confirm({
                              title: '确认删除入口？',
                              onOk: async () => {
                                try {
                                  await api('DELETE', `/api/nodes/${detail.id}/entries/${r.id}`);
                                  message.success('已删除');
                                  load();
                                } catch (e) {
                                  message.error(e.message);
                                }
                              },
                            });
                          }}
                        >
                          删除
                        </Button>
                      ),
                    },
                  ]}
                  pagination={false}
                />
              </>
            ),
          },
          {
            key: 'peers',
            label: '对端',
            children: (
              <>
                <Button type="primary" onClick={() => setPeerOpen(true)} style={{ marginBottom: 8 }}>添加对端</Button>
                <Table rowKey="id" dataSource={detail.peers || []} columns={peerCols} pagination={false} />
              </>
            ),
          },
          {
            key: 'routes',
            label: '线路',
            children: (
              <>
                <Button type="primary" onClick={() => setRouteOpen(true)} style={{ marginBottom: 8 }}>添加线路</Button>
                <Table rowKey="id" dataSource={detail.routes || []} columns={routeCols} pagination={false} />
              </>
            ),
          },
        ]}
      />

      <Modal open={entryOpen} onCancel={() => setEntryOpen(false)} onOk={addEntry} title="添加入口">
        <Form layout="vertical" form={entryForm} initialValues={{ proto: 'tcp' }}>
          <Form.Item name="listen" label="监听" rules={[{ required: true }]}><Input placeholder=":10080" /></Form.Item>
          <Form.Item name="proto" label="协议" rules={[{ required: true }]}>
            <Select
              options={[
                { value: 'tcp', label: 'tcp' },
                { value: 'udp', label: 'udp' },
                { value: 'both', label: 'tcp+udp' },
              ]}
            />
          </Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{ required: true }]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes || []).filter((n) => n.id !== detail.id).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="remote" label="远端" rules={[{ required: true }]}><Input placeholder="1.1.1.1:3389" /></Form.Item>
        </Form>
      </Modal>

      <Modal
        open={ipModalOpen}
        onCancel={() => setIpModalOpen(false)}
        onOk={async () => {
          try {
            const v = await ipForm.validateFields();
            const ips = (v.ips || '').split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
            await api('PUT', `/api/nodes/${node.id}/public-ips`, { public_ips: ips });
            message.success('公网IP已更新');
            setIpModalOpen(false);
            load();
          } catch (e) {
            message.error(e.message);
          }
        }}
        title="手动设置公网IP"
      >
        <Form layout="vertical" form={ipForm}>
          <Form.Item name="ips" label="公网IP（换行/逗号分隔）">
            <Input.TextArea rows={4} placeholder="例如: 1.2.3.4\n240e:xxxx::1" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={peerEditOpen}
        onCancel={() => setPeerEditOpen(false)}
        onOk={async () => {
          try {
            const v = await peerEditForm.validateFields();
            await api('PUT', `/api/nodes/${node.id}/peers/${v.id}`, v);
            message.success('已更新');
            setPeerEditOpen(false);
            load();
          } catch (e) {
            message.error(e.message);
          }
        }}
        title="编辑对端"
      >
        <Form layout="vertical" form={peerEditForm}>
          <Form.Item name="id" hidden><Input /></Form.Item>
          <Form.Item name="peer_name" label="对端节点" rules={[{ required: true }]}>
            <Select
              placeholder="选择已有节点"
              options={(allNodes || []).filter((n) => n.id !== detail.id).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
              onChange={(val) => { setPeerEditIPOptions(nodePublicIPs(val)); peerEditForm.setFieldsValue({ entry_ip: undefined, exit_ip: undefined }); }}
            />
          </Form.Item>
          <Form.Item name="entry_ip" label="入口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerEditIPOptions.map((ip) => ({ label: ip, value: ip }))}
            />
          </Form.Item>
          <Form.Item name="exit_ip" label="出口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerEditIPOptions.map((ip) => ({ label: ip, value: ip }))}
            />
          </Form.Item>
          <Form.Item name="endpoint" label="WS地址 (可选)"><Input placeholder="如留空则尝试根据入口IP+对端监听拼装" /></Form.Item>
        </Form>
      </Modal>

      <Modal open={peerOpen} onCancel={() => setPeerOpen(false)} onOk={addPeer} title="添加对端">
        <Form layout="vertical" form={peerForm}>
          <Form.Item name="peer_name" label="对端节点" rules={[{ required: true }]}>
            <Select
              placeholder="选择已有节点"
              options={(allNodes || []).filter((n) => n.id !== detail.id).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
              onChange={(val) => { setPeerIPOptions(nodePublicIPs(val)); peerForm.setFieldsValue({ entry_ip: undefined, exit_ip: undefined }); }}
            />
          </Form.Item>
          <Form.Item name="entry_ip" label="入口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerIPOptions.map((ip) => ({ label: ip, value: ip }))}
            />
          </Form.Item>
          <Form.Item name="exit_ip" label="出口IP (可选)">
            <Select
              placeholder="从对端公网IP选择，可不选"
              allowClear
              options={peerIPOptions.map((ip) => ({ label: ip, value: ip }))}
            />
          </Form.Item>
          <Form.Item name="endpoint" label="WS地址 (可选)">
            <Input placeholder="如留空则尝试根据入口IP+对端监听拼装" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        open={editOpen}
        onCancel={() => setEditOpen(false)}
        onOk={async () => {
          try {
            const v = await editForm.validateFields();
            await api('PUT', `/api/nodes/${detail.id}`, v);
            message.success('已更新');
            setEditOpen(false);
            load();
          } catch (e) {
            message.error(e.message);
          }
        }}
        title="编辑监听端口"
      >
        <Form layout="vertical" form={editForm}>
          <Form.Item name="ws_listen" label="WS监听" rules={[{ required: true }]}><Input placeholder=":18080" /></Form.Item>
          <Form.Item name="wss_listen" label="WSS监听 (可选)" tooltip="如需启用 WSS 请填写"><Input placeholder=":18443" /></Form.Item>
          <Form.Item name="metrics_listen" label="Metrics监听" rules={[{ required: true }]}><Input placeholder=":19090" /></Form.Item>
          <Form.Item name="poll_period" label="Poll周期" rules={[{ required: true }]}><Input placeholder="5s" /></Form.Item>
          <Form.Item name="quic_listen" label="QUIC监听 (可选)" tooltip="不填则与 WS 监听相同">
            <Input placeholder=":18090" />
          </Form.Item>
          <Form.Item name="quic_server_name" label="QUIC Server Name (可选)" tooltip="空则跳过证书校验，可用IP直连；填域名则按域名校验">
            <Input placeholder="如需校验证书请填写域名" />
          </Form.Item>
        </Form>
      </Modal>

      <Modal open={routeOpen} onCancel={() => setRouteOpen(false)} onOk={addRoute} title="添加线路" width={600}>
        <Form layout="vertical" form={routeForm} initialValues={{ priority: 1 }}>
          <Form.Item name="name" label="线路名称" rules={[{ required: true }]}><Input placeholder="如: 成都->新加坡-1" /></Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{ required: true }]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes || []).filter((n) => n.id !== detail.id).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{ required: true }]}><Input type="number" min={1} /></Form.Item>
          <Form.Item name="path" label="路径节点顺序" rules={[{ required: true, message: '请选择路径' }]}>
            <Select
              mode="multiple"
              placeholder="从起点到出口的节点顺序"
              options={(allNodes || []).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
          <Divider>可选：入口/出口 IP 参考</Divider>
          <Space direction="vertical" style={{ width: '100%' }}>
            <div>
              节点公网IP：
              {(detail.public_ips || []).length
                ? (detail.public_ips || []).map((ip) => <Tag key={ip}>{ip}</Tag>)
                : '未上报'}
            </div>
          </Space>
        </Form>
      </Modal>

      <Modal
        open={routeEditOpen}
        onCancel={() => setRouteEditOpen(false)}
        onOk={async () => {
          try {
            const v = await routeEditForm.validateFields();
            await api('PUT', `/api/nodes/${node.id}/routes/${v.id}`, v);
            message.success('已更新');
            setRouteEditOpen(false);
            load();
          } catch (e) {
            message.error(e.message);
          }
        }}
        title="编辑线路"
        width={600}
      >
        <Form layout="vertical" form={routeEditForm}>
          <Form.Item name="id" hidden><Input /></Form.Item>
          <Form.Item name="name" label="线路名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="exit" label="出口节点" rules={[{ required: true }]}>
            <Select
              placeholder="选择出口节点"
              options={(allNodes || []).filter((n) => n.id !== detail.id).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{ required: true }]}><Input type="number" min={1} /></Form.Item>
          <Form.Item name="path" label="路径节点顺序" rules={[{ required: true }]}>
            <Select
              mode="multiple"
              placeholder="从起点到出口的节点顺序"
              options={(allNodes || []).map((n) => ({ label: n.name, value: n.name }))}
              showSearch
              optionFilterProp="label"
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
}

function RouteList({ settings }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [onlineMap, setOnlineMap] = useState(new Map());
  const load = async () => {
    setLoading(true);
    try {
      const [nodes, probes] = await Promise.all([
        api('GET', '/api/nodes'),
        api('GET', '/api/probes'),
      ]);
      const online = new Map();
      (nodes || []).forEach((n) => {
        online.set(n.name, isOnline(n.last_seen_at));
      });
      setOnlineMap(online);
      const probeMap = new Map();
      (probes || []).forEach((p) => {
        probeMap.set(`${p.node}::${p.route}`, p);
      });
      const r = [];
      (nodes || []).forEach((n) => {
        (n.routes || []).forEach((rt) => {
          const key = `${n.name}::${rt.name}`;
          const pb = probeMap.get(key);
          r.push({
            key,
            node: n.name,
            route: rt.name,
            exit: rt.exit,
            priority: rt.priority,
            path: rt.path || [],
            probe: pb || null,
          });
        });
      });
      setRows(r);
    } catch (e) {
      message.error(e.message);
    }
    setLoading(false);
  };
  useEffect(() => {
    load();
    const t = setInterval(load, 10000);
    return () => clearInterval(t);
  }, []);
  const cols = [
    { title: '节点', dataIndex: 'node' },
    { title: '线路', dataIndex: 'route' },
    { title: '出口', dataIndex: 'exit' },
    { title: '优先级', dataIndex: 'priority' },
    { title: '路径', dataIndex: 'path', render: (p = []) => (p || []).map((x) => <Tag key={x}>{x}</Tag>) },
    {
      title: '延迟(ms)',
      render: (_, r) => {
        if (!onlineMap.get(r.node)) return '-';
        const pb = r.probe;
        if (!pb) return '-';
        return pb.success ? pb.rtt_ms : '失败';
      },
    },
    {
      title: '状态',
      render: (_, r) => {
        if (!onlineMap.get(r.node)) return <Tag className="soft-orange-tag">离线线路</Tag>;
        const pb = r.probe;
        if (!pb) return <Tag>未上报</Tag>;
        return pb.success ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>;
      },
    },
    {
      title: '更新时间',
      render: (_, r) => {
        const pb = r.probe;
        if (!pb || !pb.updated_at) return '-';
        return new Date(pb.updated_at).toLocaleString();
      },
    },
  ];
  const triggerAllTests = async () => {
    const target = settings?.http_probe_url || 'https://www.google.com/generate_204';
    if (!rows.length) {
      message.info('暂无线路可测试');
      return;
    }
    const runnable = rows.filter((r) => onlineMap.get(r.node));
    const skipped = rows.length - runnable.length;
    if (!runnable.length) {
      message.warning('当前节点均离线，已跳过测试');
      return;
    }
    try {
      const results = await Promise.allSettled(
        runnable.map((r) =>
          api('POST', '/api/route-test', {
            node: r.node,
            route: r.route,
            path: r.path,
            target,
          })
        )
      );
      const failed = results.filter((r) => r.status === 'rejected').length;
      if (failed) {
        message.warning(`已下发${runnable.length - failed}条测试，失败${failed}条${skipped ? `，跳过${skipped}条离线线路` : ''}`);
      } else {
        message.success(`已下发${runnable.length}条测试${skipped ? `，跳过${skipped}条离线线路` : ''}`);
      }
      setTimeout(load, 1200);
    } catch (e) {
      message.error(e.message);
    }
  };
  return (
    <Card className="page-card" title="线路列表（含端到端延迟）" extra={<Button onClick={triggerAllTests}>测试全部</Button>}>
      <Table rowKey="key" dataSource={rows} columns={cols} loading={loading} pagination={false} />
    </Card>
  );
}

export default function App() {
  const screens = useBreakpoint();
  const isMobile = !screens.md;
  const [selected, setSelected] = useState(null);
  const [refreshSignal, setRefreshSignal] = useState(0);
  const [installCmd, setInstallCmd] = useState('');
  const [installOpen, setInstallOpen] = useState(false);
  const [settings, setSettings] = useState(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [controllerVersion, setControllerVersion] = useState('');
  const [token, setToken] = useState(localStorage.getItem('jwt') || '');
  const [userList, setUserList] = useState([]);
  const [userModal, setUserModal] = useState(false);
  const [userForm] = Form.useForm();
  const [editUser, setEditUser] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [view, setView] = useState('dashboard');
  const refreshList = () => setRefreshSignal((t) => t + 1);

  const showInstall = (node) => {
    if (!node) {
      message.info('请先选择一个节点');
      return;
    }
    const origin = API_BASE || window.location.origin;
    const tok = node.token || '';
    const tokenArg = tok ? `?token=${encodeURIComponent(tok)}` : '';
    const extra = tok ? ` -k ${tok}` : '';
    setInstallCmd(`curl -fsSL ${joinUrl(origin, `/nodes/${node.id}/install.sh${tokenArg}`)} | bash -s --${extra}`);
    setInstallOpen(true);
  };
  const loadSettings = async () => {
    try {
      if (!token) return;
      const s = await api('GET', '/api/settings');
      if (s) setSettings(s);
      const v = await api('GET', '/api/version');
      if (v?.version) setControllerVersion(v.version);
    } catch (e) {
      if (token) message.error('全局设置加载失败: ' + e.message);
    }
  };
  const copyCmd = async () => {
    try {
      await navigator.clipboard.writeText(installCmd);
      message.success('已复制');
    } catch (e) {
      message.error('复制失败');
    }
  };

  const login = async (vals) => {
    try {
      const res = await api('POST', '/api/login', vals);
      localStorage.setItem('jwt', res.token);
      setToken(res.token);
      message.success('登录成功');
      loadSettings();
      refreshList();
    } catch (e) {
      message.error(e.message);
    }
  };
  const logout = () => {
    localStorage.removeItem('jwt');
    setToken('');
    setSelected(null);
    setView('dashboard');
  };

  const loadUsers = async () => {
    try {
      const res = await api('GET', '/api/users');
      setUserList(res);
    } catch (e) {
      if (token) message.error('加载用户失败: ' + e.message);
    }
  };
  useEffect(() => {
    if (token) {
      loadUsers();
    }
  }, [token]);

  useEffect(() => {
    if (token) loadSettings();
  }, [token]);

  const SettingsModal = () => {
    const [form] = Form.useForm();
    const [saving, setSaving] = useState(false);
    useEffect(() => {
      if (settings) {
        form.setFieldsValue({
          transport: settings.transport || 'quic',
          compression: settings.compression || 'none',
          compression_min_bytes: settings.compression_min_bytes || 0,
          http_probe_url: settings.http_probe_url || 'https://www.google.com/generate_204',
          debug_log: settings.debug_log || false,
          encryption_policies: settings.encryption_policies || [],
        });
      }
    }, [settings]);
    const onSave = async () => {
      try {
        const v = await form.validateFields();
        setSaving(true);
        await api('POST', '/api/settings', v);
        message.success('全局设置已更新，节点下次拉取配置后生效');
        await loadSettings();
        setSettingsOpen(false);
      } catch (e) {
        message.error(e.message);
      }
      setSaving(false);
    };
    return (
      <Modal
        open={settingsOpen}
        onCancel={() => setSettingsOpen(false)}
        onOk={onSave}
        okText="保存"
        confirmLoading={saving}
        title="全局传输与压缩设置"
        width={760}
      >
        <Form layout="vertical" form={form}>
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="transport" label="传输" rules={[{ required: true }]}>
                <Select options={[{ value: 'wss', label: 'WSS' }, { value: 'quic', label: 'QUIC(TCP)' }]} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="compression" label="压缩" rules={[{ required: true }]}>
                <Select options={[{ value: 'none', label: '关闭' }, { value: 'gzip', label: 'gzip' }]} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="compression_min_bytes" label="压缩阈值(Bytes)" tooltip="小于该大小直传不压缩，0表示总是压缩">
                <Input type="number" min={0} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="http_probe_url" label="HTTP探测URL">
                <Input placeholder="https://www.google.com/generate_204" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="debug_log" label="日志模式">
                <Select options={[
                  { value: false, label: '仅告警/错误（默认）' },
                  { value: true, label: '调试模式（输出全部）' },
                ]} />
              </Form.Item>
            </Col>
          </Row>
        </Form>
      </Modal>
    );
  };

  const EncryptionCard = () => {
    const [form] = Form.useForm();
    const [saving, setSaving] = useState(false);
    useEffect(() => {
      if (settings) form.setFieldsValue({ encryption_policies: settings.encryption_policies || [] });
    }, [settings]);
    const onSave = async () => {
      try {
        const v = await form.validateFields();
        setSaving(true);
        await api('POST', '/api/settings', { encryption_policies: v.encryption_policies || [] });
        message.success('加密策略已更新，节点下次拉取配置后生效');
        await loadSettings();
      } catch (e) {
        message.error(e.message);
      }
      setSaving(false);
    };
    return (
      <Card className="page-card" title="加密策略配置" style={{ marginBottom: 16 }}>
        <Form layout="vertical" form={form}>
          <Form.List name="encryption_policies">
            {(fields, { add, remove }) => (
              <>
                {fields.map(({ key, name, ...rest }) => (
                  <Space key={key} style={{ display: 'flex', marginBottom: 8, flexWrap: 'wrap' }} align="baseline">
                    <Form.Item {...rest} name={[name, 'enable']} label="启用" valuePropName="checked" initialValue>
                      <Switch />
                    </Form.Item>
                    <Form.Item {...rest} name={[name, 'id']} label="ID" rules={[{ required: true, message: 'ID必填' }]}>
                      <Input style={{ width: 80 }} />
                    </Form.Item>
                    <Form.Item {...rest} name={[name, 'name']} label="名称">
                      <Input style={{ width: 120 }} />
                    </Form.Item>
                    <Form.Item {...rest} name={[name, 'method']} label="算法" rules={[{ required: true }]}>
                      <Select style={{ width: 180 }} options={[
                        { value: 'aes-128-gcm', label: 'AES-128-GCM' },
                        { value: 'aes-256-gcm', label: 'AES-256-GCM' },
                        { value: 'chacha20-poly1305', label: 'ChaCha20-Poly1305' },
                      ]} />
                    </Form.Item>
                    <Form.Item {...rest} name={[name, 'key']} label="密钥(Base64/HEX)">
                      <Input style={{ width: 280 }} placeholder="可留空，保存时自动生成合规长度" />
                    </Form.Item>
                    <Button danger onClick={() => remove(name)} type="link">删除</Button>
                  </Space>
                ))}
                <Button type="dashed" onClick={() => add()} block>
                  + 增加策略
                </Button>
              </>
            )}
          </Form.List>
          <Form.Item style={{ marginTop: 12 }}>
            <Button type="primary" onClick={onSave} loading={saving}>保存</Button>
          </Form.Item>
        </Form>
      </Card>
    );
  };

  if (!token) {
    return (
      <Layout className="login-layout">
        <Header className="app-header">
          <div className="brand">
            <div className="brand-title">ARouter 控制台</div>
            <div className="brand-sub">高可用跨域加速控制台</div>
          </div>
          <Button
            size="small"
            type="text"
            icon={<GithubIcon />}
            href="https://github.com/NiuStar/arouter"
            target="_blank"
            aria-label="GitHub 仓库"
          />
        </Header>
        <Content className="login-content">
          <Card className="login-card" title="登录">
            <Form layout="vertical" onFinish={login}>
              <Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item>
              <Form.Item name="password" label="密码" rules={[{ required: true }]}><Input.Password /></Form.Item>
              <Button type="primary" htmlType="submit" block>登录</Button>
            </Form>
          </Card>
        </Content>
      </Layout>
    );
  }

  const menuItems = [
    { key: 'dashboard', label: '节点概览' },
    { key: 'routes', label: '线路列表' },
    { key: 'encryption', label: '加密策略' },
  ];

  return (
    <Layout className="app-layout">
      {!isMobile && (
        <Sider className="app-sider" width={220} theme="light">
          <div className="sider-brand">
            <div className="brand-title">ARouter</div>
            <div className="brand-sub">Controller</div>
          </div>
          <Menu
            theme="light"
            mode="inline"
            selectedKeys={[view]}
            onClick={({ key }) => { setView(key); if (key === 'dashboard') setSelected(null); }}
            items={menuItems}
          />
        </Sider>
      )}
      <Layout>
        <Header className="app-header">
          <div className="header-left">
            {isMobile && (
              <Button type="text" className="header-menu" onClick={() => setDrawerOpen(true)}>≡</Button>
            )}
            <div className="brand">
              <div className="brand-title">ARouter 控制台</div>
              <div className="brand-sub">多链路调度与可观测</div>
            </div>
          </div>
          <Space wrap>
            {controllerVersion && (
              <Space size={6}>
                <Tag color="gold">Controller版本：{controllerVersion}</Tag>
                <Button
                  size="small"
                  type="text"
                  icon={<GithubIcon />}
                  href="https://github.com/NiuStar/arouter"
                  target="_blank"
                  aria-label="GitHub 仓库"
                />
              </Space>
            )}
          </Space>
          <Space wrap>
            <Button size="small" type="text" icon={<PowerIcon />} onClick={logout} aria-label="退出" />
            <Button
              size="small"
              type="text"
              icon={<UserIcon />}
              onClick={() => { setEditUser(null); userForm.resetFields(); setUserModal(true); }}
              aria-label="用户管理"
            />
            <Button size="small" type="text" icon={<GearIcon />} onClick={() => setSettingsOpen(true)} aria-label="全局设置" />
          </Space>
        </Header>
        <Content className="app-content">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Card className="page-card" bodyStyle={{ padding: 16 }}>
              <Space wrap>
                <Button type="primary" onClick={() => refreshList()}>刷新</Button>
                <Button onClick={() => { setSelected(null); setView('dashboard'); }}>节点概览</Button>
                <Button onClick={() => setView('routes')}>线路列表</Button>
                <Button onClick={() => setView('encryption')}>加密策略</Button>
                <Tooltip title={selected ? '' : '请先选择一个节点'}>
                  <Button disabled={!selected} onClick={() => showInstall(selected)}>安装节点</Button>
                </Tooltip>
              </Space>
            </Card>
            <SettingsModal />
            {view === 'routes'
              ? <RouteList settings={settings} />
              : view === 'encryption'
                ? <EncryptionCard />
                : (selected
                  ? <NodeDetail key={selected.id} node={selected} onBack={() => setSelected(null)} refreshList={refreshList} onShowInstall={showInstall} />
                  : <NodeList onSelect={setSelected} onShowInstall={showInstall} refreshSignal={refreshSignal} />
                )
            }
            <Modal open={installOpen} onCancel={() => setInstallOpen(false)} onOk={copyCmd} okText="复制命令">
              <p>在目标节点执行以下命令以安装并自启动：</p>
              <Input.TextArea value={installCmd} rows={3} readOnly />
            </Modal>
            <Modal
              open={userModal}
              onCancel={() => { setUserModal(false); setEditUser(null); userForm.resetFields(); }}
              onOk={async () => {
                try {
                  const v = await userForm.validateFields();
                  if (editUser) {
                    const body = {};
                    if (v.password) body.password = v.password;
                    if (v.is_admin !== undefined) body.is_admin = v.is_admin;
                    await api('PUT', `/api/users/${editUser.id}`, body);
                    message.success('用户已更新');
                  } else {
                    await api('POST', '/api/users', v);
                    message.success('用户已创建');
                  }
                  setUserModal(false);
                  setEditUser(null);
                  userForm.resetFields();
                  loadUsers();
                } catch (e) {
                  message.error(e.message);
                }
              }}
              title="用户管理"
              okText={editUser ? '保存' : '添加用户'}
              width={760}
            >
              <Table
                rowKey="id"
                dataSource={userList}
                pagination={false}
                columns={[
                  { title: '用户名', dataIndex: 'username' },
                  { title: '管理员', dataIndex: 'is_admin', render: (v) => (v ? '是' : '否') },
                  {
                    title: '操作',
                    render: (_, r) => (
                      <Space>
                        <Button size="small" onClick={() => { setEditUser(r); userForm.setFieldsValue({ username: r.username, is_admin: r.is_admin, password: '' }); setUserModal(true); }}>修改</Button>
                        <Button
                          size="small"
                          danger
                          onClick={async () => {
                            try {
                              await api('DELETE', `/api/users/${r.id}`);
                              message.success('已删除');
                              loadUsers();
                            } catch (e) {
                              message.error(e.message);
                            }
                          }}
                        >
                          删除
                        </Button>
                      </Space>
                    ),
                  },
                ]}
              />
              <Divider />
              <Form layout="vertical" form={userForm}>
                <Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item>
                <Form.Item name="password" label="密码" rules={[{ required: true }]}><Input.Password /></Form.Item>
                <Form.Item name="is_admin" label="管理员" initialValue={false}>
                  <Select options={[{ value: true, label: '是' }, { value: false, label: '否' }]} />
                </Form.Item>
              </Form>
            </Modal>
          </Space>
        </Content>
        <Drawer
          placement="left"
          open={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          width={220}
          title="导航"
        >
          <Menu
            mode="inline"
            selectedKeys={[view]}
            onClick={({ key }) => { setView(key); setDrawerOpen(false); if (key === 'dashboard') setSelected(null); }}
            items={menuItems}
          />
        </Drawer>
      </Layout>
    </Layout>
  );
}
