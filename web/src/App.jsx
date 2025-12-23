import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { AutoSizer, Grid as VirtualGrid, WindowScroller } from 'react-virtualized';
import {
  Layout,
  Table,
  Button,
  Modal,
  Form,
  Input,
  InputNumber,
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
  Checkbox,
} from 'antd';
import { ApiOutlined, ClockCircleOutlined, CopyOutlined, RadarChartOutlined, ShareAltOutlined } from '@ant-design/icons';
import { api, DEFAULT_API_BASE, getApiBase, joinUrl, setApiBase } from './api';
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
const uninstallStatusLabel = (status) => {
  if (!status) return '-';
  const map = { pending: '卸载中', success: '卸载成功', failed: '卸载失败' };
  return map[status] || status;
};
const uninstallStatusColor = (status) => {
  if (status === 'pending') return 'blue';
  if (status === 'success') return 'green';
  if (status === 'failed') return 'red';
  return 'default';
};
const normalizeTimestamp = (ts) => {
  if (!ts) return 0;
  if (typeof ts === 'number') {
    return ts < 1e12 ? ts * 1000 : ts;
  }
  const t = new Date(ts).getTime();
  return t < 1e12 && t > 0 ? t * 1000 : t;
};
const formatRelativeTime = (ts) => {
  if (!ts) return '-';
  const t = normalizeTimestamp(ts);
  if (!t) return '-';
  const diff = Math.max(0, Date.now() - t);
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}秒前`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}分钟前`;
  const hour = Math.floor(min / 60);
  if (hour < 24) return `${hour}小时前`;
  const day = Math.floor(hour / 24);
  return `${day}天前`;
};

const PathOrderEditor = ({ value = [], onChange, options = [], placeholder, extra }) => {
  const dragRef = useRef(null);
  const pointerIdRef = useRef(null);
  const didTouchMoveRef = useRef(false);
  const trackRef = useRef(null);
  const lastPointRef = useRef(null);
  const scrollLockRef = useRef(0);
  const dropIndexRef = useRef(null);
  const lastValidDropIndexRef = useRef(null);
  const enteredTrackRef = useRef(false);
  const [ghost, setGhost] = useState(null);
  const [dropIndex, setDropIndex] = useState(null);
  const [collapsedGroups, setCollapsedGroups] = useState(() => new Set());
  const didInitGroups = useRef(false);
  const prevGroupNames = useRef(new Set());
  const [touchDragging, setTouchDragging] = useState(false);
  const isTouch = useMemo(() => {
    if (typeof window === 'undefined') return false;
    return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  }, []);
  const safeValue = Array.isArray(value) ? value : [];
  const selectedSet = useMemo(() => new Set(safeValue), [safeValue]);
  const filtered = useMemo(() => {
    return options.filter((opt) => {
      if (selectedSet.has(opt.value)) return false;
      return true;
    });
  }, [options, selectedSet]);
  const grouped = useMemo(() => {
    const map = new Map();
    filtered.forEach((opt) => {
      const region = opt.region || opt.country || '未知地区';
      if (!map.has(region)) map.set(region, []);
      map.get(region).push(opt);
    });
    return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b, 'zh'));
  }, [filtered]);

  useEffect(() => {
    if (!grouped.length) return;
    const names = new Set(grouped.map(([name]) => name));
    if (!didInitGroups.current) {
      setCollapsedGroups(new Set(names));
      prevGroupNames.current = names;
      didInitGroups.current = true;
      return;
    }
    const prevNames = prevGroupNames.current;
    const added = [];
    names.forEach((name) => {
      if (!prevNames.has(name)) added.push(name);
    });
    if (added.length) {
      setCollapsedGroups((prev) => {
        const next = new Set(prev);
        added.forEach((name) => next.add(name));
        return next;
      });
    }
    prevGroupNames.current = names;
  }, [grouped]);

  const addItem = (item, index = null) => {
    if (!item || selectedSet.has(item)) return;
    const next = [...safeValue];
    if (index == null || index >= next.length) {
      next.push(item);
    } else {
      next.splice(index, 0, item);
    }
    onChange?.(next);
  };

  const removeItem = (item) => {
    onChange?.(safeValue.filter((v) => v !== item));
  };

  const moveItem = (from, to) => {
    if (from === to || from == null || to == null) return;
    const next = [...safeValue];
    const [item] = next.splice(from, 1);
    next.splice(to, 0, item);
    onChange?.(next);
  };

  const setDropIndexSafe = (val) => {
    dropIndexRef.current = val;
    setDropIndex(val);
  };

  const onDropTrack = (index = null) => {
    const payload = dragRef.current;
    if (!payload) return;
    if (payload.source === 'pool') {
      addItem(payload.value, index);
    } else if (payload.source === 'track') {
      moveItem(payload.index, index == null ? safeValue.length - 1 : index);
    }
    dragRef.current = null;
    setDropIndexSafe(null);
  };

  const getDropIndexFromPoint = useCallback((x, y) => {
    const track = trackRef.current;
    if (!track) return null;
    const rect = track.getBoundingClientRect();
    if (y < rect.top - 8 || y > rect.bottom + 8) return null;
    const chips = Array.from(track.querySelectorAll('.path-order-chip'));
    if (!chips.length) return 0;
    for (let i = 0; i < chips.length; i += 1) {
      const c = chips[i].getBoundingClientRect();
      const mid = c.left + c.width / 2;
      if (x < mid) return i;
    }
    return chips.length;
  }, []);

  const getClosestDropIndex = useCallback((x) => {
    const track = trackRef.current;
    if (!track) return null;
    const rect = track.getBoundingClientRect();
    const clampedX = Math.min(Math.max(x, rect.left + 1), rect.right - 1);
    const midY = rect.top + rect.height / 2;
    return getDropIndexFromPoint(clampedX, midY);
  }, [getDropIndexFromPoint]);

  const isOverTrack = useCallback((x, y) => {
    const track = trackRef.current;
    if (!track) return false;
    const el = document.elementFromPoint(x, y);
    return !!(el && track.contains(el));
  }, []);

  const startTouchDrag = (payload, e) => {
    if (!isTouch || e.pointerType !== 'touch') return;
    e.preventDefault();
    dragRef.current = payload;
    pointerIdRef.current = e.pointerId;
    lastPointRef.current = { x: e.clientX, y: e.clientY };
    didTouchMoveRef.current = false;
    setTouchDragging(true);
    const text = payload?.value || '';
    setGhost({ x: e.clientX, y: e.clientY, text });
    scrollLockRef.current = window.scrollY || window.pageYOffset || 0;
    document.body.style.position = 'fixed';
    document.body.style.top = `-${scrollLockRef.current}px`;
    document.body.style.left = '0';
    document.body.style.right = '0';
    document.body.style.width = '100%';
    document.body.classList.add('touch-dragging');
    if (e.currentTarget?.setPointerCapture) {
      e.currentTarget.setPointerCapture(e.pointerId);
    }
  };

  useEffect(() => {
    if (!touchDragging) return;
    const updateFromPoint = (x, y, source = '') => {
      const last = lastPointRef.current;
      if (last) {
        if (Math.abs(x - last.x) > 2 || Math.abs(y - last.y) > 2) {
          didTouchMoveRef.current = true;
        }
      }
      lastPointRef.current = { x, y };
      setGhost((prev) => (prev ? { ...prev, x, y } : null));
      const idx = getDropIndexFromPoint(x, y);
      setDropIndexSafe(idx);
      if (idx != null) {
        lastValidDropIndexRef.current = idx;
        enteredTrackRef.current = true;
      } else if (isOverTrack(x, y)) {
        enteredTrackRef.current = true;
      }
    };
    const onMove = (e) => {
      if (!dragRef.current) return;
      if (pointerIdRef.current != null && e.pointerId !== pointerIdRef.current) return;
      updateFromPoint(e.clientX, e.clientY, 'pointermove');
      e.preventDefault();
    };
    const onTouchMove = (e) => {
      if (!dragRef.current) return;
      const touch = e.touches && e.touches[0];
      if (!touch) return;
      updateFromPoint(touch.clientX, touch.clientY, 'touchmove');
      e.preventDefault();
    };
    const finishDrag = (x, y, source = '') => {
      if (enteredTrackRef.current) {
        const lastX = lastPointRef.current?.x ?? x ?? 0;
        const fallbackIdx = getClosestDropIndex(lastX);
        const dropIdx = lastValidDropIndexRef.current ?? fallbackIdx ?? safeValue.length;
        onDropTrack(dropIdx);
      }
      dragRef.current = null;
      setDropIndexSafe(null);
      setTouchDragging(false);
      setGhost(null);
      pointerIdRef.current = null;
      document.body.classList.remove('touch-dragging');
      lastValidDropIndexRef.current = null;
      enteredTrackRef.current = false;
      document.body.style.position = '';
      document.body.style.top = '';
      document.body.style.left = '';
      document.body.style.right = '';
      document.body.style.width = '';
      window.scrollTo(0, scrollLockRef.current);
    };
    const onEnd = (e) => {
      if (!dragRef.current) return;
      if (pointerIdRef.current != null && e.pointerId !== pointerIdRef.current) return;
      finishDrag(e.clientX, e.clientY, 'pointerup');
    };
    const onTouchEnd = (e) => {
      if (!dragRef.current) return;
      const touch = e.changedTouches && e.changedTouches[0];
      finishDrag(touch ? touch.clientX : null, touch ? touch.clientY : null, 'touchend');
    };
    window.addEventListener('pointermove', onMove, { passive: false });
    window.addEventListener('touchmove', onTouchMove, { passive: false });
    window.addEventListener('pointerup', onEnd);
    window.addEventListener('pointercancel', onEnd);
    window.addEventListener('touchend', onTouchEnd, { passive: false });
    window.addEventListener('touchcancel', onTouchEnd, { passive: false });
    return () => {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('touchmove', onTouchMove);
      window.removeEventListener('pointerup', onEnd);
      window.removeEventListener('pointercancel', onEnd);
      window.removeEventListener('touchend', onTouchEnd);
      window.removeEventListener('touchcancel', onTouchEnd);
    };
  }, [touchDragging, getDropIndexFromPoint, getClosestDropIndex]);

  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      <div className="path-order-pool">
        {filtered.length === 0 ? (
          <div className="path-order-empty">暂无可用节点</div>
        ) : grouped.map(([group, items]) => (
          <div key={group} className="path-order-group">
            <button
              type="button"
              className="path-order-group-title"
              onClick={() => {
                setCollapsedGroups((prev) => {
                  const next = new Set(prev);
                  if (next.has(group)) next.delete(group);
                  else next.add(group);
                  return next;
                });
              }}
            >
              <span className={`path-order-group-caret${collapsedGroups.has(group) ? ' is-collapsed' : ''}`}>▾</span>
              <span>{group}</span>
              <span className="path-order-group-count">{items.length}</span>
            </button>
            {!collapsedGroups.has(group) && (
              <div className="path-order-group-items">
                {items.map((opt) => (
                  <div
                    key={opt.value}
                    className={`path-order-pool-chip${isTouch ? ' is-touch' : ''}`}
                    draggable={!isTouch}
                    onDragStart={() => {
                      if (isTouch) return;
                      dragRef.current = { source: 'pool', value: opt.value };
                    }}
                    onPointerDown={(e) => startTouchDrag({ source: 'pool', value: opt.value }, e)}
                    onClick={isTouch ? () => {
                      if (didTouchMoveRef.current) return;
                      addItem(opt.value);
                    } : undefined}
                  >
                    <span className="path-order-handle">＋</span>
                    <span>{opt.label}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
      {extra ? <Text type="secondary" style={{ fontSize: 12 }}>{extra}</Text> : null}
      <div
        className="path-order-track"
        ref={trackRef}
        onDragOver={(e) => e.preventDefault()}
        onDrop={() => onDropTrack()}
        onDragLeave={() => setDropIndex(null)}
      >
        {dropIndex === 0 ? <div className="path-drop-indicator" /> : null}
        {safeValue.length === 0 ? (
          <div className="path-order-empty">拖拽节点到这里形成路径</div>
        ) : safeValue.map((item, idx) => (
          <React.Fragment key={`${item}-${idx}`}>
            {dropIndex === idx ? <div className="path-drop-indicator" /> : null}
            <div
              className={`path-order-chip${isTouch ? ' is-touch' : ''}${dropIndex === idx ? ' path-order-chip-shift' : ''}`}
              draggable={!isTouch}
              onDragStart={() => {
                if (isTouch) return;
                dragRef.current = { source: 'track', value: item, index: idx };
              }}
              onPointerDown={(e) => startTouchDrag({ source: 'track', value: item, index: idx }, e)}
              onDragOver={(e) => {
                e.preventDefault();
                setDropIndex(idx + 1);
              }}
              onDrop={() => onDropTrack(idx)}
            >
              <span className="path-order-handle">≡</span>
              <span>{item}</span>
              {isTouch ? (
                <span className="path-order-actions">
                  <button
                    type="button"
                    className="path-order-action"
                    disabled={idx === 0}
                    onClick={(e) => {
                      e.stopPropagation();
                      moveItem(idx, idx - 1);
                    }}
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    className="path-order-action"
                    disabled={idx === safeValue.length - 1}
                    onClick={(e) => {
                      e.stopPropagation();
                      moveItem(idx, idx + 1);
                    }}
                  >
                    ↓
                  </button>
                </span>
              ) : null}
              <button
                type="button"
                className="path-order-remove"
                onClick={(e) => {
                  e.stopPropagation();
                  removeItem(item);
                }}
              >
                ×
              </button>
            </div>
          </React.Fragment>
        ))}
        {dropIndex === safeValue.length ? <div className="path-drop-indicator" /> : null}
      </div>
      {ghost && (
        <div
          className="path-order-ghost"
          style={{ transform: `translate(${ghost.x}px, ${ghost.y}px)` }}
        >
          <span className="path-order-handle">≡</span>
          <span>{ghost.text}</span>
        </div>
      )}
    </Space>
  );
};

const PathActionBar = ({ form, field, sourceField }) => {
  const reverseField = () => {
    const cur = form.getFieldValue(field);
    const next = Array.isArray(cur) ? [...cur].reverse() : [];
    form.setFieldsValue({ [field]: next });
  };
  const clearField = () => {
    form.setFieldsValue({ [field]: [] });
  };
  const fillFromSource = () => {
    if (!sourceField) return;
    const src = form.getFieldValue(sourceField);
    const next = Array.isArray(src) ? [...src].reverse() : [];
    form.setFieldsValue({ [field]: next });
  };
  return (
    <Space size={8} wrap>
      <Button size="small" onClick={reverseField}>反转顺序</Button>
      <Button size="small" onClick={clearField}>清空</Button>
      {sourceField ? <Button size="small" onClick={fillFromSource}>回程=正向反转</Button> : null}
    </Space>
  );
};

const escapeHtml = (input = '') => (
  input.replace(/[&<>"']/g, (ch) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] || ch
  ))
);

function NodeList({ onSelect, onShowInstall, refreshSignal }) {
  const [data, setData] = useState([]);
  const [searchText, setSearchText] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [filterRegion, setFilterRegion] = useState('all');
  const [filterTransport, setFilterTransport] = useState('all');
  const [cpuMin, setCpuMin] = useState(null);
  const [memMin, setMemMin] = useState(null);
  const [viewName, setViewName] = useState('');
  const [views, setViews] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('node_filter_views') || '[]');
    } catch (_) {
      return [];
    }
  });
  const [modalOpen, setModalOpen] = useState(false);
  const [form] = Form.useForm();
  const screens = useBreakpoint();
  const [isScrolling, setIsScrolling] = useState(false);
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagRunId, setDiagRunId] = useState('');
  const [diagReports, setDiagReports] = useState([]);
  const [diagMissing, setDiagMissing] = useState([]);
  const [diagTargets, setDiagTargets] = useState([]);
  const [diagFilter, setDiagFilter] = useState('');
  const [diagLimit, setDiagLimit] = useState(200);
  const [diagLoading, setDiagLoading] = useState(false);
  const [uninstallMap, setUninstallMap] = useState(new Map());
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletePlan, setDeletePlan] = useState({ routes: [] });
  const [deleteRoutes, setDeleteRoutes] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [endpointOpen, setEndpointOpen] = useState(false);
  const [endpointLoading, setEndpointLoading] = useState(false);
  const [endpointResults, setEndpointResults] = useState([]);
  const [endpointRunId, setEndpointRunId] = useState('');
  const [timeSyncOpen, setTimeSyncOpen] = useState(false);
  const [timeSyncLoading, setTimeSyncLoading] = useState(false);
  const [timeSyncResults, setTimeSyncResults] = useState([]);
  const [timeSyncRunId, setTimeSyncRunId] = useState('');
  const [timeSyncTZ, setTimeSyncTZ] = useState('Asia/Shanghai');

  const load = async () => {
    if (document.hidden || isScrolling) return;
    try {
      const [list, uninstallStatuses] = await Promise.all([
        api('GET', '/api/nodes'),
        api('GET', '/api/uninstall-status'),
      ]);
      const sorted = [...(list || [])].sort((a, b) => {
        const at = normalizeTimestamp(a.created_at);
        const bt = normalizeTimestamp(b.created_at);
        if (at !== bt) return bt - at;
        return (a.name || '').localeCompare(b.name || '');
      });
      const existing = new Map(sorted.map((n) => [n.name, n]));
      const nextMap = new Map();
      (uninstallStatuses || []).forEach((s) => {
        if (!s?.node) return;
        if (s.status === 'success') return;
        nextMap.set(s.node, s);
      });
      const merged = [...sorted];
      nextMap.forEach((s, name) => {
        if (!existing.has(name)) {
          merged.push({
            id: `ghost-${name}`,
            name,
            _ghost: true,
          });
        }
      });
      setData(merged.sort((a, b) => {
        const at = normalizeTimestamp(a.created_at);
        const bt = normalizeTimestamp(b.created_at);
        if (at !== bt) return bt - at;
        return (a.name || '').localeCompare(b.name || '');
      }));
      setUninstallMap(nextMap);
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

  const openDiag = () => {
    const online = data.filter((n) => isOnline(n.last_seen_at)).map((n) => n.name);
    setDiagTargets(online);
    setDiagOpen(true);
  };

  const openDelete = async (n) => {
    if (!n?.id || n._ghost) return;
    setDeleteTarget(n);
    setDeleteOpen(true);
    setDeleteLoading(true);
    try {
      const plan = await api('GET', `/api/nodes/${n.id}/delete-plan`);
      setDeletePlan(plan || { routes: [] });
      setDeleteRoutes((plan?.routes?.length || 0) > 0);
    } catch (e) {
      message.error(e.message);
      setDeleteOpen(false);
    } finally {
      setDeleteLoading(false);
    }
  };

  const confirmDelete = async () => {
    if (!deleteTarget?.id) return;
    if ((deletePlan.routes?.length || 0) > 0 && !deleteRoutes) {
      message.warning('请勾选同时删除这些线路');
      return;
    }
    try {
      setDeleteLoading(true);
      await api('POST', `/api/nodes/${deleteTarget.id}/delete`, { delete_routes: deleteRoutes });
      message.success('卸载指令已下发，等待节点上报完成');
      setDeleteOpen(false);
      setDeleteTarget(null);
      load();
    } catch (e) {
      message.error(e.message);
    } finally {
      setDeleteLoading(false);
    }
  };

  const fetchDiag = async (runId) => {
    if (!runId) return;
    setDiagLoading(true);
    try {
      const res = await api('GET', `/api/diag?run_id=${encodeURIComponent(runId)}`);
      setDiagReports(res.reports || []);
      setDiagMissing(res.missing || []);
    } catch (e) {
      message.error(e.message);
    }
    setDiagLoading(false);
  };

  useEffect(() => {
    if (!diagOpen || !diagRunId) return;
    const t = setInterval(() => fetchDiag(diagRunId), 2000);
    return () => clearInterval(t);
  }, [diagOpen, diagRunId]);

  useEffect(() => {
    if (!endpointOpen || !endpointRunId) return;
    const t = setInterval(async () => {
      try {
        const res = await api('GET', `/api/endpoint-check?run_id=${encodeURIComponent(endpointRunId)}`);
        setEndpointResults(res.results || []);
      } catch (e) {
        message.error(e.message);
      }
    }, 2000);
    return () => clearInterval(t);
  }, [endpointOpen, endpointRunId]);

  useEffect(() => {
    if (!timeSyncOpen || !timeSyncRunId) return;
    const t = setInterval(async () => {
      try {
        const res = await api('GET', `/api/time-sync?run_id=${encodeURIComponent(timeSyncRunId)}`);
        setTimeSyncResults(res.results || []);
      } catch (e) {
        message.error(e.message);
      }
    }, 2000);
    return () => clearInterval(t);
  }, [timeSyncOpen, timeSyncRunId]);

  const columns = useMemo(() => {
    if (screens.xl) return 4;
    if (screens.lg) return 3;
    if (screens.md) return 2;
    if (screens.sm) return 2;
    return 1;
  }, [screens]);

  const rowHeight = 360;
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

  const regionOptions = useMemo(() => {
    const set = new Set();
    data.forEach((n) => {
      const region = n.geo_region || n.geo_country || '未知地区';
      set.add(region);
    });
    return Array.from(set).sort((a, b) => a.localeCompare(b, 'zh'));
  }, [data]);

  const transportOptions = useMemo(() => {
    const set = new Set();
    data.forEach((n) => {
      const v = (n.transport || 'quic').toUpperCase();
      set.add(v);
    });
    return Array.from(set).sort();
  }, [data]);

  const displayData = useMemo(() => {
    const keyword = searchText.trim().toLowerCase();
    return data.filter((n) => {
      if (keyword) {
        const name = String(n.name || '').toLowerCase();
        if (!name.includes(keyword)) return false;
      }
      if (filterStatus !== 'all') {
        const online = isOnline(n.last_seen_at);
        if (filterStatus === 'online' && !online) return false;
        if (filterStatus === 'offline' && online) return false;
      }
      if (filterRegion !== 'all') {
        const region = n.geo_region || n.geo_country || '未知地区';
        if (region !== filterRegion) return false;
      }
      if (filterTransport !== 'all') {
        const v = (n.transport || 'quic').toUpperCase();
        if (v !== filterTransport) return false;
      }
      if (cpuMin != null && cpuMin !== '') {
        const cpu = n.cpu_usage || 0;
        if (cpu < cpuMin) return false;
      }
      if (memMin != null && memMin !== '') {
        const memPct = n.mem_total_bytes
          ? Math.round((n.mem_used_bytes || 0) / n.mem_total_bytes * 100)
          : 0;
        if (memPct < memMin) return false;
      }
      return true;
    });
  }, [data, searchText, filterStatus, filterRegion, filterTransport, cpuMin, memMin]);

  const resetFilters = () => {
    setSearchText('');
    setFilterStatus('all');
    setFilterRegion('all');
    setFilterTransport('all');
    setCpuMin(null);
    setMemMin(null);
  };

  const saveView = () => {
    const name = viewName.trim();
    if (!name) {
      message.warning('请输入视图名称');
      return;
    }
    const next = [...views.filter((v) => v.name !== name), {
      name,
      filters: {
        searchText,
        filterStatus,
        filterRegion,
        filterTransport,
        cpuMin,
        memMin,
      },
    }];
    setViews(next);
    localStorage.setItem('node_filter_views', JSON.stringify(next));
    message.success('视图已保存');
  };

  const applyView = (name) => {
    const v = views.find((x) => x.name === name);
    if (!v) return;
    const f = v.filters || {};
    setSearchText(f.searchText || '');
    setFilterStatus(f.filterStatus || 'all');
    setFilterRegion(f.filterRegion || 'all');
    setFilterTransport(f.filterTransport || 'all');
    setCpuMin(f.cpuMin ?? null);
    setMemMin(f.memMin ?? null);
  };

  const removeView = (name) => {
    const next = views.filter((v) => v.name !== name);
    setViews(next);
    localStorage.setItem('node_filter_views', JSON.stringify(next));
  };

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
      <Card
        className="page-card"
        title="节点列表"
        extra={
          <Space>
            <Tooltip title="诊断采集">
              <Button className="icon-btn" type="text" size="small" icon={<RadarChartOutlined />} onClick={openDiag} aria-label="诊断采集" />
            </Tooltip>
            <Tooltip title="一键配置对端">
              <Button
                className="icon-btn"
                type="text"
                size="small"
                icon={<ShareAltOutlined />}
                onClick={async () => {
                  try {
                    const res = await api('POST', '/api/peers/auto', {});
                    message.success(`已批量配置对端：新增${res.created || 0}，补全${res.updated || 0}`);
                    load();
                  } catch (e) {
                    message.error(e.message);
                  }
                }}
                aria-label="一键配置对端"
              />
            </Tooltip>
            <Tooltip title="对端检测">
              <Button
                className="icon-btn"
                type="text"
                size="small"
                icon={<ApiOutlined />}
                onClick={async () => {
                  setEndpointOpen(true);
                  setEndpointLoading(true);
                  try {
                    const res = await api('POST', '/api/endpoint-check/run', {});
                    setEndpointRunId(res.run_id || '');
                    setEndpointResults([]);
                  } catch (e) {
                    message.error(e.message);
                  }
                  setEndpointLoading(false);
                }}
                aria-label="对端检测"
              />
            </Tooltip>
            <Tooltip title="时间同步">
              <Button
                className="icon-btn"
                type="text"
                size="small"
                icon={<ClockCircleOutlined />}
                onClick={async () => {
                  setTimeSyncOpen(true);
                  setTimeSyncLoading(true);
                  try {
                    const res = await api('POST', '/api/time-sync/run', { timezone: timeSyncTZ });
                    setTimeSyncRunId(res.run_id || '');
                    setTimeSyncResults([]);
                  } catch (e) {
                    message.error(e.message);
                  }
                  setTimeSyncLoading(false);
                }}
                aria-label="时间同步"
              />
            </Tooltip>
          </Space>
        }
      >
        <div className="node-filter-bar">
          <Space wrap>
            <Input
              placeholder="搜索节点名称"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              allowClear
            />
            <Select
              placeholder="视图"
              options={views.map((v) => ({ label: v.name, value: v.name }))}
              onChange={applyView}
              allowClear
              style={{ minWidth: 140 }}
            />
            <Input
              placeholder="视图名称"
              value={viewName}
              onChange={(e) => setViewName(e.target.value)}
              style={{ minWidth: 140 }}
            />
            <Button onClick={saveView}>保存视图</Button>
            {views.length ? (
              <Select
                placeholder="删除视图"
                options={views.map((v) => ({ label: v.name, value: v.name }))}
                onChange={removeView}
                style={{ minWidth: 140 }}
              />
            ) : null}
            <Select
              value={filterStatus}
              onChange={setFilterStatus}
              options={[
                { label: '全部状态', value: 'all' },
                { label: '在线', value: 'online' },
                { label: '离线', value: 'offline' },
              ]}
              style={{ minWidth: 120 }}
            />
            <Select
              value={filterRegion}
              onChange={setFilterRegion}
              options={[{ label: '全部地区', value: 'all' }, ...regionOptions.map((r) => ({ label: r, value: r }))]}
              style={{ minWidth: 140 }}
            />
            <Select
              value={filterTransport}
              onChange={setFilterTransport}
              options={[{ label: '全部传输', value: 'all' }, ...transportOptions.map((v) => ({ label: v, value: v }))]}
              style={{ minWidth: 120 }}
            />
            <InputNumber
              min={0}
              max={100}
              value={cpuMin}
              onChange={setCpuMin}
              placeholder="CPU≥%"
            />
            <InputNumber
              min={0}
              max={100}
              value={memMin}
              onChange={setMemMin}
              placeholder="内存≥%"
            />
            <Button onClick={resetFilters}>清空筛选</Button>
          </Space>
        </div>
        <div className="node-list-viewport">
          <WindowScroller scrollElement={window}>
            {({ height, isScrolling, onChildScroll, scrollTop }) => (
              <AutoSizer disableHeight>
                {({ width }) => {
                  const columnWidth = Math.max(260, Math.floor((width - gutter * (columns - 1)) / columns));
                  const rowCount = Math.ceil(displayData.length / columns) || 1;
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
                        if (index >= displayData.length) return null;
                        const n = displayData[index];
                        const online = isOnline(n.last_seen_at);
                        const cellStyle = {
                          ...style,
                          width: style.width - gutter,
                          height: style.height - gutter,
                          paddingRight: gutter,
                          paddingBottom: gutter,
                          boxSizing: 'border-box',
                        };
                        const uninstall = uninstallMap.get(n.name);
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
                              extra={(
                                <Space size={6}>
                                  {uninstall?.status ? (
                                    <Tooltip title={uninstall.reason || ''}>
                                      <Tag color={uninstallStatusColor(uninstall.status)}>
                                        {uninstallStatusLabel(uninstall.status)}
                                      </Tag>
                                    </Tooltip>
                                  ) : null}
                                  <Tag color="blue">{n.transport?.toUpperCase() || 'QUIC'}</Tag>
                                </Space>
                              )}
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
                                  <Button size="small" type="primary" disabled={n._ghost} onClick={() => onSelect(n)}>管理</Button>
                                  <Button size="small" disabled={n._ghost} onClick={() => onShowInstall(n)}>安装</Button>
                                  <Button
                                    size="small"
                                    onClick={async () => {
                                      try {
                                        await navigator.clipboard.writeText(n.name || '');
                                        message.success('已复制节点名称');
                                      } catch (e) {
                                        message.error('复制失败');
                                      }
                                    }}
                                  >
                                    复制名称
                                  </Button>
                                  <Button size="small" danger disabled={n._ghost} onClick={() => openDelete(n)}>删除</Button>
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
      <Modal
        open={deleteOpen}
        onCancel={() => setDeleteOpen(false)}
        onOk={confirmDelete}
        confirmLoading={deleteLoading}
        okText="确认删除"
        title={deleteTarget ? `确认删除节点：${deleteTarget.name}` : '确认删除节点'}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>将先下发卸载指令，节点上报卸载成功后才会清除数据。</Text>
          {deletePlan.routes?.length ? (
            <>
              <Text>以下线路使用了该节点：</Text>
              <div style={{ border: '1px solid #f0f0f0', borderRadius: 6, padding: 8, maxHeight: 240, overflow: 'auto' }}>
                {deletePlan.routes.map((r) => (
                  <div key={r.id} style={{ padding: '6px 0', borderBottom: '1px dashed #f0f0f0' }}>
                    <div><Text strong>{r.name}</Text> <Text type="secondary">优先级 {r.priority || 1}</Text></div>
                    <div><Text type="secondary">路径：</Text>{(r.path || []).join(' -> ') || '-'}</div>
                    <div><Text type="secondary">回程：</Text>{(r.return_path || []).join(' -> ') || '-'}</div>
                  </div>
                ))}
              </div>
              <Checkbox checked={deleteRoutes} onChange={(e) => setDeleteRoutes(e.target.checked)}>
                同时删除这些线路
              </Checkbox>
            </>
          ) : (
            <Text type="secondary">未发现引用该节点的线路。</Text>
          )}
        </Space>
      </Modal>
      <Modal
        open={endpointOpen}
        onCancel={() => setEndpointOpen(false)}
        onOk={() => setEndpointOpen(false)}
        title="Endpoint 健康检测"
        width={900}
        okText="关闭"
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space>
            <Button
              loading={endpointLoading}
              onClick={async () => {
                setEndpointLoading(true);
                try {
                  const res = await api('POST', '/api/endpoint-check/run', {});
                  setEndpointRunId(res.run_id || '');
                  setEndpointResults([]);
                } catch (e) {
                  message.error(e.message);
                }
                setEndpointLoading(false);
              }}
            >
              重新检测
            </Button>
            <Button
              disabled={!endpointRunId}
              onClick={async () => {
                try {
                  const res = await api('GET', `/api/endpoint-check?run_id=${encodeURIComponent(endpointRunId)}`);
                  setEndpointResults(res.results || []);
                } catch (e) {
                  message.error(e.message);
                }
              }}
            >
              刷新
            </Button>
            <Button
              disabled={!endpointResults.length}
              onClick={async () => {
                const text = endpointResults
                  .map((r) => `${r.node} -> ${r.peer} ${r.endpoint} ok=${r.ok} rtt=${r.rtt_ms || 0}ms ${r.status || ''} ${r.error || ''}`.trim())
                  .join('\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制检测结果');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制结果
            </Button>
          </Space>
          <Table
            rowKey={(r) => `${r.node}-${r.peer}-${r.endpoint}`}
            dataSource={endpointResults}
            loading={endpointLoading}
            pagination={{ pageSize: 8 }}
            columns={[
              { title: '节点', dataIndex: 'node' },
              { title: 'Peer', dataIndex: 'peer' },
              { title: 'Endpoint', dataIndex: 'endpoint' },
              {
                title: '状态',
                render: (_, r) => (
                  r.ok ? <Tag color="green">OK</Tag> : <Tag color="red">FAIL</Tag>
                ),
              },
              { title: 'RTT', dataIndex: 'rtt_ms', render: (v) => (v ? `${v}ms` : '-') },
              { title: 'HTTP', dataIndex: 'status' },
              { title: '错误', dataIndex: 'error' },
            ]}
          />
        </Space>
      </Modal>
      <Modal
        open={timeSyncOpen}
        onCancel={() => setTimeSyncOpen(false)}
        onOk={() => setTimeSyncOpen(false)}
        title="时间同步"
        width={900}
        okText="关闭"
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Space>
            <Input
              value={timeSyncTZ}
              onChange={(e) => setTimeSyncTZ(e.target.value)}
              style={{ width: 220 }}
              placeholder="Asia/Shanghai"
            />
            <Button
              loading={timeSyncLoading}
              onClick={async () => {
                setTimeSyncLoading(true);
                try {
                  const res = await api('POST', '/api/time-sync/run', { timezone: timeSyncTZ });
                  setTimeSyncRunId(res.run_id || '');
                  setTimeSyncResults([]);
                } catch (e) {
                  message.error(e.message);
                }
                setTimeSyncLoading(false);
              }}
            >
              重新执行
            </Button>
            <Button
              disabled={!timeSyncRunId}
              onClick={async () => {
                try {
                  const res = await api('GET', `/api/time-sync?run_id=${encodeURIComponent(timeSyncRunId)}`);
                  setTimeSyncResults(res.results || []);
                } catch (e) {
                  message.error(e.message);
                }
              }}
            >
              刷新
            </Button>
            <Button
              disabled={!timeSyncResults.length}
              onClick={async () => {
                const text = timeSyncResults
                  .map((r) => {
                    const steps = (r.steps || [])
                      .map((s) => {
                        const tag = s.skipped ? 'skip' : s.ok ? 'ok' : 'fail';
                        const msg = s.error || s.output || '';
                        return `- [${tag}] ${s.command}${msg ? ` :: ${msg}` : ''}`;
                      })
                      .join('\n');
                    return `### ${r.node} ok=${r.success} tz=${r.timezone}\n${steps}`;
                  })
                  .join('\n\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制结果');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制结果
            </Button>
          </Space>
          <div className="diag-report-list">
            {(timeSyncResults || []).map((r) => {
              const text = (r.steps || [])
                .map((s) => {
                  const tag = s.skipped ? 'skip' : s.ok ? 'ok' : 'fail';
                  const msg = s.error || s.output || '';
                  return `[${tag}] ${s.command}${msg ? ` :: ${msg}` : ''}`;
                })
                .join('\n');
              return (
                <Card
                  key={r.node}
                  size="small"
                  className={`diag-report-card ${r.success ? '' : 'diag-node-fail'}`}
                  title={<Space><Tag color={r.success ? 'green' : 'red'}>{r.node}</Tag></Space>}
                  extra={<Text type="secondary">TZ: {r.timezone || '-'}</Text>}
                >
                  <Input.TextArea value={text} rows={6} readOnly />
                </Card>
              );
            })}
          </div>
        </Space>
      </Modal>
      <Modal
        open={diagOpen}
        onCancel={() => setDiagOpen(false)}
        onOk={() => setDiagOpen(false)}
        title="诊断日志采集"
        width={900}
        okText="关闭"
      >
        <Space direction="vertical" size={12} style={{ width: '100%' }}>
          <Row gutter={[12, 12]}>
            <Col xs={24} md={12}>
              <Text type="secondary">目标节点</Text>
              <Checkbox.Group
                style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 6 }}
                value={diagTargets}
                onChange={(vals) => setDiagTargets(vals)}
              >
                {(data || []).map((n) => (
                  <Checkbox key={n.name} value={n.name}>
                    {n.name}
                  </Checkbox>
                ))}
              </Checkbox.Group>
            </Col>
            <Col xs={12} md={6}>
              <Text type="secondary">行数</Text>
              <Input
                type="number"
                min={50}
                max={2000}
                value={diagLimit}
                onChange={(e) => setDiagLimit(Number(e.target.value || 0))}
              />
            </Col>
            <Col xs={12} md={6}>
              <Text type="secondary">过滤关键字</Text>
              <Input value={diagFilter} onChange={(e) => setDiagFilter(e.target.value)} placeholder="可选" />
            </Col>
          </Row>
          <Space>
            <Button
              type="primary"
              loading={diagLoading}
              onClick={async () => {
                if (!diagTargets.length) {
                  message.warning('请先选择节点');
                  return;
                }
                setDiagLoading(true);
                try {
                  const res = await api('POST', '/api/diag/run', {
                    nodes: diagTargets,
                    limit: diagLimit,
                    contains: diagFilter,
                  });
                  setDiagRunId(res.run_id || '');
                  setDiagMissing(res.offline || []);
                  setDiagReports([]);
                  message.success(`已下发诊断到 ${res.sent?.length || 0} 个节点`);
                  setTimeout(() => fetchDiag(res.run_id), 800);
                } catch (e) {
                  message.error(e.message);
                }
                setDiagLoading(false);
              }}
            >
              开始采集
            </Button>
            <Button disabled={!diagRunId} onClick={() => fetchDiag(diagRunId)}>
              刷新
            </Button>
            <Button
              disabled={!diagReports.length}
              onClick={async () => {
                const text = diagReports
                  .map((r) => `### ${r.node}\n${(r.lines || []).join('\n')}`)
                  .join('\n\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制全部日志');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制全部
            </Button>
          </Space>
          {diagMissing.length > 0 && (
            <Text type="secondary">未返回：{diagMissing.join(', ')}</Text>
          )}
          <div className="diag-report-list">
            {(diagReports || []).map((r) => (
              <Card
                key={r.node}
                size="small"
                className="diag-report-card"
                title={<Space><Tag color="blue">{r.node}</Tag><Text type="secondary">{r.at ? new Date(r.at).toLocaleString() : '-'}</Text></Space>}
                extra={
                  <Button
                    size="small"
                    onClick={async () => {
                      const text = `### ${r.node}\n${(r.lines || []).join('\n')}`;
                      try {
                        await navigator.clipboard.writeText(text);
                        message.success(`已复制 ${r.node}`);
                      } catch (e) {
                        message.error('复制失败，请手动选择文本');
                      }
                    }}
                  >
                    复制
                  </Button>
                }
              >
                <Input.TextArea
                  value={(r.lines || []).join('\n')}
                  rows={8}
                  readOnly
                />
              </Card>
            ))}
          </div>
        </Space>
      </Modal>
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

function NodeMap({ refreshSignal, onSelect, onOpenNode }) {
  const [nodes, setNodes] = useState([]);
  const [mapReady, setMapReady] = useState(false);
  const [mapError, setMapError] = useState('');
  const [autoFit, setAutoFit] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerNode, setDrawerNode] = useState(null);
  const mapRef = useRef(null);
  const mapInstance = useRef(null);
  const markersRef = useRef(new Map());
  const hoverTimer = useRef(null);

  const loadNodes = async () => {
    try {
      const list = await api('GET', '/api/nodes');
      setNodes(list || []);
    } catch (e) {
      message.error(e.message);
    }
  };

  useEffect(() => {
    loadNodes();
    const timer = setInterval(loadNodes, 6000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (refreshSignal > 0) loadNodes();
  }, [refreshSignal]);

  useEffect(() => {
    if (!mapRef.current) return;
    if (mapInstance.current) return;
    try {
      const map = L.map(mapRef.current, {
        zoomControl: true,
        attributionControl: true,
      }).setView([20, 0], 2);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors',
      }).addTo(map);
      map.on('zoomstart', () => setAutoFit(false));
      map.on('dragstart', () => setAutoFit(false));
      mapInstance.current = map;
      setMapReady(true);
      setTimeout(() => map.invalidateSize(), 0);
    } catch (e) {
      setMapError(e.message || '地图加载失败');
    }
  }, []);

  const nodeLocations = useMemo(() => (
    nodes.map((node) => {
      const ip = String(node.geo_ip || (node.public_ips || [])[0] || '').trim();
      const geo = {
        lat: Number(node.geo_lat),
        lng: Number(node.geo_lng),
        city: node.geo_city,
        region: node.geo_region,
        country: node.geo_country,
      };
      return { node, ip, geo };
    })
  ), [nodes]);

  useEffect(() => {
    const map = mapInstance.current;
    if (!map) return;
    const active = nodeLocations.filter(
      (n) => n.geo && Number.isFinite(n.geo.lat) && Number.isFinite(n.geo.lng),
    );
    if (active.length === 0) return;
    const bounds = L.latLngBounds();

    const nextKeys = new Set();
    active.forEach(({ node, ip, geo }) => {
      const key = node.id || node.name;
      if (!key) return;
      nextKeys.add(key);
      const position = [geo.lat, geo.lng];
      const locationText = [geo.city, geo.region, geo.country].filter(Boolean).join(' / ');
      const statusText = isOnline(node.last_seen_at) ? '在线' : '离线';
      const statusColor = isOnline(node.last_seen_at) ? '#16a34a' : '#64748b';
      const cpu = node.cpu_usage?.toFixed ? Number(node.cpu_usage.toFixed(1)) : 0;
      const cpuColor = cpu >= 85 ? '#ef4444' : cpu >= 70 ? '#f59e0b' : cpu >= 50 ? 'linear-gradient(90deg,#0a66ff,#22c55e)' : '#0a66ff';
      const memPct = node.mem_total_bytes
        ? Math.min(100, Math.round((node.mem_used_bytes || 0) / node.mem_total_bytes * 100))
        : 0;
      const memColor = memPct >= 85 ? '#ef4444' : memPct >= 70 ? '#f59e0b' : memPct >= 50 ? 'linear-gradient(90deg,#0a66ff,#22c55e)' : '#0a66ff';
      const memText = node.mem_total_bytes
        ? `${formatBytes(node.mem_used_bytes)} / ${formatBytes(node.mem_total_bytes)}`
        : '-';
      const uptimeText = node.uptime_sec ? formatUptime(node.uptime_sec) : '-';
      const lastSeenText = node.last_seen_at ? formatRelativeTime(node.last_seen_at) : '-';
      const html = `
        <div class="node-map-card">
          <div class="node-map-title">
            <span class="node-map-dot" style="background:${statusColor};"></span>
            <span>${escapeHtml(node.name || '-')}</span>
          </div>
          <div class="node-map-meta">IP：${escapeHtml(ip || '-')}</div>
          <div class="node-map-meta">${escapeHtml(locationText || '未知位置')}</div>
          <div class="node-map-status">${escapeHtml(statusText)}</div>
        </div>
      `;
      const detailHtml = `
        <div class="node-map-detail">
          <div class="node-map-detail-head">
            <span class="node-map-dot" style="background:${statusColor};"></span>
            <span class="node-map-detail-name">${escapeHtml(node.name || '-')}</span>
            <span class="node-map-tag node-map-tag-status ${isOnline(node.last_seen_at) ? 'node-map-tag-status-on' : 'node-map-tag-status-off'}">${escapeHtml(statusText)}</span>
            <span class="node-map-tag node-map-tag-transport">${escapeHtml((node.transport || 'quic').toUpperCase())}</span>
          </div>
          <div class="node-map-detail-grid">
            <div class="node-map-metric">
              <div class="node-map-metric-label">CPU</div>
              <div class="node-map-metric-sub">占用：${escapeHtml(String(cpu))}%</div>
              <div class="node-map-progress">
                <span style="width:${cpu}%;background:${cpuColor};"></span>
              </div>
            </div>
            <div class="node-map-metric">
              <div class="node-map-metric-label">内存</div>
              <div class="node-map-metric-sub">占用：${escapeHtml(String(memPct))}%</div>
              <div class="node-map-metric-sub">已用：${escapeHtml(memText)}</div>
              <div class="node-map-progress">
                <span style="width:${memPct}%;background:${memColor};"></span>
              </div>
            </div>
          </div>
          <div class="node-map-detail-meta">
            <div>IP：${escapeHtml(ip || '-')}</div>
            <div>位置：${escapeHtml(locationText || '未知位置')}</div>
            <div>上行：${escapeHtml(formatBytes(node.net_out_bytes))}</div>
            <div>下行：${escapeHtml(formatBytes(node.net_in_bytes))}</div>
            <div>运行：${escapeHtml(uptimeText)}</div>
            <div>上报：${escapeHtml(lastSeenText)}</div>
          </div>
        </div>
      `;
      const existing = markersRef.current.get(key);
      if (existing) {
        const last = existing._nodeMapState || {};
        const posChanged = last.lat !== geo.lat || last.lng !== geo.lng;
        if (posChanged) {
          existing.setLatLng(position);
        }
        if (last.html !== html) {
          existing.setIcon(L.divIcon({
            className: 'node-map-marker',
            html,
            iconSize: [220, 78],
            iconAnchor: [110, 78],
          }));
        }
        if (last.detailHtml !== detailHtml) {
          existing.setTooltipContent(detailHtml);
        }
        existing._nodeMapState = { lat: geo.lat, lng: geo.lng, html, detailHtml };
      } else {
        const marker = L.marker(position, {
          title: node.name || ip,
          icon: L.divIcon({
            className: 'node-map-marker',
            html,
            iconSize: [220, 78],
            iconAnchor: [110, 78],
          }),
        });
        const tooltip = L.tooltip({
          direction: 'top',
          offset: [0, -10],
          opacity: 1,
          className: 'node-map-tooltip',
          interactive: true,
        }).setContent(detailHtml);
        marker.bindTooltip(tooltip);
        marker.on('mouseover', () => {
          if (hoverTimer.current) window.clearTimeout(hoverTimer.current);
          marker.openTooltip();
        });
        marker.on('mouseout', () => {
          if (hoverTimer.current) window.clearTimeout(hoverTimer.current);
          hoverTimer.current = window.setTimeout(() => marker.closeTooltip(), 160);
        });
        marker.on('tooltipopen', (e) => {
          const el = e.tooltip.getElement?.();
          if (!el) return;
          const onEnter = () => {
            if (hoverTimer.current) window.clearTimeout(hoverTimer.current);
          };
          const onLeave = () => {
            if (hoverTimer.current) window.clearTimeout(hoverTimer.current);
            hoverTimer.current = window.setTimeout(() => marker.closeTooltip(), 160);
          };
          el.addEventListener('mouseenter', onEnter);
          el.addEventListener('mouseleave', onLeave);
          e.tooltip._nodeMapHandlers = { onEnter, onLeave };
        });
        marker.on('tooltipclose', (e) => {
          const el = e.tooltip.getElement?.();
          const handlers = e.tooltip._nodeMapHandlers;
          if (!el || !handlers) return;
          el.removeEventListener('mouseenter', handlers.onEnter);
          el.removeEventListener('mouseleave', handlers.onLeave);
          e.tooltip._nodeMapHandlers = null;
        });
      marker.on('click', () => {
        setDrawerNode(node);
        setDrawerOpen(true);
      });
        marker.addTo(map);
        marker._nodeMapState = { lat: geo.lat, lng: geo.lng, html, detailHtml };
        markersRef.current.set(key, marker);
      }
      bounds.extend(position);
    });

    markersRef.current.forEach((marker, key) => {
      if (!nextKeys.has(key)) {
        marker.remove();
        markersRef.current.delete(key);
      }
    });

    if (autoFit) {
      map.fitBounds(bounds, { padding: [80, 80] });
      if (map.getZoom() > 5) map.setZoom(5);
    }
  }, [nodeLocations, autoFit]);

  const missing = nodeLocations.filter(
    (n) => !n.geo || !Number.isFinite(n.geo.lat) || !Number.isFinite(n.geo.lng),
  );

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card className="page-card" title="节点地图">
        <div className="map-shell">
          <div ref={mapRef} className="map-canvas" />
          <Button
            className="map-fit-btn"
            size="small"
            disabled={!mapReady}
            onClick={() => setAutoFit(true)}
          >
            重新适配
          </Button>
          {mapError ? (
            <div className="map-overlay">
              <Text type="danger">{mapError}</Text>
            </div>
          ) : !mapReady ? (
            <div className="map-overlay">
              <Text type="secondary">地图加载中...</Text>
            </div>
          ) : null}
        </div>
      </Card>
      <Card className="page-card" title="未定位节点">
        {missing.length === 0 ? (
          <Text type="secondary">全部节点已定位。</Text>
        ) : (
          <Space wrap>
            {missing.map((n) => (
              <Tag key={n.node.id || n.node.name} color="default">
                {n.node.name || '未命名'}
              </Tag>
            ))}
          </Space>
        )}
      </Card>
      <Drawer
        placement="right"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        width={420}
        title={drawerNode ? `节点详情：${drawerNode.name}` : '节点详情'}
      >
        {drawerNode ? (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            <Space>
              <Tooltip title="进入管理">
                <Button
                  type="text"
                  className="icon-btn icon-btn-primary"
                  icon={<GearIcon />}
                  onClick={() => {
                    if (onSelect) onSelect(drawerNode);
                    if (onOpenNode) onOpenNode();
                    setDrawerOpen(false);
                  }}
                />
              </Tooltip>
              <Tooltip title="复制节点名称">
                <Button
                  type="text"
                  className="icon-btn icon-btn-neutral"
                  icon={<CopyOutlined />}
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(drawerNode.name || '');
                      message.success('已复制节点名称');
                    } catch (e) {
                      message.error('复制失败');
                    }
                  }}
                />
              </Tooltip>
              <Tooltip title="Endpoint 检测">
                <Button
                  type="text"
                  className="icon-btn icon-btn-success"
                  icon={<ApiOutlined />}
                  onClick={async () => {
                    try {
                      await api('POST', '/api/endpoint-check/run', { nodes: [drawerNode.name] });
                      message.success('已触发 Endpoint 检测');
                    } catch (e) {
                      message.error(e.message);
                    }
                  }}
                />
              </Tooltip>
              <Tooltip title="时间同步">
                <Button
                  type="text"
                  className="icon-btn icon-btn-warn"
                  icon={<ClockCircleOutlined />}
                  onClick={async () => {
                    try {
                      await api('POST', '/api/time-sync/run', { nodes: [drawerNode.name], timezone: 'Asia/Shanghai' });
                      message.success('已触发时间同步');
                    } catch (e) {
                      message.error(e.message);
                    }
                  }}
                />
              </Tooltip>
            </Space>
            <Descriptions size="small" column={1}>
              <Descriptions.Item label="状态">{isOnline(drawerNode.last_seen_at) ? '在线' : '离线'}</Descriptions.Item>
              <Descriptions.Item label="IP">{drawerNode.geo_ip || (drawerNode.public_ips || []).join(', ') || '-'}</Descriptions.Item>
              <Descriptions.Item label="位置">
                {[drawerNode.geo_city, drawerNode.geo_region, drawerNode.geo_country].filter(Boolean).join(' / ') || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="CPU">{drawerNode.cpu_usage?.toFixed ? `${drawerNode.cpu_usage.toFixed(1)}%` : '-'}</Descriptions.Item>
              <Descriptions.Item label="内存">
                {drawerNode.mem_total_bytes
                  ? `${formatBytes(drawerNode.mem_used_bytes)} / ${formatBytes(drawerNode.mem_total_bytes)}`
                  : '-'}
              </Descriptions.Item>
            </Descriptions>
          </Space>
        ) : null}
      </Drawer>
    </Space>
  );
}

function NodeDetail({ node, onBack, refreshList, onShowInstall }) {
  const [detail, setDetail] = useState(node);
  const [updateStatus, setUpdateStatus] = useState(null);
  const [uninstallStatus, setUninstallStatus] = useState(null);
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
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deletePlan, setDeletePlan] = useState({ routes: [] });
  const [deleteRoutes, setDeleteRoutes] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const load = async () => {
    try {
      const detailRes = await api('GET', `/api/nodes/${node.id}`);
      if (detailRes?.routes) {
        detailRes.routes = [...detailRes.routes].sort((a, b) => {
          const at = normalizeTimestamp(a.created_at);
          const bt = normalizeTimestamp(b.created_at);
          if (at !== bt) return bt - at;
          return (a.name || '').localeCompare(b.name || '');
        });
      }
      setDetail(detailRes);
      setUpdateStatus(await api('GET', `/api/nodes/${node.id}/update-status`));
      setUninstallStatus(await api('GET', `/api/nodes/${node.id}/uninstall-status`));
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
      const path = (v.path || []).filter(Boolean);
      if (path.length < 2) {
        message.warning('路径至少包含入口和出口节点');
        return;
      }
      if (path[0] !== detail.name) {
        message.warning('路径第一个必须是入口节点');
        return;
      }
      const exit = path[path.length - 1];
      await api('POST', `/api/nodes/${node.id}/routes`, { ...v, path, exit });
      message.success(`线路已创建并分配到入口节点 ${detail.name}`);
      setRouteOpen(false);
      routeForm.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };
  const openDelete = async () => {
    setDeleteOpen(true);
    setDeleteLoading(true);
    try {
      const plan = await api('GET', `/api/nodes/${node.id}/delete-plan`);
      setDeletePlan(plan || { routes: [] });
      setDeleteRoutes((plan?.routes?.length || 0) > 0);
    } catch (e) {
      message.error(e.message);
      setDeleteOpen(false);
    } finally {
      setDeleteLoading(false);
    }
  };
  const confirmDelete = async () => {
    try {
      setDeleteLoading(true);
      if ((deletePlan.routes?.length || 0) > 0 && !deleteRoutes) {
        message.warning('请勾选同时删除这些线路');
        setDeleteLoading(false);
        return;
      }
      await api('POST', `/api/nodes/${node.id}/delete`, { delete_routes: deleteRoutes });
      message.success('卸载指令已下发，等待节点上报完成');
      setDeleteOpen(false);
      onBack();
      refreshList();
    } catch (e) {
      message.error(e.message);
    } finally {
      setDeleteLoading(false);
    }
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
    { title: '回程路径', dataIndex: 'return_path', render: (p = []) => (p || []).map((n) => <Tag key={n}>{n}</Tag>) },
    { title: '回程模式', render: (_, r) => ((r.return_path || []).length ? <Tag color="green">指定回程</Tag> : <Tag>自动回程</Tag>) },
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
          <Button href={joinUrl(getApiBase(), `/nodes/${detail.id}/config`)} target="_blank">下载配置</Button>
          <Button onClick={() => onShowInstall(detail)}>安装脚本</Button>
          <Button
            onClick={() => {
              Modal.confirm({
                title: '确认触发强制更新？',
                content: '节点将重新下载并替换二进制，随后自动重启。',
                onOk: async () => {
                  try {
                    await api('POST', `/api/nodes/${detail.id}/force-update`);
                    message.success('已触发强制更新');
                    load();
                  } catch (e) {
                    message.error(e.message);
                  }
                },
              });
            }}
          >
            强制更新
          </Button>
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
          <Button danger onClick={openDelete}>删除</Button>
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
        <Descriptions.Item label="卸载状态">
          {(() => {
            if (!uninstallStatus) return '-';
            const status = uninstallStatus.status || 'unknown';
            const tip = uninstallStatus.reason ? <div>原因：{uninstallStatus.reason}</div> : null;
            return (
              <Tooltip title={tip}>
                <Tag color={uninstallStatusColor(status)}>{uninstallStatusLabel(status)}</Tag>
              </Tooltip>
            );
          })()}
        </Descriptions.Item>
        <Descriptions.Item label="更新状态">
          {(() => {
            if (!updateStatus) return '-';
            const status = updateStatus.status || 'unknown';
            const labelMap = {
              in_progress: '更新中',
              success: '更新成功',
              failed: '更新失败',
              skipped: '已是最新',
            };
            const colorMap = {
              in_progress: 'blue',
              success: 'green',
              failed: 'red',
              skipped: 'default',
              unknown: 'default',
            };
            const label = labelMap[status] || '未知';
            const tip = (
              <div>
                <div>版本：{updateStatus.version || '-'}</div>
                <div>触发：{updateStatus.forced ? '强制' : '自动'}</div>
                {updateStatus.reason ? <div>原因：{updateStatus.reason}</div> : null}
              </div>
            );
            return (
              <Tooltip title={tip}>
                <Tag color={colorMap[status] || 'default'}>{label}</Tag>
              </Tooltip>
            );
          })()}
        </Descriptions.Item>
        <Descriptions.Item label="更新结果时间">
          {updateStatus && updateStatus.updated_at
            ? <Tooltip title={new Date(updateStatus.updated_at).toLocaleString()}>{formatRelativeTime(updateStatus.updated_at)}</Tooltip>
            : '-'}
        </Descriptions.Item>
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
                <Space style={{ marginBottom: 8 }}>
                  <Button type="primary" onClick={() => setPeerOpen(true)}>添加对端</Button>
                  <Button
                    onClick={async () => {
                      try {
                        const res = await api('POST', `/api/nodes/${detail.id}/peers/auto`, {});
                        message.success(`已生成对端：新增${res.created || 0}，补全${res.updated || 0}`);
                        load();
                      } catch (e) {
                        message.error(e.message);
                      }
                    }}
                  >
                    自动配置对端
                  </Button>
                </Space>
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

      <Modal
        open={deleteOpen}
        onCancel={() => setDeleteOpen(false)}
        onOk={confirmDelete}
        confirmLoading={deleteLoading}
        okText="确认删除"
        title="确认删除节点"
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>将先下发卸载指令，节点上报卸载成功后才会清除数据。</Text>
          {deletePlan.routes?.length ? (
            <>
              <Text>以下线路使用了该节点：</Text>
              <div style={{ border: '1px solid #f0f0f0', borderRadius: 6, padding: 8, maxHeight: 240, overflow: 'auto' }}>
                {deletePlan.routes.map((r) => (
                  <div key={r.id} style={{ padding: '6px 0', borderBottom: '1px dashed #f0f0f0' }}>
                    <div><Text strong>{r.name}</Text> <Text type="secondary">优先级 {r.priority || 1}</Text></div>
                    <div><Text type="secondary">路径：</Text>{(r.path || []).join(' -> ') || '-'}</div>
                    <div><Text type="secondary">回程：</Text>{(r.return_path || []).join(' -> ') || '-'}</div>
                  </div>
                ))}
              </div>
              <Checkbox checked={deleteRoutes} onChange={(e) => setDeleteRoutes(e.target.checked)}>
                同时删除这些线路
              </Checkbox>
            </>
          ) : (
            <Text type="secondary">未发现引用该节点的线路。</Text>
          )}
        </Space>
      </Modal>

      <Modal open={routeOpen} onCancel={() => setRouteOpen(false)} onOk={addRoute} title="添加线路" width={600}>
        <Form layout="vertical" form={routeForm} initialValues={{ priority: 1 }}>
          <Form.Item name="name" label="线路名称" rules={[{ required: true }]}><Input placeholder="如: 成都->新加坡-1" /></Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{ required: true }]}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item label="路径节点顺序">
            <div className="path-action-bar">
              <PathActionBar form={routeForm} field="path" />
            </div>
            <Form.Item name="path" rules={[{ required: true, message: '请选择路径' }]} noStyle>
              <PathOrderEditor
                options={(allNodes || []).map((n) => ({
                  label: n.name,
                  value: n.name,
                  region: n.geo_region,
                  country: n.geo_country,
                }))}
                placeholder="从起点到出口的节点顺序"
                extra="首节点必须是入口，末节点为出口"
              />
            </Form.Item>
          </Form.Item>
          <Form.Item label="回程路径节点顺序 (可选)" tooltip="从出口回到入口的节点顺序，需以出口开头、入口结尾">
            <div className="path-action-bar">
              <PathActionBar form={routeForm} field="return_path" sourceField="path" />
            </div>
            <Form.Item name="return_path" noStyle>
              <PathOrderEditor
                options={(allNodes || []).map((n) => ({
                  label: n.name,
                  value: n.name,
                  region: n.geo_region,
                  country: n.geo_country,
                }))}
                placeholder="从出口回到入口的节点顺序"
              />
            </Form.Item>
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
            const path = (v.path || []).filter(Boolean);
            if (path.length < 2) {
              message.warning('路径至少包含入口和出口节点');
              return;
            }
            if (path[0] !== detail.name) {
              message.warning('路径第一个必须是入口节点');
              return;
            }
            const exit = path[path.length - 1];
            await api('PUT', `/api/nodes/${node.id}/routes/${v.id}`, { ...v, path, exit });
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
          <Form.Item name="priority" label="优先级" rules={[{ required: true }]}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="path"
            label="路径节点顺序"
            rules={[{ required: true }]}
          >
            <div className="path-action-bar">
              <PathActionBar form={routeEditForm} field="path" />
            </div>
            <PathOrderEditor
              options={(allNodes || []).map((n) => ({
                label: n.name,
                value: n.name,
                region: n.geo_region,
                country: n.geo_country,
              }))}
              placeholder="从起点到出口的节点顺序"
              extra="首节点必须是入口，末节点为出口"
            />
          </Form.Item>
          <Form.Item
            name="return_path"
            label="回程路径节点顺序 (可选)"
            tooltip="从出口回到入口的节点顺序，需以出口开头、入口结尾"
          >
            <div className="path-action-bar">
              <PathActionBar form={routeEditForm} field="return_path" sourceField="path" />
            </div>
            <PathOrderEditor
              options={(allNodes || []).map((n) => ({
                label: n.name,
                value: n.name,
                region: n.geo_region,
                country: n.geo_country,
              }))}
              placeholder="从出口回到入口的节点顺序"
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
  const [allNodes, setAllNodes] = useState([]);
  const [routeOpen, setRouteOpen] = useState(false);
  const [routeForm] = Form.useForm();
  const [routeSearch, setRouteSearch] = useState('');
  const [filterEntry, setFilterEntry] = useState('all');
  const [filterExit, setFilterExit] = useState('all');
  const [filterStatus, setFilterStatus] = useState('all');
  const [templates, setTemplates] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('route_templates') || '[]');
    } catch (_) {
      return [];
    }
  });
  const [templateName, setTemplateName] = useState('');
  const [diagOpen, setDiagOpen] = useState(false);
  const [diagRunId, setDiagRunId] = useState('');
  const [diagEvents, setDiagEvents] = useState([]);
  const [diagReports, setDiagReports] = useState([]);
  const [diagMissing, setDiagMissing] = useState([]);
  const [diagCachedAt, setDiagCachedAt] = useState(null);
  const [diagRoute, setDiagRoute] = useState(null);
  const [diagLoading, setDiagLoading] = useState(false);
  const [logOpen, setLogOpen] = useState(false);
  const [logRunId, setLogRunId] = useState('');
  const [logReports, setLogReports] = useState([]);
  const [logMissing, setLogMissing] = useState([]);
  const [logCachedAt, setLogCachedAt] = useState(null);
  const [logLoading, setLogLoading] = useState(false);
  const [logRoute, setLogRoute] = useState(null);
  const load = async () => {
    setLoading(true);
    try {
      const [nodes, probes, returnStatus] = await Promise.all([
        api('GET', '/api/nodes'),
        api('GET', '/api/probes'),
        api('GET', '/api/return-status'),
      ]);
      const online = new Map();
      (nodes || []).forEach((n) => {
        online.set(n.name, isOnline(n.last_seen_at));
      });
      setOnlineMap(online);
      setAllNodes(nodes || []);
      const probeMap = new Map();
      (probes || []).forEach((p) => {
        probeMap.set(`${p.node}::${p.route}`, p);
      });
      const statusMap = new Map();
      (returnStatus || []).forEach((st) => {
        const key = `${st.entry}::${st.route}::${st.exit}`;
        const prev = statusMap.get(key);
        const nextTs = new Date(st.updated_at || 0).getTime();
        const prevTs = prev ? new Date(prev.updated_at || 0).getTime() : 0;
        if (!prev || nextTs > prevTs) {
          statusMap.set(key, st);
        }
      });
      const r = [];
      (nodes || []).forEach((n) => {
        (n.routes || []).forEach((rt) => {
          const key = `${n.name}::${rt.name}`;
          const pb = probeMap.get(key);
          const stKey = `${n.name}::${rt.name}::${rt.exit}`;
          const st = statusMap.get(stKey) || null;
          r.push({
            key,
            node: n.name,
            route: rt.name,
            exit: rt.exit,
            priority: rt.priority,
            path: rt.path || [],
            return_path: rt.return_path || [],
            return_status: st,
            probe: pb || null,
            created_at: rt.created_at,
          });
        });
      });
      setRows(r.sort((a, b) => {
        const at = normalizeTimestamp(a.created_at);
        const bt = normalizeTimestamp(b.created_at);
        if (at !== bt) return bt - at;
        if (a.node !== b.node) return (a.node || '').localeCompare(b.node || '');
        return (a.route || '').localeCompare(b.route || '');
      }));
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

  const entryOptions = useMemo(() => {
    const set = new Set(rows.map((r) => r.node));
    return Array.from(set).sort((a, b) => (a || '').localeCompare(b || ''));
  }, [rows]);

  const exitOptions = useMemo(() => {
    const set = new Set(rows.map((r) => r.exit));
    return Array.from(set).sort((a, b) => (a || '').localeCompare(b || ''));
  }, [rows]);

  const filteredRows = useMemo(() => {
    const keyword = routeSearch.trim().toLowerCase();
    return rows.filter((r) => {
      if (keyword) {
        const name = `${r.route || ''} ${r.node || ''} ${r.exit || ''}`.toLowerCase();
        if (!name.includes(keyword)) return false;
      }
      if (filterEntry !== 'all' && r.node !== filterEntry) return false;
      if (filterExit !== 'all' && r.exit !== filterExit) return false;
      if (filterStatus !== 'all') {
        const online = onlineMap.get(r.node);
        if (filterStatus === 'online' && !online) return false;
        if (filterStatus === 'offline' && online) return false;
      }
      return true;
    });
  }, [rows, routeSearch, filterEntry, filterExit, filterStatus, onlineMap]);

  const resetFilters = () => {
    setRouteSearch('');
    setFilterEntry('all');
    setFilterExit('all');
    setFilterStatus('all');
  };

  const saveTemplate = () => {
    const values = routeForm.getFieldsValue();
    const path = Array.isArray(values.path) ? values.path : [];
    if (!path.length) {
      message.warning('请先配置路径');
      return;
    }
    const name = templateName.trim();
    if (!name) {
      message.warning('请输入模板名称');
      return;
    }
    const next = [...templates.filter((t) => t.name !== name), {
      name,
      path,
      return_path: Array.isArray(values.return_path) ? values.return_path : [],
      route_name: values.name || '',
      priority: values.priority || 1,
    }];
    setTemplates(next);
    localStorage.setItem('route_templates', JSON.stringify(next));
    message.success('模板已保存');
  };

  const applyTemplate = (name) => {
    const tpl = templates.find((t) => t.name === name);
    if (!tpl) return;
    routeForm.setFieldsValue({
      path: tpl.path || [],
      return_path: tpl.return_path || [],
      name: tpl.route_name || routeForm.getFieldValue('name'),
      priority: tpl.priority || routeForm.getFieldValue('priority'),
    });
  };

  const removeTemplate = (name) => {
    const next = templates.filter((t) => t.name !== name);
    setTemplates(next);
    localStorage.setItem('route_templates', JSON.stringify(next));
  };

  const diagLastKey = (routeKey) => `route_diag_last:${routeKey}`;
  const logLastKey = (routeKey) => `node_log_last:${routeKey}`;

  const fetchDiag = async (runId, cache = false) => {
    if (!runId) return;
    setDiagLoading(true);
    try {
      const [trace, logs] = await Promise.all([
        api('GET', `/api/route-diag?run_id=${encodeURIComponent(runId)}`),
        api('GET', `/api/diag?run_id=${encodeURIComponent(runId)}`),
      ]);
      if (!cache) {
        setDiagEvents(trace.events || []);
        setDiagReports(logs.reports || []);
        setDiagMissing(logs.missing || []);
      }
      try {
        localStorage.setItem(`route_diag_cache:${runId}`, JSON.stringify({
          events: trace.events || [],
          reports: logs.reports || [],
          missing: logs.missing || [],
          cached_at: Date.now(),
        }));
        if (diagRoute?.key) {
          localStorage.setItem(diagLastKey(diagRoute.key), JSON.stringify({
            run_id: runId,
            events: trace.events || [],
            reports: logs.reports || [],
            missing: logs.missing || [],
            cached_at: Date.now(),
          }));
        }
      } catch (_) {}
    } catch (e) {
      message.error(e.message);
    }
    setDiagLoading(false);
  };

  useEffect(() => {
    if (!diagOpen || !diagRunId) return;
    const t = setInterval(() => fetchDiag(diagRunId), 2000);
    return () => clearInterval(t);
  }, [diagOpen, diagRunId]);
  const fetchLogs = async (runId, cache = false) => {
    if (!runId) return;
    setLogLoading(true);
    try {
      const logs = await api('GET', `/api/diag?run_id=${encodeURIComponent(runId)}`);
      if (!cache) {
        setLogReports(logs.reports || []);
        setLogMissing(logs.missing || []);
      }
      try {
        localStorage.setItem(`node_log_cache:${runId}`, JSON.stringify({
          reports: logs.reports || [],
          missing: logs.missing || [],
          cached_at: Date.now(),
        }));
        if (logRoute?.key) {
          localStorage.setItem(logLastKey(logRoute.key), JSON.stringify({
            run_id: runId,
            reports: logs.reports || [],
            missing: logs.missing || [],
            cached_at: Date.now(),
          }));
        }
      } catch (_) {}
    } catch (e) {
      message.error(e.message);
    }
    setLogLoading(false);
  };

  const openDiagFromCache = (route) => {
    if (!route?.key) return;
    const cached = localStorage.getItem(diagLastKey(route.key));
    if (!cached) {
      message.info('暂无上次诊断结果');
      return;
    }
    try {
      const payload = JSON.parse(cached);
      setDiagRoute(route);
      setDiagRunId(payload.run_id || '');
      setDiagEvents(payload.events || []);
      setDiagReports(payload.reports || []);
      setDiagMissing(payload.missing || []);
      setDiagCachedAt(payload.cached_at || null);
      setDiagOpen(true);
    } catch (_) {
      message.error('读取上次诊断失败');
    }
  };

  const openLogFromCache = (route) => {
    if (!route?.key) return;
    const cached = localStorage.getItem(logLastKey(route.key));
    if (!cached) {
      message.info('暂无上次日志结果');
      return;
    }
    try {
      const payload = JSON.parse(cached);
      setLogRoute(route);
      setLogRunId(payload.run_id || '');
      setLogReports(payload.reports || []);
      setLogMissing(payload.missing || []);
      setLogCachedAt(payload.cached_at || null);
      setLogOpen(true);
    } catch (_) {
      message.error('读取上次日志失败');
    }
  };
  useEffect(() => {
    if (!logOpen || !logRunId) return;
    const t = setInterval(() => fetchLogs(logRunId), 2000);
    return () => clearInterval(t);
  }, [logOpen, logRunId]);
  const cols = [
    { title: '节点', dataIndex: 'node' },
    { title: '线路', dataIndex: 'route' },
    { title: '出口', dataIndex: 'exit' },
    { title: '优先级', dataIndex: 'priority' },
    { title: '路径', dataIndex: 'path', render: (p = []) => (p || []).map((x) => <Tag key={x}>{x}</Tag>) },
    {
      title: '回程信息',
      render: (_, r) => {
        const st = r.return_status;
        const modeTag = (r.return_path || []).length ? <Tag color="green">指定回程</Tag> : <Tag>自动回程</Tag>;
        let statusTag = <Tag>未上报</Tag>;
        if (st) {
          const detail = `pending=${st.pending || 0}, ready_total=${st.ready_total || 0}, fail_total=${st.fail_total || 0}${st.fail_reason ? `, reason=${st.fail_reason}` : ''}`;
          if (st.pending > 0) {
            statusTag = <Tooltip title={detail}><Tag color="gold">切换中</Tag></Tooltip>;
          } else if ((st.fail_at || 0) > (st.ready_at || 0)) {
            statusTag = <Tooltip title={detail}><Tag color="red">切换失败</Tag></Tooltip>;
          } else if (st.ready_total > 0) {
            statusTag = (
              <Tooltip title={detail}>
                {st.auto ? <Tag color="blue">已切换(自动)</Tag> : <Tag color="green">已切换(指定)</Tag>}
              </Tooltip>
            );
          } else {
            statusTag = <Tooltip title={detail}><Tag>未切换</Tag></Tooltip>;
          }
        }
        const ts = st
          ? (normalizeTimestamp(st.fail_at) || normalizeTimestamp(st.ready_at) || normalizeTimestamp(st.updated_at))
          : 0;
        const timeTag = ts
          ? <Tooltip title={new Date(ts).toLocaleString()}>{formatRelativeTime(ts)}</Tooltip>
          : '-';
        return (
          <div className="return-info-card">
            <div>{modeTag}</div>
            <div>{statusTag}</div>
            <div style={{ color: 'rgba(60, 60, 67, 0.68)', fontSize: 12 }}>{timeTag}</div>
          </div>
        );
      },
    },
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
    {
      title: '操作',
      render: (_, r) => (
        <Space>
          <Button
            size="small"
            disabled={!onlineMap.get(r.node)}
            onClick={async () => {
              const target = settings?.http_probe_url || 'https://www.google.com/generate_204';
              try {
                setDiagRoute(r);
                const res = await api('POST', '/api/route-diag/run', {
                  node: r.node,
                  route: r.route,
                  path: r.path || [],
                  return_path: r.return_path || [],
                  target,
                });
                setDiagRunId(res.run_id || '');
                setDiagEvents([]);
                setDiagReports([]);
                setDiagMissing(res.offline || []);
                setDiagCachedAt(null);
                setDiagOpen(true);
                const cacheKey = `route_diag_cache:${res.run_id}`;
                const cached = localStorage.getItem(cacheKey);
                if (cached) {
                  try {
                    const payload = JSON.parse(cached);
                    setDiagEvents(payload.events || []);
                    setDiagReports(payload.reports || []);
                    setDiagMissing(payload.missing || []);
                    setDiagCachedAt(payload.cached_at || null);
                  } catch (_) {}
                }
                setTimeout(() => fetchDiag(res.run_id), 800);
              } catch (e) {
                message.error(e.message);
              }
            }}
          >
            诊断
          </Button>
          <Button size="small" onClick={() => openDiagFromCache(r)}>上次诊断</Button>
          <Button
            size="small"
            disabled={!onlineMap.get(r.node)}
            onClick={async () => {
              try {
                const nodes = Array.from(new Set([...(r.path || []), ...(r.return_path || [])].filter(Boolean)));
                setLogRoute(r);
                const res = await api('POST', '/api/diag/run', {
                  nodes,
                  limit: 400,
                  contains: '',
                });
                setLogRunId(res.run_id || '');
                setLogReports([]);
                setLogMissing(res.offline || []);
                setLogCachedAt(null);
                setLogOpen(true);
                const cacheKey = `node_log_cache:${res.run_id}`;
                const cached = localStorage.getItem(cacheKey);
                if (cached) {
                  try {
                    const payload = JSON.parse(cached);
                    setLogReports(payload.reports || []);
                    setLogMissing(payload.missing || []);
                    setLogCachedAt(payload.cached_at || null);
                  } catch (_) {}
                }
                setTimeout(() => fetchLogs(res.run_id), 800);
              } catch (e) {
                message.error(e.message);
              }
            }}
          >
            节点日志
          </Button>
          <Button size="small" onClick={() => openLogFromCache(r)}>上次日志</Button>
        </Space>
      ),
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
  const addRoute = async () => {
    try {
      const v = await routeForm.validateFields();
      const path = (v.path || []).filter(Boolean);
      if (path.length < 2) {
        message.warning('路径至少包含入口和出口节点');
        return;
      }
      const entryName = path[0];
      const entry = allNodes.find((n) => n.name === entryName);
      if (!entry) {
        message.error('入口节点不存在');
        return;
      }
      const exit = path[path.length - 1];
      await api('POST', `/api/nodes/${entry.id}/routes`, {
        name: v.name,
        priority: v.priority,
        path,
        return_path: v.return_path || [],
        exit,
      });
      message.success(`线路已创建并分配到入口节点 ${entry.name}`);
      setRouteOpen(false);
      routeForm.resetFields();
      load();
    } catch (e) {
      message.error(e.message);
    }
  };
  return (
    <>
      <Card
        className="page-card"
        title="线路列表（含端到端延迟）"
        extra={
          <Space>
            <Button type="primary" onClick={() => setRouteOpen(true)}>新建线路</Button>
            <Button onClick={triggerAllTests}>测试全部</Button>
          </Space>
        }
      >
        <div className="route-filter-bar">
          <Space wrap>
            <Input
              placeholder="搜索线路/入口/出口"
              value={routeSearch}
              onChange={(e) => setRouteSearch(e.target.value)}
              allowClear
            />
            <Select
              value={filterEntry}
              onChange={setFilterEntry}
              options={[{ label: '全部入口', value: 'all' }, ...entryOptions.map((v) => ({ label: v, value: v }))]}
              style={{ minWidth: 140 }}
            />
            <Select
              value={filterExit}
              onChange={setFilterExit}
              options={[{ label: '全部出口', value: 'all' }, ...exitOptions.map((v) => ({ label: v, value: v }))]}
              style={{ minWidth: 140 }}
            />
            <Select
              value={filterStatus}
              onChange={setFilterStatus}
              options={[
                { label: '全部状态', value: 'all' },
                { label: '在线入口', value: 'online' },
                { label: '离线入口', value: 'offline' },
              ]}
              style={{ minWidth: 120 }}
            />
            <Button onClick={resetFilters}>清空筛选</Button>
          </Space>
        </div>
        <Table rowKey="key" dataSource={filteredRows} columns={cols} loading={loading} pagination={false} />
      </Card>
      <Modal open={routeOpen} onCancel={() => setRouteOpen(false)} onOk={addRoute} title="新建线路" width={620}>
        <Form layout="vertical" form={routeForm} initialValues={{ priority: 1 }}>
          <div className="route-template-bar">
            <Space wrap>
              <Select
                placeholder="选择模板"
                options={templates.map((t) => ({ label: t.name, value: t.name }))}
                onChange={applyTemplate}
                allowClear
                style={{ minWidth: 180 }}
              />
              <Input
                placeholder="模板名称"
                value={templateName}
                onChange={(e) => setTemplateName(e.target.value)}
                style={{ minWidth: 160 }}
              />
              <Button onClick={saveTemplate}>保存为模板</Button>
              {templates.length ? (
                <Select
                  placeholder="删除模板"
                  options={templates.map((t) => ({ label: t.name, value: t.name }))}
                  onChange={removeTemplate}
                  style={{ minWidth: 160 }}
                />
              ) : null}
            </Space>
          </div>
          <Form.Item name="name" label="线路名称" rules={[{ required: true }]}><Input placeholder="如: 成都->新加坡-1" /></Form.Item>
          <Form.Item name="priority" label="优先级" rules={[{ required: true }]}>
            <InputNumber min={1} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item label="路径节点顺序">
            <div className="path-action-bar">
              <PathActionBar form={routeForm} field="path" />
            </div>
            <Form.Item name="path" rules={[{ required: true, message: '请选择路径' }]} noStyle>
              <PathOrderEditor
                options={(allNodes || []).map((n) => ({
                  label: n.name,
                  value: n.name,
                  region: n.geo_region,
                  country: n.geo_country,
                }))}
                placeholder="从节点池拖拽到轨道形成路径"
                extra="首节点必须是入口，末节点为出口"
              />
            </Form.Item>
          </Form.Item>
          <Form.Item label="回程路径节点顺序 (可选)" tooltip="从出口回到入口的节点顺序，需以出口开头、入口结尾">
            <div className="path-action-bar">
              <PathActionBar form={routeForm} field="return_path" sourceField="path" />
            </div>
            <Form.Item name="return_path" noStyle>
              <PathOrderEditor
                options={(allNodes || []).map((n) => ({
                  label: n.name,
                  value: n.name,
                  region: n.geo_region,
                  country: n.geo_country,
                }))}
                placeholder="从节点池拖拽到轨道形成回程路径"
              />
            </Form.Item>
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        open={diagOpen}
        onCancel={() => setDiagOpen(false)}
        onOk={() => setDiagOpen(false)}
        width={900}
        okText="关闭"
        title={diagRoute ? `线路诊断：${diagRoute.node} / ${diagRoute.route}` : '线路诊断'}
      >
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <Space>
            <Button
              disabled={!diagRunId}
              onClick={async () => {
                try {
                  await api('POST', '/api/diag/refresh', {
                    run_id: diagRunId,
                    limit: 400,
                    contains: '',
                  });
                } catch (e) {
                  message.error(e.message);
                }
                fetchDiag(diagRunId);
              }}
            >
              刷新
            </Button>
            {diagCachedAt ? (
              <Text type="secondary">最近缓存：{new Date(diagCachedAt).toLocaleString()}</Text>
            ) : null}
            <Button
              disabled={!diagEvents.length}
              onClick={async () => {
                const text = [...diagEvents]
                  .sort((a, b) => (a.at || 0) - (b.at || 0))
                  .map((e) => `${new Date(e.at || 0).toLocaleTimeString()} [${e.node}] ${e.stage} ${e.detail || ''}`.trim())
                  .join('\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制诊断日志');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制步骤
            </Button>
            <Button
              disabled={!diagReports.length}
              onClick={async () => {
                const text = diagReports
                  .map((r) => `### ${r.node}\n${(r.lines || []).join('\n')}`)
                  .join('\n\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制节点日志');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制节点日志
            </Button>
          </Space>
          {diagMissing.length > 0 && (
            <Text type="secondary">未返回：{diagMissing.join(', ')}</Text>
          )}
          <div className="diag-report-list">
            {(() => {
              const groups = new Map();
              (diagEvents || []).forEach((e) => {
                if (!groups.has(e.node)) groups.set(e.node, []);
                groups.get(e.node).push(e);
              });
              const isReturnStage = (stage = '') => {
                const s = stage.toLowerCase();
                return s.includes('return') || s.includes('ack');
              };
              const isFailStage = (e) => /fail|error/i.test(e.stage || '') || /timeout/i.test(e.detail || '');
              return Array.from(groups.entries()).map(([node, items]) => {
                items.sort((a, b) => (a.at || 0) - (b.at || 0));
                const hasFail = items.some((e) => isFailStage(e));
                const forward = items.filter((e) => !isReturnStage(e.stage));
                const ret = items.filter((e) => isReturnStage(e.stage));
                const inbound = [...items].reverse().find((e) => e.stage === 'links_inbound');
                const outbound = [...items].reverse().find((e) => e.stage === 'links_outbound');
                const summaryStages = new Set([
                  'return_ready',
                  'return_fail',
                  'return_ack_sent',
                  'return_ack_relay',
                  'return_ack_recv',
                  'return_ack_rtt',
                ]);
                const summary = [...items]
                  .filter((e) => summaryStages.has(e.stage))
                  .sort((a, b) => (a.at || 0) - (b.at || 0));
                return (
                  <Card
                    key={node}
                    size="small"
                    className={`diag-report-card ${hasFail ? 'diag-node-fail' : ''}`}
                    title={<Space><Tag color={hasFail ? 'red' : 'blue'}>{node}</Tag></Space>}
                    extra={
                      <Button
                        size="small"
                        onClick={async () => {
                          const text = `### ${node}\n${items
                            .map((e) => `${new Date(e.at || 0).toLocaleTimeString()} ${e.stage} ${e.detail || ''}`.trim())
                            .join('\n')}`;
                          try {
                            await navigator.clipboard.writeText(text);
                            message.success(`已复制 ${node}`);
                          } catch (e) {
                            message.error('复制失败，请手动选择文本');
                          }
                        }}
                    >
                      复制
                    </Button>
                  }
                >
                  <Space direction="vertical" size={8} style={{ width: '100%' }}>
                    {summary.length > 0 && (
                      <div className="diag-summary">
                        <Text type="secondary">诊断结论</Text>
                        <div className="diag-event-list">
                          {summary.map((e, idx) => (
                            <Text key={`${node}-s-${e.at}-${idx}`} className={isFailStage(e) ? 'diag-event-fail' : ''}>
                              {e.at ? new Date(e.at).toLocaleTimeString() : '--'} {e.stage}
                              {e.detail ? ` - ${e.detail}` : ''}
                            </Text>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="diag-link-summary">
                      <Text type="secondary">入站：{inbound?.detail || '-'}</Text>
                      <Text type="secondary">出站：{outbound?.detail || '-'}</Text>
                    </div>
                    <Text type="secondary">去程</Text>
                      <div className="diag-event-list">
                        {(forward.length ? forward : items).map((e, idx) => (
                          <Text key={`${node}-f-${e.at}-${idx}`} className={isFailStage(e) ? 'diag-event-fail' : ''}>
                            {e.at ? new Date(e.at).toLocaleTimeString() : '--'} {e.stage}
                            {e.detail ? ` - ${e.detail}` : ''}
                          </Text>
                        ))}
                      </div>
                      <Text type="secondary">回程</Text>
                      <div className="diag-event-list">
                        {(ret.length ? ret : []).map((e, idx) => (
                          <Text key={`${node}-r-${e.at}-${idx}`} className={isFailStage(e) ? 'diag-event-fail' : ''}>
                            {e.at ? new Date(e.at).toLocaleTimeString() : '--'} {e.stage}
                            {e.detail ? ` - ${e.detail}` : ''}
                          </Text>
                        ))}
                        {!ret.length && <Text type="secondary">无回程事件</Text>}
                      </div>
                    </Space>
                  </Card>
                );
              });
            })()}
          </div>
          <Divider>节点日志</Divider>
          <div className="diag-report-list">
            {(diagReports || []).map((r) => (
              <Card
                key={r.node}
                size="small"
                className="diag-report-card"
                title={<Space><Tag color="blue">{r.node}</Tag></Space>}
              >
                <Input.TextArea
                  value={(r.lines || []).join('\n')}
                  rows={8}
                  readOnly
                />
              </Card>
            ))}
          </div>
        </Space>
      </Modal>
      <Modal
        open={logOpen}
        onCancel={() => setLogOpen(false)}
        onOk={() => setLogOpen(false)}
        width={900}
        okText="关闭"
        title={logRoute ? `线路节点日志：${logRoute.node} / ${logRoute.route}` : '线路节点日志'}
      >
        <Space direction="vertical" size={10} style={{ width: '100%' }}>
          <Space>
            <Button
              disabled={!logRunId}
              onClick={async () => {
                try {
                  await api('POST', '/api/diag/refresh', {
                    run_id: logRunId,
                    limit: 400,
                    contains: '',
                  });
                } catch (e) {
                  message.error(e.message);
                }
                fetchLogs(logRunId);
              }}
            >
              刷新
            </Button>
            {logCachedAt ? (
              <Text type="secondary">最近缓存：{new Date(logCachedAt).toLocaleString()}</Text>
            ) : null}
            <Button
              disabled={!logReports.length}
              onClick={async () => {
                const text = logReports
                  .map((r) => `### ${r.node}\n${(r.lines || []).join('\n')}`)
                  .join('\n\n');
                try {
                  await navigator.clipboard.writeText(text);
                  message.success('已复制节点日志');
                } catch (e) {
                  message.error('复制失败，请手动选择文本');
                }
              }}
            >
              复制节点日志
            </Button>
          </Space>
          {logMissing.length > 0 && (
            <Text type="secondary">未返回：{logMissing.join(', ')}</Text>
          )}
          <div className="diag-report-list">
            {(logReports || []).map((r) => (
              <Card
                key={r.node}
                size="small"
                className="diag-report-card"
                title={<Space><Tag color="blue">{r.node}</Tag></Space>}
              >
                <Input.TextArea value={(r.lines || []).join('\n')} rows={8} readOnly />
              </Card>
            ))}
          </div>
        </Space>
      </Modal>
    </>
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
  const [apiBase, setApiBaseState] = useState(getApiBase());
  const [userList, setUserList] = useState([]);
  const [userModal, setUserModal] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [view, setView] = useState('dashboard');
  const refreshList = () => setRefreshSignal((t) => t + 1);

  const applyApiBase = () => {
    const next = apiBase.trim();
    setApiBase(next);
    localStorage.removeItem('jwt');
    setToken('');
    message.success(next ? '已切换控制器地址' : '已恢复默认控制器地址');
  };

  const resetApiBase = () => {
    setApiBaseState('');
    setApiBase('');
    localStorage.removeItem('jwt');
    setToken('');
    message.success('已恢复默认控制器地址');
  };

  const showInstall = (node) => {
    if (!node) {
      message.info('请先选择一个节点');
      return;
    }
    const origin = getApiBase() || window.location.origin;
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

  const UserModal = () => {
    const [form] = Form.useForm();
    const [editUser, setEditUser] = useState(null);
    useEffect(() => {
      if (!userModal) return;
      if (editUser) {
        form.setFieldsValue({ username: editUser.username, is_admin: editUser.is_admin, password: '' });
      } else {
        form.resetFields();
      }
    }, [editUser, userModal]);
    return (
      <Modal
        open={userModal}
        onCancel={() => { setUserModal(false); setEditUser(null); form.resetFields(); }}
        onOk={async () => {
          try {
            const v = await form.validateFields();
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
            form.resetFields();
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
                  <Button size="small" onClick={() => { setEditUser(r); setUserModal(true); }}>修改</Button>
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
        <Form layout="vertical" form={form}>
          <Form.Item name="username" label="用户名" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: !editUser }]}><Input.Password /></Form.Item>
          <Form.Item name="is_admin" label="管理员" initialValue={false}>
            <Select options={[{ value: true, label: '是' }, { value: false, label: '否' }]} />
          </Form.Item>
        </Form>
      </Modal>
    );
  };

  const SettingsModal = () => {
    const [form] = Form.useForm();
    const [saving, setSaving] = useState(false);
    useEffect(() => {
      if (settings) {
        form.setFieldsValue({
          transport: settings.transport || 'quic',
          compression: settings.compression || 'none',
          compression_min_bytes: settings.compression_min_bytes || 0,
          max_mux_streams: settings.max_mux_streams || 4,
          http_probe_url: settings.http_probe_url || 'https://www.google.com/generate_204',
          return_ack_timeout: settings.return_ack_timeout || '10s',
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
              <Form.Item name="max_mux_streams" label="最大Mux并发" tooltip="控制单连接复用的并发流数量，建议 4-8">
                <Input type="number" min={1} />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="http_probe_url" label="HTTP探测URL">
                <Input placeholder="https://www.google.com/generate_204" />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12} lg={12}>
              <Form.Item name="return_ack_timeout" label="回程ACK超时" tooltip="建议 10s-20s，支持 Go duration 格式，如 10s">
                <Input placeholder="10s" />
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
            <Space direction="vertical" size={8} style={{ width: '100%', marginBottom: 16 }}>
              <div style={{ fontSize: 13, color: '#64748b' }}>控制器地址</div>
              <Space.Compact style={{ width: '100%' }}>
                <Input
                  value={apiBase}
                  onChange={(e) => setApiBaseState(e.target.value)}
                  placeholder={`默认：${DEFAULT_API_BASE}`}
                />
                <Button type="primary" onClick={applyApiBase}>应用</Button>
              </Space.Compact>
              <Button size="small" type="link" onClick={resetApiBase}>恢复默认</Button>
            </Space>
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
    { key: 'map', label: '节点地图' },
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
              onClick={() => { setUserModal(true); }}
              aria-label="用户管理"
            />
            <Button size="small" type="text" icon={<GearIcon />} onClick={() => setSettingsOpen(true)} aria-label="全局设置" />
          </Space>
        </Header>
        <Content className="app-content">
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Card className="page-card" styles={{ body: { padding: 16 } }}>
              <Space wrap>
                <Button type="primary" onClick={() => refreshList()}>刷新</Button>
                <Button onClick={() => { setSelected(null); setView('dashboard'); }}>节点概览</Button>
                <Button onClick={() => { setSelected(null); setView('map'); }}>节点地图</Button>
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
                : view === 'map'
                  ? <NodeMap refreshSignal={refreshSignal} onSelect={setSelected} onOpenNode={() => setView('dashboard')} />
                  : (selected
                    ? <NodeDetail key={selected.id} node={selected} onBack={() => setSelected(null)} refreshList={refreshList} onShowInstall={showInstall} />
                    : <NodeList onSelect={setSelected} onShowInstall={showInstall} refreshSignal={refreshSignal} />
                  )
            }
            <Modal open={installOpen} onCancel={() => setInstallOpen(false)} onOk={copyCmd} okText="复制命令">
              <p>在目标节点执行以下命令以安装并自启动：</p>
              <Input.TextArea value={installCmd} rows={3} readOnly />
            </Modal>
            <UserModal />
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
