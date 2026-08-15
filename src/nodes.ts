export type NodeStack = 'dual' | 'v4' | 'v6'

export interface SourceNode {
  id: string
  label: string
  url: string
  stack: NodeStack
}

const jiangsu: SourceNode = {
  id: 'cn-jiangsu-mobile',
  label: '中国 江苏 移动',
  url: '/jiangsu-node/',
  stack: 'dual',
}

const shenzhen: SourceNode = {
  id: 'cn-shenzhen-mobile',
  label: '中国 广东 深圳 龙岗 坪地街道 中国移动',
  url: '/shenzhen-node/',
  stack: 'dual',
}

const guangzhou: SourceNode = {
  id: 'cn-guangzhou-tencent',
  label: '中国 广东 广州 腾讯云',
  url: '/guangzhou-node/',
  stack: 'v4',
}

const singapore: SourceNode = {
  id: 'sg-tencent',
  label: '新加坡 腾讯云',
  url: '/singapore-node/',
  stack: 'v4',
}

const xian: SourceNode = {
  id: 'cn-xian-telecom',
  label: '中国 陕西 西安 北经济技术开发区 未央区凤城 中国电信[ZFC]',
  url: '/xian-node/',
  stack: 'v4',
}

const xian2: SourceNode = {
  id: 'cn-xian2-telecom',
  label: '中国 陕西 西安二 电信',
  url: '/xian2-node/',
  stack: 'v4',
}

const natSpeedNode: SourceNode = {
  id: 'cn-nat-minecraft',
  label: '中国 山东 枣庄 移动/电信双线',
  url: '/speed-node/',
  stack: 'v4',
}

const hongKongDedicatedNode: SourceNode = {
  id: 'hk-dedicated-cogent',
  label: '中国 香港 Cogent',
  url: '/manage-node/hongkong/',
  stack: 'v4',
}

const shiyan: SourceNode = {
  id: 'cn-hubei-shiyan-telecom',
  label: '中国 湖北 十堰 电信',
  url: '/shiyan-node/',
  stack: 'v4',
}

const hongKongVpsQuan: SourceNode = {
  id: 'hk-vpsquan',
  label: '中国 香港 VpsQuan',
  url: '/hongkong2-node/',
  stack: 'v4',
}

const jdCloudBGP: SourceNode = {
  id: 'cn-beijing-jdcloud-bgp',
  label: '中国 北京 京东云 三网BGP',
  url: '/jdcloud-node/',
  stack: 'v4',
}

const huawei: SourceNode = {
  id: 'cn-beijing-huawei-go',
  label: '中国 华为云 北京',
  url: '/huawei-node/',
  stack: 'v4',
}

// 腾讯云上海 BGP 是双栈（部署时实测 v4/v6 均出网），因此同时进
// dualStack 列表 —— v4/v6 测速、TCPing、DNS 页都能选到它。
const tencentSh: SourceNode = {
  id: 'cn-shanghai-tencent-bgp',
  label: '中国 上海 腾讯云 BGP',
  url: '/tencent-sh-node/',
  stack: 'dual',
}

const sichuan: SourceNode = {
  id: 'cn-sichuan-telecom',
  label: '中国 四川 沙渠 电信[ZFC]',
  url: '/sichuan-node/',
  stack: 'v6',
}

const hongKong: SourceNode = {
  id: 'cn-hong-kong-cloudie',
  label: '中国 香港 九龙城区 旺角东 Cloudie[ZFC]',
  url: '/hkcloudie-node/',
  stack: 'v6',
}

const dualStackNodes = [jiangsu, shenzhen, tencentSh] as const
const ipv4Nodes = [guangzhou, singapore, xian] as const
const ipv6Nodes = [sichuan, hongKong] as const
const extraIpv4Nodes = [natSpeedNode, hongKongDedicatedNode, xian2, shiyan, hongKongVpsQuan, jdCloudBGP, huawei] as const

export const sourceNodes = {
  core: [...dualStackNodes],
  location: [sichuan, xian2],
  tcping: {
    v4: [...dualStackNodes, ...ipv4Nodes, ...extraIpv4Nodes],
    v6: [...dualStackNodes, ...ipv6Nodes],
  },
  speed: {
    v4: [...dualStackNodes, ...ipv4Nodes, ...extraIpv4Nodes],
    v6: [...dualStackNodes, ...ipv6Nodes],
  },
  dns: [jiangsu, guangzhou, singapore, sichuan, xian, hongKong, shenzhen, ...extraIpv4Nodes],
}

export function nodeStackLabel(stack: NodeStack) {
  if (stack === 'dual') return '双栈节点'
  return stack === 'v4' ? 'IPv4 节点' : 'IPv6 节点'
}
