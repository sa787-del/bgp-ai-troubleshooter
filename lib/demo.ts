export const sampleTime = '2026-10-10 10:42:18 UTC';
export const devices = [
  {name:'core-rtr-01',ip:'10.0.0.1',as:'65001',site:'DC East',reachable:true},
  {name:'core-rtr-02',ip:'10.0.0.2',as:'65001',site:'DC East',reachable:true},
  {name:'edge-rtr-01',ip:'10.0.1.1',as:'65002',site:'DC East',reachable:true},
  {name:'edge-rtr-02',ip:'10.0.1.2',as:'65002',site:'DC West',reachable:true},
  {name:'dist-rtr-01',ip:'10.0.2.1',as:'65003',site:'DC West',reachable:true},
  {name:'dist-rtr-02',ip:'10.0.2.2',as:'65003',site:'DC West',reachable:true},
  {name:'branch-rtr-01',ip:'10.0.3.1',as:'65004',site:'Branch',reachable:true},
  {name:'branch-rtr-02',ip:'10.0.3.2',as:'65004',site:'Branch',reachable:false},
];
export const peers = devices.flatMap((d,i)=>[0,1].map(n=>({id:`${i}-${n}`,device:d.name,ip:d.ip,localAS:d.as,peer:`172.16.${i}.${n+1}`,remoteAS:String(65100+i),state:i===7?'Unknown':i===2&&n===1?'Idle':i===3&&n===1?'Active':'Established',prefixes:i===7||((i===2||i===3)&&n===1)?null:[128,64,256,96,48,32][(i+n)%6],time:'10:42:18',site:d.site})));
export type Peer = typeof peers[number];
export const interfaces = devices.filter(d=>d.reachable).flatMap((d,i)=>[0,1].map(n=>({device:d.name,name:`eth${n}`,state:i===2&&n===1?'Down':'Up',admin:'Up',ip:`172.16.${i}.${n+1}/30`})));
export const tools = [
 {id:'bgp',name:'BGP State',command:'show bgp summary',endpoint:'/tools/bgp/state',available:true},
 {id:'neighbor',name:'BGP Neighbor Details',command:'show bgp neighbors <peer>',endpoint:'/tools/bgp/neighbor',available:false},
 {id:'interface',name:'Interface Details',command:'show interface detail',endpoint:'/tools/interface/detail',available:true},
 {id:'tcp',name:'TCP Connectivity',command:'TCP connection to peer:179',endpoint:'/tools/tcp/check',available:true},
 {id:'config',name:'Configuration',command:'show running-config',endpoint:'/tools/config/diff',available:true},
 {id:'route',name:'Routing Table',command:'show ip bgp',endpoint:'/tools/route/table',available:false},
 {id:'map',name:'Route Maps',command:'show route-map',endpoint:'/tools/route/map',available:false},
];
export const rawSummary = 'BGP router identifier 10.0.0.1, local AS number 65001\nBGP table version is 132, main routing table version 132\n\nNeighbor        V    AS MsgRcvd MsgSent  TblVer InQ OutQ Up/Down  State/PfxRcd\n172.16.0.1      4 65100    1042    1046     132   0    0 00:42:16          128\n172.16.0.2      4 65100    1038    1041     132   0    0 00:42:12           64\n\nTotal number of neighbors 2';
