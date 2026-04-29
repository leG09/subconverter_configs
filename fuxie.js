const prependRule = [
  "DOMAIN-SUFFIX,1234567.com.cn,🏢 公司节点",
  "DOMAIN-SUFFIX,eastmoney.com,🏢 公司节点",
  "PROCESS-NAME,Fishing Funds Helper,🏢 公司节点",
  "PROCESS-NAME,MuMuEmulator,REJECT",
  "PROCESS-NAME,MuMuPlayer,REJECT",
  "PROCESS-NAME,Raycast,REJECT",
  "DOMAIN,mumu.nie.netease.com,REJECT"

];

function main(config) {
  config.rules = [...prependRule, ...(config.rules || [])];
  return config;
}
