// lookup the connectTunnel func address, for example: 0x107b91904
const moduleName = 'guimessenger_jyp.node';
const connectTunnelFunctionName = 'connectTunnel';
const funcAddress = Module.findExportByName(moduleName, connectTunnelFunctionName);
if (funcAddress) {
  console.log(`Address of ${connectTunnelFunctionName} in ${moduleName}: ${funcAddress}`);

  const addrConnectTunnel = ptr(funcAddress); 

  const fnConnectTunnel = new NativeFunction(addrConnectTunnel, 'pointer', ['pointer']);

  // 通过之前的探测和调试，获取到connectTunnel的入参形式，是一个json字符串，作为string的引用
  const connJSONStrTpl = '{"connection_name":"xxx","connection_type":"ssl","password":"","username":"xxx","save_username":false,"save_password":"0","always_up":"0","auto_connect":"0","saml_error":1,"saml_type":1}';
  const connObject = JSON.parse(connJSONStrTpl);

  const userName = "zw@webull.com"; 
  const connName = "webull";
  connObject.connection_name = connName;
  connObject.username = userName;

  const connJSONStr = JSON.stringify(connObject);
  console.log(`conn string: ${connJSONStr}`);

  // Memory.allocUtf8String 自动在尾部加 '\0'
  const utf8buf = Memory.allocUtf8String(connJSONStr);
  const strLen = connJSONStr.length;
  console.log(`conn string length (NUL excluded): 0x${strLen.toString(16)}`);

  // 关键的适配std::string layout的计算（本地arm64上验证通过）
  const strControlBase = 0x8000000000000000n;
  const full64StrControl = strControlBase + (BigInt(strLen) + 1n);
  const uint64StrControl = uint64(full64StrControl.toString());
  console.log(`conn string control: 0x${uint64StrControl.toString(16)}`);

  // 分配内存给 std::string 对象本身
  const strSize = 32;  // libc++ 下 sizeof(std::string) 通常是 24，但向上取整 32
  const strMem  = Memory.alloc(strSize);

  // 在 strMem 上写入3个字节（自行构造）
  Memory.writePointer(strMem,          utf8buf);     // _M_ptr
  Memory.writeU64   (strMem.add(8),    strLen);         // _M_size
  Memory.writeU64   (strMem.add(16),   uint64StrControl); //_M_capacity, sso flag?

  // 调用 connectTunnel
  const ret = fnConnectTunnel(strMem);

  // TODO: 析构 string，free(utf8buf)
  //fnDtor(strMem);
  //Memory.free(utf8buf);

  console.log(`connectTunnel return: ${ret.toInt32() == 0 ? "OK" : "Failed"}`);


} else {
  console.log(`${connectTunnelFunctionName} not found in ${moduleName}.`);
}

