- 目标程序FortiClient基于ElectronFramework构建，动态加载的库*guimessenger_jyp.node*，使用了nodejs的C++扩展标准node-gyp进行构建，用于调用C++实现的基础功能，比如*ConnectTunnel*

库的位置
```
/Applications/FortiClient.app/Contents/Resources/app.asar.unpacked/assets/js/guimessenger_jyp.node
```

- 基于*napi.h*和*napi-inl.h*中关于Napi::CallbackInfo的定义(node-addon-api-7.1.0)

```
class CallbackInfo {
 public:
  CallbackInfo(napi_env env, napi_callback_info info);
  ~CallbackInfo();

  // Disallow copying to prevent multiple free of _dynamicArgs
  NAPI_DISALLOW_ASSIGN_COPY(CallbackInfo)

  Napi::Env Env() const;
  Value NewTarget() const;
  bool IsConstructCall() const;
  size_t Length() const;
  const Value operator[](size_t index) const;
  Value This() const;
  void* Data() const;
  void SetData(void* data);
  explicit operator napi_callback_info() const;

 private:
  const size_t _staticArgCount = 6;
  napi_env _env;
  napi_callback_info _info;
  napi_value _this;
  size_t _argc;
  napi_value* _argv;
  napi_value _staticArgs[6];
  napi_value* _dynamicArgs;
  void* _data;
};

inline CallbackInfo::CallbackInfo(napi_env env, napi_callback_info info)
    : _env(env),
      _info(info),
      _this(nullptr),
      _dynamicArgs(nullptr),
      _data(nullptr) {
  _argc = _staticArgCount;
  _argv = _staticArgs;
  napi_status status =
      napi_get_cb_info(env, info, &_argc, _argv, &_this, &_data);
  NAPI_THROW_IF_FAILED_VOID(_env, status);

  if (_argc > _staticArgCount) {
    // Use either a fixed-size array (on the stack) or a dynamically-allocated
    // array (on the heap) depending on the number of args.
    _dynamicArgs = new napi_value[_argc];
    _argv = _dynamicArgs;

    status = napi_get_cb_info(env, info, &_argc, _argv, nullptr, nullptr);
    NAPI_THROW_IF_FAILED_VOID(_env, status);
  }
}

```

- CallbackInfo的字段内存布局

```
0x00    _staticArgCount     常量 6
0x08    _env                napi_env
0x10    _info               napi_callback_info
0x18    _this               napi_value this 值
0x20    _argc               参数个数
0x28    _argv               指向实际参数数组（napi_value*）
```

- 在lldb attach目标程序FortiClient缺少符号表和源代码支持的情况下，解析如下汇编代码中，函数MessageSender::ConnectTunnel(Napi::CallbackInfo const&)的参数内容。
```
guimessenger_jyp.node`MessageSender::ConnectTunnel:
->  0x105d09014 <+0>:   sub    sp, sp, #0x60
    0x105d09018 <+4>:   stp    x20, x19, [sp, #0x40]
    0x105d0901c <+8>:   stp    x29, x30, [sp, #0x50]
    0x105d09020 <+12>:  add    x29, sp, #0x50
    0x105d09024 <+16>:  mov    x19, x1
    0x105d09028 <+20>:  ldr    x8, [x1, #0x20]
    0x105d0902c <+24>:  cmp    x8, #0x1
    0x105d09030 <+28>:  b.ne   0x105d09090    ; <+124>
    0x105d09034 <+32>:  mov    x0, x19
    0x105d09038 <+36>:  mov    x1, #0x0 ; =0
    0x105d0903c <+40>:  bl     0x105d152ac    ; Napi::CallbackInfo::operator[](unsigned long) const
    0x105d09040 <+44>:  stp    x0, x1, [x29, #-0x20]
    0x105d09044 <+48>:  add    x8, sp, #0x18
    0x105d09048 <+52>:  sub    x0, x29, #0x20
    0x105d0904c <+56>:  bl     0x105d1536c    ; Napi::String::Utf8Value() const
    0x105d09050 <+60>:  mov    x0, sp
    0x105d09054 <+64>:  add    x1, sp, #0x18
    0x105d09058 <+68>:  bl     0x105dea4e8    ; symbol stub for: std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>>::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char>> const&)
    0x105d0905c <+72>:  mov    x0, sp
    0x105d09060 <+76>:  bl     0x105d31904    ; connectTunnel
    0x105d09064 <+80>:  mov    x20, x0
    0x105d09068 <+84>:  ldrsb  w8, [sp, #0x17]
    0x105d0906c <+88>:  tbz    w8, #0x1f, 0x105d09078 ; <+100>
    0x105d09070 <+92>:  ldr    x0, [sp]
    0x105d09074 <+96>:  bl     0x105dea7c4    ; symbol stub for: operator delete(void*)
    0x105d09078 <+100>: ldr    x0, [x19, #0x8]
    0x105d0907c <+104>: cbz    w20, 0x105d090ac ; <+152>
    0x105d09080 <+108>: adrp   x1, 232
    0x105d09084 <+112>: add    x1, x1, #0xb80 ; "["0"]"
    0x105d09088 <+116>: bl     0x105d15200    ; Napi::String::New(napi_env__*, char const*)
    0x105d0908c <+120>: b      0x105d090b8    ; <+164>
    0x105d09090 <+124>: ldr    x0, [x19, #0x8]
    0x105d09094 <+128>: adrp   x1, 236
    0x105d09098 <+132>: add    x1, x1, #0xb28 ; ""
    0x105d0909c <+136>: ldp    x29, x30, [sp, #0x50]
    0x105d090a0 <+140>: ldp    x20, x19, [sp, #0x40]
    0x105d090a4 <+144>: add    sp, sp, #0x60
    0x105d090a8 <+148>: b      0x105d15200    ; Napi::String::New(napi_env__*, char const*)
    0x105d090ac <+152>: adrp   x1, 232
    0x105d090b0 <+156>: add    x1, x1, #0x90f ; "["1"]"
    0x105d090b4 <+160>: bl     0x105d15200    ; Napi::String::New(napi_env__*, char const*)
    0x105d090b8 <+164>: mov    x19, x0
    0x105d090bc <+168>: mov    x20, x1
    0x105d090c0 <+172>: ldrsb  w8, [sp, #0x2f]
    0x105d090c4 <+176>: tbz    w8, #0x1f, 0x105d090d0 ; <+188>
    0x105d090c8 <+180>: ldr    x0, [sp, #0x18]
    0x105d090cc <+184>: bl     0x105dea7c4    ; symbol stub for: operator delete(void*)
    0x105d090d0 <+188>: mov    x0, x19
    0x105d090d4 <+192>: mov    x1, x20
    0x105d090d8 <+196>: ldp    x29, x30, [sp, #0x50]
    0x105d090dc <+200>: ldp    x20, x19, [sp, #0x40]
    0x105d090e0 <+204>: add    sp, sp, #0x60
    0x105d090e4 <+208>: ret
    0x105d090e8 <+212>: b      0x105d09108    ; <+244>
    0x105d090ec <+216>: b      0x105d09108    ; <+244>
    0x105d090f0 <+220>: mov    x19, x0
    0x105d090f4 <+224>: ldrsb  w8, [sp, #0x17]
    0x105d090f8 <+228>: tbz    w8, #0x1f, 0x105d0910c ; <+248>
    0x105d090fc <+232>: ldr    x0, [sp]
    0x105d09100 <+236>: bl     0x105dea7c4    ; symbol stub for: operator delete(void*)
    0x105d09104 <+240>: b      0x105d0910c    ; <+248>
    0x105d09108 <+244>: mov    x19, x0
    0x105d0910c <+248>: ldrsb  w8, [sp, #0x2f]
    0x105d09110 <+252>: tbz    w8, #0x1f, 0x105d0911c ; <+264>
    0x105d09114 <+256>: ldr    x0, [sp, #0x18]
    0x105d09118 <+260>: bl     0x105dea7c4    ; symbol stub for: operator delete(void*)
    0x105d0911c <+264>: mov    x0, x19
    0x105d09120 <+268>: bl     0x105dea3a4    ; symbol stub for: _Unwind_Resume
```

*+16*处，**x1**存放Callbackinfo的地址，比如**0x000000016f327e40**

读取*size_t _staticArgCount*的结果
```
x/1g 0x000000016f327e40

0x16f327e40: \x06\0\0\0\0\0\0\
```

读取*size_t _argc*的结果
```
x/1g 0x000000016f327e40+0x20
0x16f327e60: \x01\0\0\0\0\0\0\0
```

*+24*处，确认CallbackInfo携带的参数个数为1，开始处理其携带的参数内容，*+36*处，基于operator的索引（第一个参数的索引是0）

参数的处理来到*+60*处，是C++的*(const basic_string&)*的构造，观察下*sp+0x18*作为源字符串地址（引用），可能的布局

```
memory read -b $sp+0x18
0x16f327e18: 80 e0 ae 00 00 60 00 00 c7 00 00 00 00 00 00 00  .....`..........
0x16f327e28: d0 00 00 00 00 00 00 80 a0 0e af 00 00 60 00 00  .............`.
```
字符串的data_ptr地址可能是首8个字节，为**0x600000aee080**，长度是下8个字节，为**0xc7**
```
memory read --format Y --count 0xc7 0x600000aee080
0x600000aee080: 7b 22 63 6f 6e 6e 65 63 74 69 6f 6e 5f 6e 61 6d  {"connection_nam
0x600000aee090: 65 22 3a 22 77 65 62 75 6c 6c 22 2c 22 63 6f 6e  e":"webull","con
0x600000aee0a0: 6e 65 63 74 69 6f 6e 5f 74 79 70 65 22 3a 22 73  nection_type":"s
0x600000aee0b0: 73 6c 22 2c 22 70 61 73 73 77 6f 72 64 22 3a 22  sl","password":"
0x600000aee0c0: 22 2c 22 75 73 65 72 6e 61 6d 65 22 3a 22 7a 77  ","username":"zw
0x600000aee0d0: 40 77 65 62 75 6c 6c 2e 63 6f 6d 22 2c 22 73 61  @webull.com","sa
0x600000aee0e0: 76 65 5f 75 73 65 72 6e 61 6d 65 22 3a 66 61 6c  ve_username":fal
0x600000aee0f0: 73 65 2c 22 73 61 76 65 5f 70 61 73 73 77 6f 72  se,"save_passwor
0x600000aee100: 64 22 3a 22 30 22 2c 22 61 6c 77 61 79 73 5f 75  d":"0","always_u
0x600000aee110: 70 22 3a 22 30 22 2c 22 61 75 74 6f 5f 63 6f 6e  p":"0","auto_con
0x600000aee120: 6e 65 63 74 22 3a 22 30 22 2c 22 73 61 6d 6c 5f  nect":"0","saml_
0x600000aee130: 65 72 72 6f 72 22 3a 31 2c 22 73 61 6d 6c 5f 74  error":1,"saml_t
0x600000aee140: 79 70 65 22 3a 31 7d                             ype":1}
```

在*+72*处，调用*connectTunnel*之前，复制后的字符串引用是这个方法唯一的参数，打印看下参数
```
(lldb) memory read $x0
0x16f327e00: 00 e7 ae 00 00 60 00 00 c7 00 00 00 00 00 00 00  .....`..........
0x16f327e10: c8 00 00 00 00 00 00 80 80 e0 ae 00 00 60 00 00  .............`..
(lldb) memory read --format Y --count 0xc7 0x600000aee700
0x600000aee700: 7b 22 63 6f 6e 6e 65 63 74 69 6f 6e 5f 6e 61 6d  {"connection_nam
0x600000aee710: 65 22 3a 22 77 65 62 75 6c 6c 22 2c 22 63 6f 6e  e":"webull","con
0x600000aee720: 6e 65 63 74 69 6f 6e 5f 74 79 70 65 22 3a 22 73  nection_type":"s
0x600000aee730: 73 6c 22 2c 22 70 61 73 73 77 6f 72 64 22 3a 22  sl","password":"
0x600000aee740: 22 2c 22 75 73 65 72 6e 61 6d 65 22 3a 22 7a 77  ","username":"zw
0x600000aee750: 40 77 65 62 75 6c 6c 2e 63 6f 6d 22 2c 22 73 61  @webull.com","sa
0x600000aee760: 76 65 5f 75 73 65 72 6e 61 6d 65 22 3a 66 61 6c  ve_username":fal
0x600000aee770: 73 65 2c 22 73 61 76 65 5f 70 61 73 73 77 6f 72  se,"save_passwor
0x600000aee780: 64 22 3a 22 30 22 2c 22 61 6c 77 61 79 73 5f 75  d":"0","always_u
0x600000aee790: 70 22 3a 22 30 22 2c 22 61 75 74 6f 5f 63 6f 6e  p":"0","auto_con
0x600000aee7a0: 6e 65 63 74 22 3a 22 30 22 2c 22 73 61 6d 6c 5f  nect":"0","saml_
0x600000aee7b0: 65 72 72 6f 72 22 3a 31 2c 22 73 61 6d 6c 5f 74  error":1,"saml_t
0x600000aee7c0: 79 70 65 22 3a 31 7d                             ype":1}
```

有个猜测，把这个json字符串修改下，auto_connect设置为"1"？比如
```
memory write --format byte 0x600000aee7a7 0x31
```
设置后，断开Wifi，没有观察到VPN自动重连。



- 主要用于观察的断点

```
Current breakpoints:
1: address = guimessenger_jyp.node[0x0000000000011034], locations = 1 Options: disabled
  1.1: where = guimessenger_jyp.node`MessageSender::ConnectTunnel(Napi::CallbackInfo const&) + 32, address = 0x0000000105d09034, unresolved, hit count = 1

2: address = guimessenger_jyp.node[0x000000000001105c], locations = 1, resolved = 1, hit count = 4
  2.1: where = guimessenger_jyp.node`MessageSender::ConnectTunnel(Napi::CallbackInfo const&) + 72, address = 0x0000000105d0905c, resolved, hit count = 4
```
