function debugAndCallConnectVpn() {
    console.log("=== 开始调试 FortiTray.AppDelegate.connectVpn ===");
    
    // 1. 查找所有相关类
    console.log("\n1. 查找相关类:");
    var allClasses = Object.keys(ObjC.classes);
    var relevantClasses = allClasses.filter(function(name) {
        return name.toLowerCase().indexOf("fortitray") !== -1 || 
               name.toLowerCase().indexOf("appdelegate") !== -1;
    });
    
    relevantClasses.forEach(function(className) {
        console.log("  " + className);
    });
    
    // 2. 获取 AppDelegate 实例
    console.log("\n2. 获取 AppDelegate 实例:");
    var app = ObjC.classes.NSApplication.sharedApplication();
    var delegate = app.delegate();
    
    if (delegate) {
        console.log("  成功获取 delegate");
        console.log("  类名: " + delegate.$className);
        
        // 3. 检查方法
        console.log("\n3. 检查 connectVpn 相关方法:");
        var methods = delegate.$ownMethods;
        var connectMethods = methods.filter(function(method) {
            return method.toLowerCase().indexOf("connect") !== -1;
        });
        
        connectMethods.forEach(function(method) {
            console.log("  " + method);
        });
        
        // 4. 尝试调用
        console.log("\n4. 尝试 NativeFunction 精确调用:");
        try {
            // 根据方法签名创建函数
            var disConnectVpnFunc = new NativeFunction(
                ptr("0x1000ab858"), 
                'void',           // 返回类型
                ['pointer', 'pointer', 'pointer']  // self, selector, parameter
            );
            
            var selector = ObjC.selector("disconnectVpn:");
            var nsNull = ObjC.classes.NSNull.null();
            
            disConnectVpnFunc(delegate.handle, selector, nsNull.handle);
            console.log("✅ NativeFunction disconnectVpn 调用成功");
            return;
        } catch (e) {
            console.log("❌ NativeFunction 调用失败: " + e.message);
        }
                
    } else {
        console.log("  ✗ 无法获取 delegate");
    }
}

// 执行调试
debugAndCallConnectVpn();
