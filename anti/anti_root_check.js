// 2021-03-01 add Android AntiDebug

// Android 反调试检测绕过脚本

// java 
function testSucheck() {
    // 常规的su 和root命令的检测
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload("java.lang.String").implementation = function (command) {

        if (command.endsWith("su")) {
            // 检测到su命令简直，这里直接绕过，设置为空
            command = "";
            console.log("Detect su commands  exec ,hacked  ,commands " + String(command));
        }
        console.log("Runtime.exec detected commands \"" + String(command) + "\".");
        return this.exec.overload("java.lang.String").call(this, command);
    }
}

function testFileExistsCheck() {
    // 通过Hook注File接口，判断是否在检测root
    var commandFilePaths = [
        "/data/local/bin/su",
        "/data/local/su",
        "/data/local/xbin/su",
        "/dev/com.koushikdutta.superuser.daemon/",
        "/sbin/su",
        "/system/app/Superuser.apk",
        "/system/bin/failsafe/su",
        "/system/bin/su",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/sd/xbin/su",
        "/system/xbin/busybox",
        "/system/xbin/daemonsu",
        "/system/xbin/su",
    ];
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var filename = this.getAbsolutePath();//获取文件路径
        if (commandFilePaths.indexOf(filename) >= 0) {
            console.log("--> File existence check of \"" + filename + "\" detected,which has been bypassed !!");
            return false; //直接返回false 不做校验
        }
        return this.exists.call(this);
    }

}


function testEmulatorFingerprint() {
    //校验自定义系统的指纹。如果是自己编译的系统，fingerprint可能是test-key开头的，这里可能是被检测的点
    var NeedCheckStringList = ["Xposed", "test-key", "xposed", "frida", "frida_server", "Frida", "frida-server"];//需要检测的数组，包括一些字符串比较的，例如比较test-key Xposed xposed 等
    var JavaString = Java.use("java.lang.String");
    JavaString.contains.overload("java.lang.CharSequence").implementation = function (name) {

        for (var i = 0; i < NeedCheckStringList.length; i++) {
            if (name == NeedCheckStringList[i]) {
                console.log("Detect: java.lang.String contains \"" + String(name) + "\" ,bypass it!");
                return false;
            }
        }
        return this.contains.call(this, name);

    }

}

function bypassAntiCheck() {

    try {
        testEmulatorFingerprint(); // 暂时不用这个功能，其他已经测试完成
        testFileExistsCheck();
        testSucheck();
    } catch (error) {
        console.error("--> error occured in function bypassAntiCheck ! It will be ignored!!! " + error.message);
    }
}

setTimeout(function () {
    Java.perform(function () {
        // vatrclazz_Thread = Java.use("java.lang.Thread");
        console.log("Entering Js code , monitor_tpl.js -->")
        // call native hook
        // 

        // 优先调用反调试作为预先处理
        bypassAntiCheck(); //如果异常会自动提示
    });
}, 0);