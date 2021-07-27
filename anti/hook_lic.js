
const STD_STRING_SIZE = 3 * Process.pointerSize;


// StdString start
// class StdString {
//     constructor() {
//         this.handle = Memory.alloc(STD_STRING_SIZE);
//     }

//     dispose() {
//         const [data, isTiny] = this._getData();
//         if (!isTiny) {
//             Java.api.$delete(data);
//         }
//     }

//     disposeToString() {
//         const result = this.toString();
//         this.dispose();
//         return result;
//     }

//     toString() {
//         const [data] = this._getData();
//         return data.readUtf8String();
//     }

//     _getData() {
//         const str = this.handle;
//         const isTiny = (str.readU8() & 1) === 0;
//         const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
//         return [data, isTiny];
//     }
// }

// StdString end
// https://github.com/lasting-yang/frida_hook_libart/blob/master/hook_RegisterNatives.js
function hook_RegisterNatives() {
    var symbols = Module.enumerateSymbolsSync("libart.so");
    var addrRegisterNatives = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];

        //_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi
        if (symbol.name.indexOf("art") >= 0 &&
            symbol.name.indexOf("JNI") >= 0 &&
            symbol.name.indexOf("RegisterNatives") >= 0 &&
            symbol.name.indexOf("CheckJNI") < 0) {
            addrRegisterNatives = symbol.address;
            console.log("RegisterNatives is at ", symbol.address, symbol.name);
        }
    }

    if (addrRegisterNatives != null) {
        Interceptor.attach(addrRegisterNatives, {
            onEnter: function (args) {
                console.log("[RegisterNatives] method_count:", args[3]);
                var env = args[0];
                var java_class = args[1];
                var class_name = Java.vm.tryGetEnv().getClassName(java_class);
                //console.log(class_name);

                var methods_ptr = ptr(args[2]);

                var method_count = parseInt(args[3]);
                for (var i = 0; i < method_count; i++) {
                    var name_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3));
                    var sig_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize));
                    var fnPtr_ptr = Memory.readPointer(methods_ptr.add(i * Process.pointerSize * 3 + Process.pointerSize * 2));

                    var name = Memory.readCString(name_ptr);
                    var sig = Memory.readCString(sig_ptr);
                    var find_module = Process.findModuleByAddress(fnPtr_ptr);
                    console.log("[RegisterNatives] java_class:", class_name, "name:", name, "sig:", sig, "fnPtr:", fnPtr_ptr, "module_name:", find_module.name, "module_base:", find_module.base, "offset:", ptr(fnPtr_ptr).sub(find_module.base));

                }
            }
        });
    }
}

//

function hook_read() {
    Interceptor.attach(Module.getExportByName("libc.so", "read"), {
        onEnter: function (args) {
            // ssize_t read [1]  (int fd, void *buf, size_t count);
            // var s1 = Memory.readUtf8String(args[0])
            // // var s2 = Memory.readUtf8String(args[1])
            // will dump hex data to console 
            console.log("========================== read =========================")
            console.log("-> default dump read size:  256")
            console.log("")
            var data = Memory.readByteArray(args[1], 256)
            console.log(data)


        },

    });
}


function hook_write() {

    Interceptor.attach(Module.getExportByName("libc.so", "write"), {
        onEnter: function (args) {
            // var s1 = Memory.readUtf8String(args[0])
            // // var s2 = Memory.readUtf8String(args[1])
            // will dump hex data to console

            // ssize_t write(int fd, const void *buf, size_t nbyte);
            console.log("========================== write =========================")
            console.log("-> default dump wtite size: 256")
            console.log("")
            var data = Memory.readByteArray(args[1], 256)
            console.log(data)
        },

    });

}


function hook_opens() {
    Interceptor.attach(Module.getExportByName("libc.so", "open"), {

        onEnter: function (args) {
            var s1 = Memory.readUtf8String(args[0])
            console.log("[+] open " + "path:\"" + s1 + "\"")
            // hook_read()
            // hook_write()
            // var s2 = Memory.readUtf8String(args[1])
            // console.log("[+] open " + "path:\"" + s1 + "\"")
            // if (s1 && s1.search("/sdcard") != -1) {
            //     console.log("[+] open " + "path:\"" + s1 + "\"")
            //     hook_read()
            //     hook_write()
            // }
        },
    });

    Interceptor.attach(Module.getExportByName("libc.so", "fopen"), {

        onEnter: function (args) {
            var s1 = Memory.readUtf8String(args[0])
            var s2 = Memory.readUtf8String(args[1])
            console.log("[+] fopen " + "path:\"" + s1 + "\"" + " mode:\"" + s2 + "\"")
            // if (s1 && s1.search("/sdcard") != -1) {

            //     console.log("[+] fopen " + "path:\"" + s1 + "\"" + " mode:\"" + s2 + "\"")
            // }
            // else if (s1 && s1.search("/storage") != -1) {

            //     console.log("[+] fopen " + "path:\"" + s1 + "\"" + " mode:\"" + s2 + "\"")
            // }
        },

    });



    Interceptor.attach(Module.getExportByName("libc.so", "system"), {

        onEnter: function (args) {
            var s1 = Memory.readUtf8String(args[0])
            console.log("[+] executed command by function system " + "s1:\"" + s1)

        },

    });

    Interceptor.attach(Module.getExportByName("libc.so", "popen"), {

        onEnter: function (args) {
            var s1 = Memory.readUtf8String(args[0])
            var s2 = Memory.readUtf8String(args[1])
            console.log("[+] popen " + "path:\"" + s1 + "\"" + " s2:\"" + s2 + "\"")

        },

    });
}

function bypass_check() {
    // 通过strstr函数检测是否存在特征 xposed frida ida等
    Interceptor.attach(Module.getExportByName("libc.so", "strstr"), {

        onEnter: function (args) {
            // s2可能会为空，导致检测失败，所以默认使用s1就能判断成功
            var s1 = Memory.readUtf8String(args[0])
            var s2 = Memory.readUtf8String(args[1])
            // console.log("--> strstr s2: " + s2)

            this.flag = false
            if (s1 && s1.search("re.frida.server") != -1) {
                this.flag = true
            }
            if (s1 && s1.search("xposed") != -1) {
                this.flag = true
            }
            if (s1 && s1.search("TracerPid") != -1) {
                // 
                // console.log("---> TracerPid found : " + s1)
                this.flag = true
            }
            if (this.flag) {
                console.log("--> Found frida detect ," + "s1: " + "\"" + s1 + "\"" + "s2: \"" + s2 + " \"")
            }
        },
        onLeave: function (retval) {
            if (this.flag) {
                retval.replace(ptr(0))
                this.flag = false
                // console.log("--> replace strstr return value null ok,check was bypass")
            }
        }

    });

}

function prettyMethod(method_id, withSignature) {
    // const result = new StdString(); // 这个方法在frida 12.11.11 上无法使用，所以这里我将这个类注释掉了
    var result = Memory.alloc(STD_STRING_SIZE);
    Java.api['art::ArtMethod::PrettyMethod'](result, method_id, withSignature ? 1 : 0);
    //return result.disposeToString();
    const str = result
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * Process.pointerSize).readPointer();
    var info = data.readUtf8String();
    // console.log("--> prettyMethod info: " + info)
    return info
}

function hook_dlopen(module_name, fun) {
    var android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");

    if (android_dlopen_ext) {
        Interceptor.attach(android_dlopen_ext, {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr) {
                    this.path = (pathptr).readCString();
                    if (this.path.indexOf(module_name) >= 0) {
                        this.canhook = true;
                        console.log("android_dlopen_ext:", this.path);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.canhook) {
                    fun();
                }
            }
        });
    }
    var dlopen = Module.findExportByName(null, "dlopen");
    if (dlopen) {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr) {
                    this.path = (pathptr).readCString();
                    if (this.path.indexOf(module_name) >= 0) {
                        this.canhook = true;
                        console.log("dlopen:", this.path);
                    }
                }
            },
            onLeave: function (retval) {
                if (this.canhook) {
                    fun();
                }
            }
        });
    }
    console.log("android_dlopen_ext:", android_dlopen_ext, "dlopen:", dlopen);
}

function hook_native() {
    var module_libart = Process.findModuleByName("libart.so");
    var symbols = module_libart.enumerateSymbols();
    var ArtMethod_Invoke = null;
    for (var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        var address = symbol.address;
        var name = symbol.name;
        var indexArtMethod = name.indexOf("ArtMethod");
        var indexInvoke = name.indexOf("Invoke");
        var indexThread = name.indexOf("Thread");
        if (indexArtMethod >= 0
            && indexInvoke >= 0
            && indexThread >= 0
            && indexArtMethod < indexInvoke
            && indexInvoke < indexThread) {
            console.log(name);
            ArtMethod_Invoke = address;
        }
    }
    if (ArtMethod_Invoke) {
        Interceptor.attach(ArtMethod_Invoke, {
            onEnter: function (args) {
                var method_name = prettyMethod(args[0], 0);
                if (!(method_name.indexOf("java.") == 0 || method_name.indexOf("android.") == 0)) {
                    console.log("ArtMethod Invoke: " + method_name + '  called from:\n' +
                        Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join('\n') + '\n');
                }
            }
        });
    }

}


function hook_artmethod() {
    hook_dlopen("libart.so", hook_native);
    hook_native();
}

//



function dohook() {

    bypass_check() // call bypass 绕过 检测/proc/pid/maps 或者 /proc/self/maps  使用strstr 检测是否包含了frida或者xposed字符串
    // hook_RegisterNatives() // catch all jni registerNatives
    // trace all method call
    hook_artmethod()

}

setImmediate(dohook)