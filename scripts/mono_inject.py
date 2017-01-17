import frida
import sys
import time
import subprocess
import json
import psutil
def on_message(message, data):
   print("recv [%s] => %s" % (message, data))

def main():
    pid=frida.spawn(["F:\\GitHub\\frida_learning\\testWin\\build\\test.exe"])
    session = frida.attach(pid)
    script = session.create_script("""
	function hexToBytes(hex) {
		for (var bytes = [], c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
		return bytes;
	}
    var baseAddr = Module.findBaseAddress('mono.dll');
    console.log('mono.dll baseAddr: ' + baseAddr);
	Interceptor.attach(Module.findExportByName("mono.dll" , "mono_image_open_from_data"), {
        onEnter: function(args) {
			console.log('mono_image_open_from_data onEnter');
			console.log('name:' + args[1]);
		},
		onLeave:function(retval){
		}
    });
	Interceptor.attach(Module.findExportByName("mono.dll" , "mono_assembly_load_from_full"), {
        onEnter: function(args) {
			console.log('mono_assembly_load_from_full onEnter');
			curFileName = Memory.readUtf8String(args[1]);
			console.log('name:' + curFileName);
		},
		onLeave:function(retval){
		}
    });

	recv('poke', function onMessage(pokeMessage) 
	{ 
		for(var i in pokeMessage)
			console.log(i);

		var bytes=hexToBytes(pokeMessage["data"])
		var mem=Memory.alloc(bytes.length)
		console.log("mem:"+mem)
		Memory.writeByteArray(mem, bytes)
		var status=Memory.alloc(4)
		console.log("status "+status)
            
		var  mono_image_open_from_data_func=new NativeFunction(Module.findExportByName("mono.dll" , "mono_image_open_from_data"),"pointer",["int","int","int","int","int"])
		var image_data_get_result=mono_image_open_from_data_func(mem.toInt32(),bytes.length,1,status.toInt32(),0);
		console.log("image_data_get_result "+image_data_get_result)
		console.log("status "+Memory.readInt(status));
            
		var image=new NativePointer(image_data_get_result);
		var pName=Memory.allocUtf8String("ok")
		console.log("pName:"+pName);
		status=Memory.alloc(4)
		
		var mono_assembly_load_from_full_func=new NativeFunction(Module.findExportByName("mono.dll" , "mono_assembly_load_from_full"),"pointer",["pointer","pointer","pointer","int"])
		console.log("mono_assembly_load_from_full_func "+mono_assembly_load_from_full_func)
		var assembly=mono_assembly_load_from_full_func(image_data_get_result,pName,status,0)
		console.log("status "+Memory.readInt(status));
		console.log("assembly "+assembly);
		
		var mono_assembly_get_image_func=new NativeFunction(Module.findExportByName("mono.dll" , "mono_assembly_get_image"),"int",["int"])
		var ret3=mono_assembly_get_image_func(assembly)
		console.log("ret3:"+ret3);
		
		var mono_class_from_name_func=new NativeFunction(Module.findExportByName("mono.dll","mono_class_from_name"),"int",["int","pointer","pointer"]);
		var klass=mono_class_from_name_func(ret,Memory.allocUtf8String(""),Memory.allocUtf8String("Injector"));
		console.log("klass:"+klass);
		
		//var mono_class_get_method_from_name_func=new NativeFunction(Module.findExportByName("mono.dll","mono_class_get_method_from_name"),"int",["int","pointer","int"]);
		//var method=mono_class_get_method_from_name_func(klass,Memory.allocUtf8String("Inject"),0);
		//console.log("method:"+method);
	});

""")

    script.on('message', on_message)
    frida.resume(pid);
    script.load()
    fileContent=open('F:\\GitHub\\frida_learning\\scripts\\sF.dll', 'rb').read()
    time.sleep(1)
    byteStr=''.join('{:02x}'.format(x) for x in fileContent)
    script.post({"type": "poke","data":byteStr})
    input('[!] Press Enter at any time to detach from instrumented program.\n\n')
    session.detach()

if __name__ == '__main__':
    main()
