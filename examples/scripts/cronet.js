/// <reference path="./runidbg.d.ts" />
// Run with:
//   cargo run --bin runidbg-cli -- run examples/scripts/cronet.js

const emu = Emu.create({
  packageName: "com.example.cronetdemo",
  hleAccel: true,
});

emu.jni.hook("org/chromium/base/JNIUtils", {
  getSplitClassLoader(splitName) {
    return emu.jni.newObject("java/lang/ClassLoader", { split: String(splitName) });
  },
});

emu.jni.hook("internal/org/jni_zero/JniInit", {
  init() {
    const emptyMap = emu.jni.newObject("java/util/Collections$EmptyMap");
    return [emptyMap, null];
  },
});

const mod = emu.load("samples/libcronet.so");
console.log("Loaded", mod.name, "at 0x" + mod.base.toString(16), "size=" + mod.size);

const jniVer = emu.jniOnLoad(mod);
console.log("JNI_OnLoad => 0x" + (jniVer ?? 0).toString(16));
console.log("Registered natives:", emu.jni.registeredNatives().length);

const engine = mod.call("Cronet_Engine_Create");
const verPtr = mod.call("Cronet_Engine_GetVersionString", engine);
console.log("Cronet version:", emu.mem.readCString(verPtr));
mod.call("Cronet_Engine_Destroy", engine);
