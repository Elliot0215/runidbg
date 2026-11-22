// runidbg QuickJS V1 + V2 Bootstrap — wraps Rust `__native` bridge into ergonomic JS APIs

(function (global) {
  function toAddr(v) {
    if (typeof v === "bigint") return Number(v);
    if (typeof v === "number") return v;
    throw new TypeError("Expected number or bigint address/argument, got " + typeof v);
  }

  function formatArg(v) {
    if (v instanceof Uint8Array) {
      return "Uint8Array(" + v.length + ") [" + hex(v.slice(0, 16)) + (v.length > 16 ? "..." : "") + "]";
    }
    if (typeof v === "bigint") return v.toString() + "n";
    if (typeof v === "object" && v !== null) {
      try {
        return JSON.stringify(v, (_, x) => (typeof x === "bigint" ? x.toString() + "n" : x));
      } catch (_) {
        return String(v);
      }
    }
    return String(v);
  }

  global.hex = function hex(bytes) {
    if (!(bytes instanceof Uint8Array)) {
      throw new TypeError("hex() expects a Uint8Array");
    }
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      out += (b < 16 ? "0" : "") + b.toString(16);
    }
    return out;
  };

  global.console = {
    log(...vals) {
      __native.print("log", vals.map(formatArg).join(" "));
    },
    warn(...vals) {
      __native.print("warn", vals.map(formatArg).join(" "));
    },
    error(...vals) {
      __native.print("error", vals.map(formatArg).join(" "));
    },
  };

  // V2: Host filesystem helpers
  global.fs = {
    readBytes(path) {
      return __native.fsReadBytes(String(path));
    },
    readText(path) {
      return __native.fsReadText(String(path));
    },
    writeBytes(path, bytes) {
      if (!(bytes instanceof Uint8Array)) {
        throw new TypeError("fs.writeBytes expects a Uint8Array");
      }
      __native.fsWriteBytes(String(path), bytes);
    },
    writeText(path, text) {
      __native.fsWriteText(String(path), String(text));
    },
    exists(path) {
      return __native.fsExists(String(path));
    },
  };

  // V2: CommonJS require()
  global.require = function require(specifier) {
    return __native.requireModule(String(specifier));
  };

  // RPC: Frida-style rpc.exports registry & JSON bridge helpers
  global.rpc = { exports: {} };

  function toJsonSafe(val) {
    if (val instanceof Uint8Array) {
      return { __type: "bytes", hex: hex(val), length: val.length };
    }
    if (typeof val === "bigint") {
      return val.toString();
    }
    return val;
  }

  function safeStringify(val) {
    if (val === undefined) return "null";
    return JSON.stringify(val, (_, v) => toJsonSafe(v));
  }

  global.__rpcList = function __rpcList() {
    const exp = global.rpc && global.rpc.exports;
    if (!exp || typeof exp !== "object") return "[]";
    const names = Object.keys(exp).filter((k) => typeof exp[k] === "function");
    names.sort();
    return JSON.stringify(names);
  };

  global.__asyncSlot = { state: "idle", json: "null", err: null };

  function settleOrWrap(ret) {
    if (ret && typeof ret.then === "function") {
      global.__asyncSlot = { state: "pending", json: "null", err: null };
      ret.then(
        (v) => {
          try {
            global.__asyncSlot = { state: "ok", json: safeStringify(v), err: null };
          } catch (e) {
            global.__asyncSlot = { state: "err", json: "null", err: String(e) };
          }
        },
        (e) => {
          global.__asyncSlot = {
            state: "err",
            json: "null",
            err: e && e.stack ? String(e.message || e) + "\n" + e.stack : String(e),
          };
        }
      );
      return "__PENDING__";
    }
    return safeStringify(ret);
  }

  global.__rpcCall = function __rpcCall(method, paramsJson) {
    const exp = global.rpc && global.rpc.exports;
    if (!exp || typeof exp[method] !== "function") {
      throw new Error("RPC method not found: " + method);
    }
    const parsed = paramsJson ? JSON.parse(paramsJson) : [];
    const callArgs = Array.isArray(parsed) ? parsed : [parsed];
    return settleOrWrap(exp[method](...callArgs));
  };

  global.__evalToJson = function __evalToJson(code) {
    return settleOrWrap((0, eval)(code));
  };

  // Per-emu MemNamespace registry so CpuContext.mem can reuse it with zero allocation
  const emuMemMap = new Map();

  // Build shared prototype for V2 CpuContext (x0..x30, sp, pc, lr, fp, nzcv, retval)
  const cpuCtxProto = {
    reg(name) {
      return __native.regGet(this._emuId, String(name));
    },
    regBigInt(name) {
      return __native.regGetBigInt(this._emuId, String(name));
    },
    setReg(name, val) {
      __native.regSet(this._emuId, String(name), val);
    },
    args(n = 8) {
      const count = Math.min(Math.max(Number(n) | 0, 0), 8);
      const out = new Array(count);
      for (let i = 0; i < count; i++) {
        out[i] = __native.regGet(this._emuId, "x" + i);
      }
      return out;
    },
    stop() {
      __native.emuStop(this._emuId);
    },
    get mem() {
      return emuMemMap.get(this._emuId);
    },
    get retval() {
      return __native.regGet(this._emuId, "x0");
    },
    set retval(val) {
      __native.regSet(this._emuId, "x0", val);
    },
  };

  const regProps = ["sp", "pc", "lr", "fp", "nzcv"];
  for (let i = 0; i <= 30; i++) regProps.push("x" + i);
  for (const name of regProps) {
    Object.defineProperty(cpuCtxProto, name, {
      enumerable: true,
      get() {
        return __native.regGet(this._emuId, name);
      },
      set(val) {
        __native.regSet(this._emuId, name, val);
      },
    });
  }

  global.__makeCpuCtx = function __makeCpuCtx(emuId) {
    const ctx = Object.create(cpuCtxProto);
    ctx._emuId = emuId;
    return ctx;
  };

  function makeHookHandle(emuId, hookId) {
    let detached = false;
    return {
      id: hookId,
      detach() {
        if (detached) return false;
        detached = true;
        return __native.hookDetach(emuId, hookId);
      },
    };
  }

  function makeModule(emuId, info) {
    const modId = info.id;
    return {
      name: info.name,
      base: info.base,
      size: info.size,
      symbol(name) {
        const addr = __native.modSymbol(emuId, modId, String(name));
        return addr === 0 ? null : addr;
      },
      exports() {
        return __native.modExports(emuId, modId);
      },
      call(symOrAddr, ...callArgs) {
        const rawArgs = callArgs.map(toAddr);
        if (typeof symOrAddr === "string") {
          return __native.modCallSymbol(emuId, modId, symOrAddr, rawArgs);
        }
        return __native.emuCallAddr(emuId, toAddr(symOrAddr), rawArgs);
      },
      runInit() {
        __native.modRunInit(emuId, modId);
      },
      _id: modId,
    };
  }

  global.Emu = {
    backends() {
      return __native.emuCompiledBackends();
    },
    create(opts = {}) {
      const packageName = opts.packageName || "com.example.app";
      const searchPaths = Array.isArray(opts.searchPaths) ? opts.searchPaths.map(String) : [];
      const hleAccel = opts.hleAccel !== undefined ? Boolean(opts.hleAccel) : true;
      const heapSize = opts.heapSize !== undefined ? Number(opts.heapSize) : 32 * 1024 * 1024;
      const requestedBackend = opts.backend !== undefined ? String(opts.backend) : "unicorn";
      const emuId = __native.emuCreate(packageName, searchPaths, hleAccel, heapSize, requestedBackend);
      const backend = __native.emuBackend(emuId);
      const supportsTrace = backend === "unicorn";
      const supportsGdb = backend === "unicorn";

      const memNs = {
        alloc(size) {
          return __native.memAlloc(emuId, Number(size));
        },
        readBytes(addr, len) {
          return __native.memReadBytes(emuId, toAddr(addr), Number(len));
        },
        writeBytes(addr, bytes) {
          if (!(bytes instanceof Uint8Array)) {
            throw new TypeError("mem.writeBytes expects a Uint8Array");
          }
          __native.memWriteBytes(emuId, toAddr(addr), bytes);
        },
        readCString(addr, maxLen = 4096) {
          return __native.memReadCString(emuId, toAddr(addr), Number(maxLen));
        },
        writeCString(addr, str) {
          return __native.memWriteCString(emuId, toAddr(addr), String(str));
        },
        readU32(addr) {
          return __native.memReadU32(emuId, toAddr(addr));
        },
        writeU32(addr, val) {
          __native.memWriteU32(emuId, toAddr(addr), Number(val) >>> 0);
        },
        readU64(addr) {
          return __native.memReadU64(emuId, toAddr(addr));
        },
        writeU64(addr, val) {
          __native.memWriteU64(emuId, toAddr(addr), BigInt(val));
        },
        // V2: scan & patch
        scan(start, len, pattern) {
          return __native.memScan(emuId, toAddr(start), Number(len), String(pattern));
        },
        patch(addr, bytes) {
          if (!(bytes instanceof Uint8Array)) {
            throw new TypeError("mem.patch expects a Uint8Array");
          }
          return __native.memPatch(emuId, toAddr(addr), bytes);
        },
        nop(addr, count = 1) {
          return __native.memNop(emuId, toAddr(addr), Number(count));
        },
        ret(addr, retval) {
          const hasVal = retval !== undefined;
          return __native.memRet(emuId, toAddr(addr), hasVal, hasVal ? retval : 0);
        },
        free(addr) {
          return __native.memFree(emuId, toAddr(addr));
        },
        heapUsed() {
          return __native.memHeapUsed(emuId);
        },
      };
      emuMemMap.set(emuId, memNs);
      if (opts.device !== undefined) {
        __native.vfsSetDevice(emuId, opts.device);
      }
      if (opts.realClock !== undefined) {
        __native.vfsUseRealClock(emuId, Boolean(opts.realClock));
      }
      if (opts.net !== undefined) {
        __native.netConfigure(emuId, opts.net);
      }

      return {
        backend,
        supportsTrace,
        supportsGdb,
        load(path, loadOpts = {}) {
          const runInit = loadOpts && loadOpts.runInit === false ? false : true;
          const info = __native.emuLoad(emuId, String(path), runInit);
          return makeModule(emuId, info);
        },
        loadDex(pathOrPaths) {
          const list = Array.isArray(pathOrPaths)
            ? pathOrPaths.map(String)
            : [String(pathOrPaths)];
          return __native.emuLoadDex(emuId, list);
        },
        dex: {
          classes(prefix) {
            return __native.dexClasses(
              emuId,
              prefix !== undefined ? String(prefix) : undefined
            );
          },
          classInfo(className) {
            return __native.dexClassInfo(emuId, String(className));
          },
        },
        loadApk(path) {
          const info = __native.emuLoadApk(emuId, String(path));
          return {
            packageName: info.packageName,
            abi: info.abi,
            libs: info.libs,
            assets: info.assets,
            signatureSize: info.signatureSize,
            loadLib(libName, loadOpts = {}) {
              const runInit = loadOpts && loadOpts.runInit === false ? false : true;
              const modInfo = __native.emuLoadApkLib(emuId, String(libName), runInit);
              return makeModule(emuId, modInfo);
            },
          };
        },
        diag: {
          enable() {
            __native.diagSetEnabled(emuId, true);
          },
          disable() {
            __native.diagSetEnabled(emuId, false);
          },
          clear() {
            __native.diagClear(emuId);
          },
          report() {
            return __native.diagReport(emuId);
          },
          generatePatchJs() {
            return __native.diagGeneratePatchJs(emuId);
          },
        },
        jniOnLoad(mod) {
          const ver = __native.emuJniOnLoad(emuId, mod._id);
          return ver < 0 ? null : ver;
        },
        call(addr, ...callArgs) {
          return __native.emuCallAddr(emuId, toAddr(addr), callArgs.map(toAddr));
        },
        stop() {
          __native.emuStop(emuId);
        },
        lastCrash() {
          return __native.emuLastCrash(emuId) ?? null;
        },
        setLimits(limits = {}) {
          const timeoutMs = limits && limits.timeoutMs !== undefined ? Number(limits.timeoutMs) : 0;
          const maxInsns =
            limits && limits.maxInstructions !== undefined ? Number(limits.maxInstructions) : 0;
          __native.emuSetLimits(emuId, timeoutMs, maxInsns);
        },
        regs: {
          get(name) {
            return __native.regGet(emuId, String(name));
          },
          getBigInt(name) {
            return __native.regGetBigInt(emuId, String(name));
          },
          set(name, val) {
            __native.regSet(emuId, String(name), val);
          },
          dump() {
            return __native.regDump(emuId);
          },
        },
        hook: {
          attach(addr, callbacks) {
            if (!callbacks || typeof callbacks !== "object") {
              throw new TypeError("hook.attach(addr, { onEnter?, onLeave? }) expects an object");
            }
            const onEnter = typeof callbacks.onEnter === "function" ? callbacks.onEnter : null;
            const onLeave = typeof callbacks.onLeave === "function" ? callbacks.onLeave : null;
            if (!onEnter && !onLeave) {
              throw new TypeError("hook.attach requires at least onEnter or onLeave");
            }
            const id = __native.hookAttach(emuId, toAddr(addr), onEnter, onLeave);
            return makeHookHandle(emuId, id);
          },
          replace(addr, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.replace(addr, fn) expects a function");
            }
            const id = __native.hookReplace(emuId, toAddr(addr), fn);
            return makeHookHandle(emuId, id);
          },
          import(symName, callbacks) {
            const addr = __native.hookImportResolve(emuId, String(symName));
            if (typeof callbacks === "function") {
              const id = __native.hookReplace(emuId, addr, callbacks);
              return makeHookHandle(emuId, id);
            }
            if (!callbacks || typeof callbacks !== "object") {
              throw new TypeError("hook.import(symName, { onEnter?, onLeave? } | fn) expects callbacks or a replace function");
            }
            const onEnter = typeof callbacks.onEnter === "function" ? callbacks.onEnter : null;
            const onLeave = typeof callbacks.onLeave === "function" ? callbacks.onLeave : null;
            if (!onEnter && !onLeave) {
              throw new TypeError("hook.import requires at least onEnter or onLeave");
            }
            const id = __native.hookAttach(emuId, addr, onEnter, onLeave);
            return makeHookHandle(emuId, id);
          },
          importReplace(symName, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.importReplace(symName, fn) expects a function");
            }
            const addr = __native.hookImportResolve(emuId, String(symName));
            const id = __native.hookReplace(emuId, addr, fn);
            return makeHookHandle(emuId, id);
          },
          code(addrOrRange, fn, opts = {}) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.code(addrOrRange, fn, opts?) expects a function");
            }
            let begin, end;
            if (Array.isArray(addrOrRange) && addrOrRange.length >= 2) {
              begin = toAddr(addrOrRange[0]);
              end = toAddr(addrOrRange[1]);
            } else {
              begin = toAddr(addrOrRange);
              end = begin;
            }
            let maxHits = -1;
            if (opts && opts.once) {
              maxHits = 1;
            } else if (opts && opts.maxHits !== undefined) {
              maxHits = Number(opts.maxHits);
            }
            const id = __native.hookCode(emuId, begin, end, maxHits, fn);
            return makeHookHandle(emuId, id);
          },
          mem(range, optsOrFn, maybeFn) {
            if (!Array.isArray(range) || range.length < 2) {
              throw new TypeError("hook.mem([begin, end], opts?, fn) expects a [begin, end] range");
            }
            let opts, fn;
            if (typeof optsOrFn === "function") {
              opts = { read: true, write: true };
              fn = optsOrFn;
            } else {
              opts = optsOrFn || {};
              fn = maybeFn;
            }
            if (typeof fn !== "function") {
              throw new TypeError("hook.mem expects a callback function");
            }
            const read = opts.read !== undefined ? Boolean(opts.read) : false;
            const write = opts.write !== undefined ? Boolean(opts.write) : false;
            const r = !read && !write ? true : read;
            const w = !read && !write ? true : write;
            const id = __native.hookMem(emuId, toAddr(range[0]), toAddr(range[1]), r, w, fn);
            return makeHookHandle(emuId, id);
          },
          syscall(nrOrWildcard, fn) {
            if (typeof fn !== "function") {
              throw new TypeError("hook.syscall(nr | '*', fn) expects a function");
            }
            const nr = nrOrWildcard === "*" ? -1 : Number(nrOrWildcard);
            const id = __native.hookSyscall(emuId, nr, fn);
            return makeHookHandle(emuId, id);
          },
        },
        jni: {
          envPtr: 0x18001000,
          hook(className, methods) {
            if (!methods || typeof methods !== "object") {
              throw new TypeError("jni.hook(className, methods) expects an object of functions");
            }
            for (const [methodName, fn] of Object.entries(methods)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hook: ${className}.${methodName} must be a function`);
              }
              __native.jniHook(emuId, String(className), methodName, fn);
            }
          },
          hookField(className, fields) {
            if (!fields || typeof fields !== "object") {
              throw new TypeError("jni.hookField(className, fields) expects an object of functions");
            }
            for (const [fieldKey, fn] of Object.entries(fields)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hookField: ${className}.${fieldKey} must be a function`);
              }
              __native.jniHookField(emuId, String(className), fieldKey, fn);
            }
          },
          hookMethod(className, methods) {
            if (!methods || typeof methods !== "object") {
              throw new TypeError("jni.hookMethod(className, methods) expects an object of functions");
            }
            for (const [methodKey, fn] of Object.entries(methods)) {
              if (typeof fn !== "function") {
                throw new TypeError(`jni.hookMethod: ${className}.${methodKey} must be a function`);
              }
              __native.jniHookMethod(emuId, String(className), methodKey, fn);
            }
          },
          listHooks() {
            return __native.jniListHooks(emuId);
          },
          onUnhandled(fn) {
            if (typeof fn !== "function") {
              throw new TypeError("jni.onUnhandled expects a function");
            }
            __native.jniOnUnhandled(emuId, fn);
          },
          registeredNatives() {
            return __native.jniRegisteredNatives(emuId);
          },
          callNative(className, methodName, callArgs = [], opts = {}) {
            const thisRef =
              opts && opts.this !== undefined && opts.this !== null
                ? toAddr(opts.this)
                : 0;
            return __native.jniCallNative(
              emuId,
              String(className),
              String(methodName),
              callArgs.map(toAddr),
              thisRef
            );
          },
          callNativeOn(objRef, className, methodName, callArgs = []) {
            return __native.jniCallNative(
              emuId,
              String(className),
              String(methodName),
              callArgs.map(toAddr),
              toAddr(objRef)
            );
          },
          newString(s) {
            return __native.jniNewString(emuId, String(s));
          },
          newByteArray(bytes) {
            if (Array.isArray(bytes)) {
              bytes = new Uint8Array(bytes);
            }
            if (!(bytes instanceof Uint8Array)) {
              throw new TypeError("jni.newByteArray expects a Uint8Array or number[]");
            }
            return __native.jniNewByteArray(emuId, bytes);
          },
          newCharArray(input) {
            return __native.jniNewCharArray(emuId, input);
          },
          newIntArray(input) {
            return __native.jniNewIntArray(emuId, input);
          },
          newLongArray(input) {
            return __native.jniNewLongArray(emuId, input);
          },
          newObject(className, fields) {
            return __native.jniNewObject(emuId, String(className), fields || null);
          },
          findClass(className) {
            return __native.jniFindClass(emuId, String(className));
          },
          newStringArray(items) {
            if (!Array.isArray(items)) {
              throw new TypeError("jni.newStringArray expects a string array");
            }
            return __native.jniNewStringArray(emuId, items.map(String));
          },
          getStringArray(ref) {
            return __native.jniGetStringArray(emuId, toAddr(ref)) ?? null;
          },
          newObjectArray(refs) {
            if (!Array.isArray(refs)) {
              throw new TypeError("jni.newObjectArray expects a ref array");
            }
            return __native.jniNewObjectArray(emuId, refs.map(toAddr));
          },
          getObjectArray(ref) {
            return __native.jniGetObjectArray(emuId, toAddr(ref)) ?? null;
          },
          getString(ref) {
            return __native.jniGetString(emuId, toAddr(ref)) ?? null;
          },
          getBytes(ref) {
            return __native.jniGetBytes(emuId, toAddr(ref)) ?? null;
          },
          getChars(ref) {
            return __native.jniGetChars(emuId, toAddr(ref)) ?? null;
          },
          getInts(ref) {
            return __native.jniGetInts(emuId, toAddr(ref)) ?? null;
          },
          getLongs(ref) {
            return __native.jniGetLongs(emuId, toAddr(ref)) ?? null;
          },
          getByteArray(ref) {
            const ta = __native.jniGetBytes(emuId, toAddr(ref));
            return ta ? Array.from(ta) : [];
          },
          getIntArray(ref) {
            const ta = __native.jniGetInts(emuId, toAddr(ref));
            return ta ? Array.from(ta) : [];
          },
          getLongArray(ref) {
            const ta = __native.jniGetLongs(emuId, toAddr(ref));
            return ta ? Array.from(ta, Number) : [];
          },
          getCharArray(ref) {
            const ta = __native.jniGetChars(emuId, toAddr(ref));
            if (!ta || ta.length === 0) return "";
            let out = "";
            for (let i = 0; i < ta.length; i += 4096) {
              out += String.fromCharCode(...ta.subarray(i, Math.min(i + 4096, ta.length)));
            }
            return out;
          },
          setField(objRef, fieldName, value, sig) {
            __native.jniSetField(
              emuId,
              toAddr(objRef),
              String(fieldName),
              value,
              sig !== undefined ? String(sig) : undefined
            );
          },
          getField(objRef, fieldName) {
            return __native.jniGetField(emuId, toAddr(objRef), String(fieldName));
          },
          setStaticField(className, fieldName, value, sig) {
            __native.jniSetStaticField(
              emuId,
              String(className),
              String(fieldName),
              value,
              sig !== undefined ? String(sig) : undefined
            );
          },
          getStaticField(className, fieldName) {
            return __native.jniGetStaticField(emuId, String(className), String(fieldName));
          },
          setStrictFindClass(enabled) {
            __native.jniSetStrictFindClass(emuId, Boolean(enabled));
          },
          describeField(fieldId) {
            return __native.jniDescribeField(emuId, toAddr(fieldId));
          },
          listFields() {
            return __native.jniListFields(emuId);
          },
          describeMethod(methodId) {
            return __native.jniDescribeMethod(emuId, toAddr(methodId));
          },
          listMethods() {
            return __native.jniListMethods(emuId);
          },
          describeObject(ref) {
            return __native.jniDescribeObject(emuId, toAddr(ref));
          },
          trace: {
            start(opts = {}) {
              const maxStrLen = opts && opts.maxStrLen !== undefined ? Number(opts.maxStrLen) : 64;
              const maxEvents = opts && opts.maxEvents !== undefined ? Number(opts.maxEvents) : 0;
              __native.jniTraceStart(emuId, maxStrLen, maxEvents);
            },
            stop() {
              __native.jniTraceStop(emuId);
            },
            clear() {
              __native.jniTraceClear(emuId);
            },
            events() {
              return __native.jniTraceEvents(emuId);
            },
            onEvent(fn) {
              __native.jniTraceOnEvent(emuId, fn || null);
            },
          },
          pushLocalFrame() {
            __native.jniPushLocalFrame(emuId);
          },
          popLocalFrame(keepRef = 0) {
            return __native.jniPopLocalFrame(emuId, toAddr(keepRef));
          },
          withLocalFrame(fn) {
            if (typeof fn !== "function") {
              throw new TypeError("jni.withLocalFrame expects a function");
            }
            __native.jniPushLocalFrame(emuId);
            try {
              return fn();
            } finally {
              __native.jniPopLocalFrame(emuId, 0);
            }
          },
          objectCount() {
            return __native.jniObjectCount(emuId);
          },
        },
        mem: memNs,
        vfs: {
          setProperty(key, val) {
            __native.vfsSetProperty(emuId, String(key), String(val));
          },
          writeFile(guestPath, data) {
            if (typeof data === "string") {
              __native.vfsWriteText(emuId, String(guestPath), data);
            } else if (data instanceof Uint8Array) {
              __native.vfsWriteBytes(emuId, String(guestPath), data);
            } else {
              throw new TypeError("vfs.writeFile expects string or Uint8Array");
            }
          },
          readFile(guestPath) {
            return __native.vfsReadFile(emuId, String(guestPath)) ?? null;
          },
          mountOverlay(guestDir, hostDir) {
            __native.vfsMountOverlay(emuId, String(guestDir), String(hostDir));
          },
          setTime(unixSecs) {
            __native.vfsSetTime(emuId, Number(unixSecs));
          },
          useRealClock(enabled = true) {
            __native.vfsUseRealClock(emuId, Boolean(enabled));
          },
          setDevice(presetOrObj) {
            __native.vfsSetDevice(emuId, presetOrObj);
          },
          deviceProfile() {
            return __native.vfsDeviceProfile(emuId);
          },
        },
        net: {
          enable(netOpts = true) {
            if (typeof netOpts === "boolean") {
              __native.netConfigure(emuId, netOpts);
            } else {
              __native.netConfigure(emuId, Object.assign({ enabled: true }, netOpts || {}));
            }
          },
          disable() {
            __native.netConfigure(emuId, false);
          },
          setNic(nicObj) {
            __native.netSetNic(emuId, nicObj || {});
          },
          nic() {
            return __native.netNic(emuId);
          },
          packets() {
            return __native.netPackets(emuId);
          },
          clearPackets() {
            __native.netClearPackets(emuId);
          },
          onSend(fn) {
            __native.netSetInterceptor(emuId, true, fn || null);
          },
          onRecv(fn) {
            __native.netSetInterceptor(emuId, false, fn || null);
          },
        },
        trace: {
          start(traceOpts = {}) {
            const output = traceOpts.output ? String(traceOpts.output) : "";
            const level = traceOpts.level ? String(traceOpts.level) : "reg_delta";
            const start = traceOpts.start !== undefined ? toAddr(traceOpts.start) : 0;
            const end = traceOpts.end !== undefined ? toAddr(traceOpts.end) : -1;
            const capacity = traceOpts.capacity !== undefined ? Number(traceOpts.capacity) : 65536;
            __native.traceStart(emuId, output, level, start, end, capacity);
          },
          stop() {
            return __native.traceStop(emuId);
          },
        },
        snapshot() {
          return __native.emuSnapshot(emuId);
        },
        restore(snapId) {
          __native.emuRestore(emuId, Number(snapId));
        },
      };
    },
  };
})(globalThis);
