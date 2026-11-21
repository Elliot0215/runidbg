// runidbg (runidbg-arm64-emu-tracer) QuickJS Scripting Type Definitions (V1 + V2)
// Export via: runidbg-cli init-types

declare const args: string[];

declare function hex(bytes: Uint8Array): string;
declare function require(specifier: string): any;

declare namespace console {
  function log(...values: unknown[]): void;
  function warn(...values: unknown[]): void;
  function error(...values: unknown[]): void;
}

declare namespace fs {
  function readBytes(path: string): Uint8Array;
  function readText(path: string): string;
  function writeBytes(path: string, bytes: Uint8Array): void;
  function writeText(path: string, text: string): void;
  function exists(path: string): boolean;
}

declare namespace rpc {
  let exports: Record<string, (...args: any[]) => any>;
}

type DevicePresetName = "pixel5" | "pixel8pro" | "s24ultra" | "xiaomi14";

interface DeviceProfileConfig {
  preset?: DevicePresetName;
  brand?: string;
  manufacturer?: string;
  model?: string;
  device?: string;
  product?: string;
  board?: string;
  hardware?: string;
  socPlatform?: string;
  fingerprint?: string;
  buildId?: string;
  buildDisplay?: string;
  incremental?: string;
  securityPatch?: string;
  androidRelease?: string;
  sdkInt?: number;
  abi?: string;
  abiList?: string;
  cpuCores?: number;
  ramTotalKb?: number;
  kernelRelease?: string;
  kernelVersion?: string;
  screenWidth?: number;
  screenHeight?: number;
  screenDpi?: number;
  locale?: string;
  timezone?: string;
  carrierName?: string;
  carrierMccMnc?: string;
  serialNo?: string;
  androidId?: string;
}

interface EmuOptions {
  packageName?: string;
  searchPaths?: string[];
  hleAccel?: boolean;
  heapSize?: number;
  device?: DevicePresetName | DeviceProfileConfig;
  realClock?: boolean;
  net?: boolean | NetOptions;
}

interface TraceOptions {
  output?: string;
  level?: "fast" | "reg_delta" | "full";
  start?: number | bigint;
  end?: number | bigint;
  capacity?: number;
}

interface TraceStats {
  records: number;
  extRecords: number;
  totalInsns: number;
  droppedInsns: number;
  droppedExt: number;
}

interface RegisteredNativeInfo {
  className: string;
  name: string;
  sig: string;
  fnPtr: number;
}

interface UnhandledJniInfo {
  kind: string;
  className: string;
  name: string;
  sig: string;
  isStatic: boolean;
  args: unknown[];
}

interface HookHandle {
  readonly id: number;
  detach(): boolean;
}

interface CodeHookOptions {
  once?: boolean;
  maxHits?: number;
}

interface MemHookOptions {
  read?: boolean;
  write?: boolean;
}

interface CpuContext {
  x0: number; x1: number; x2: number; x3: number; x4: number; x5: number; x6: number; x7: number;
  x8: number; x9: number; x10: number; x11: number; x12: number; x13: number; x14: number; x15: number;
  x16: number; x17: number; x18: number; x19: number; x20: number; x21: number; x22: number; x23: number;
  x24: number; x25: number; x26: number; x27: number; x28: number; x29: number; x30: number;
  sp: number;
  pc: number;
  lr: number;
  fp: number;
  nzcv: number;
  retval: number;
  readonly mem: MemNamespace;
  reg(name: string): number;
  regBigInt(name: string): bigint;
  setReg(name: string, value: number | bigint): void;
  args(count?: number): number[];
  stop(): void;
}

interface AttachCallbacks {
  onEnter?: (this: Record<string, any>, ctx: CpuContext) => void;
  onLeave?: (this: Record<string, any>, ctx: CpuContext) => void;
}

interface RegsNamespace {
  get(name: string): number;
  getBigInt(name: string): bigint;
  set(name: string, value: number | bigint): void;
  dump(): Record<string, number>;
}

interface HookNamespace {
  /** 在已映射指令地址挂入 onEnter/onLeave Hook（若地址未映射会立即抛错） */
  attach(addr: number | bigint, callbacks: AttachCallbacks): HookHandle;
  replace(addr: number | bigint, fn: (ctx: CpuContext) => number | bigint | boolean | void): HookHandle;
  /** 按外部导入符号名（如 `"fopen"`, `"getauxval"`）挂 Hook；支持在 `emu.load` 之前或之后调用 */
  import(
    symbolName: string,
    callbacks: AttachCallbacks | ((ctx: CpuContext) => number | bigint | boolean | void)
  ): HookHandle;
  /** 按外部导入符号名直接替换其实现（无需反汇编找 PLT 偏移） */
  importReplace(
    symbolName: string,
    fn: (ctx: CpuContext) => number | bigint | boolean | void
  ): HookHandle;
  /**
   * 指令级 Hook（**指令执行前**触发回调；在回调内调用 `ctx.setReg` / 改写 `ctx.x0` 会立即作用于当前即将执行的这条指令）。
   * 若要改写某次 `BL` 调用后的返回值，请把地址挂在 `BL` 的**下一条指令**（`blAddr + 4`），例如：
   * ```js
   * emu.hook.code(mod.base + 0x93664 + 4, (ctx) => { ctx.x0 = 1; });
   * ```
   */
  code(
    addrOrRange: number | bigint | [number | bigint, number | bigint],
    fn: (ctx: CpuContext, pc: number, size: number) => void,
    options?: CodeHookOptions
  ): HookHandle;
  mem(
    range: [number | bigint, number | bigint],
    options: MemHookOptions,
    fn: (ctx: CpuContext, access: "read" | "write" | "other", addr: number, size: number, value: number) => void
  ): HookHandle;
  mem(
    range: [number | bigint, number | bigint],
    fn: (ctx: CpuContext, access: "read" | "write" | "other", addr: number, size: number, value: number) => void
  ): HookHandle;
  syscall(
    nrOrWildcard: number | "*",
    fn: (ctx: CpuContext, nr: number) => number | bigint | void | undefined
  ): HookHandle;
}

interface LoadOptions {
  /** 是否在加载后立即执行 DT_INIT / .init_array 构造器（默认 true；设为 false 可先挂 Hook 再手动调用 mod.runInit()） */
  runInit?: boolean;
}

interface ModuleHandle {
  readonly name: string;
  readonly base: number;
  readonly size: number;
  symbol(name: string): number | null;
  exports(): string[];
  call(symOrAddr: string | number | bigint, ...args: Array<number | bigint>): number;
  /** 手动执行该模块的 DT_INIT / .init_array 构造器（配合 `load(path, { runInit: false })` 使用） */
  runInit(): void;
}

interface JniFieldInfo {
  readonly id: number;
  readonly className: string;
  readonly name: string;
  readonly sig: string;
  readonly isStatic: boolean;
}

interface JniMethodInfo {
  readonly id: number;
  readonly className: string;
  readonly name: string;
  readonly sig: string;
  readonly isStatic: boolean;
}

interface JniObjectInfo {
  readonly ref: number;
  readonly className: string;
  readonly kind: string;
}

interface JniTraceEvent {
  readonly seq: number;
  readonly op: string;
  readonly className: string;
  readonly targetRef: number;
  readonly member: string;
  readonly sig: string;
  readonly args: string[];
  readonly ret: string;
  readonly isNull: boolean;
}

interface JniTraceNamespace {
  /** 开启全量 JNI 调用事件采集（默认关闭，关闭时零开销） */
  start(opts?: { maxStrLen?: number; maxEvents?: number }): void;
  stop(): void;
  clear(): void;
  /** 导出完整 JNI 调用序列（不受 32 条面包屑环形缓冲截断） */
  events(): JniTraceEvent[];
  /** 实时订阅每一次 JNI 调用事件（无需硬编码虚表/槽位地址；传 null 取消订阅） */
  onEvent(cb: ((ev: JniTraceEvent) => void) | null): void;
}

interface JniNamespace {
  readonly envPtr: number;
  hook(className: string, methods: Record<string, (...args: any[]) => any>): void;
  onUnhandled(callback: (info: UnhandledJniInfo) => any): void;
  registeredNatives(): RegisteredNativeInfo[];
  /**
   * 调用通过 `RegisterNatives` 动态注册的 JNI 方法。
   * - 静态方法：不传 `opts.this`，`X1` 自动传 `jclass`；
   * - 实例方法：传 `{ this: objRef }`，`X1` 传入该实例 `jobject`（使 `GetObjectField(this, ...)` 正常读取实例字段）。
   */
  callNative(
    className: string,
    methodName: string,
    args?: Array<number | bigint>,
    opts?: { this?: number | bigint }
  ): number;
  /** 以指定实例 `objRef` 作为 `this` 调用已注册的 JNI 实例方法 */
  callNativeOn(
    objRef: number | bigint,
    className: string,
    methodName: string,
    args?: Array<number | bigint>
  ): number;
  findClass(className: string): number;
  newString(value: string): number;
  newByteArray(bytes: Uint8Array): number;
  /** 创建 `[C` (`jcharArray`, UTF-16) 对象 */
  newCharArray(input: string | Uint16Array | number[]): number;
  /** 创建 `[I` (`jintArray`) 对象 */
  newIntArray(input: Int32Array | number[]): number;
  /** 创建 `[J` (`jlongArray`) 对象 */
  newLongArray(input: BigInt64Array | Array<number | bigint>): number;
  newObject(className: string, fields?: Record<string, unknown>): number;
  newStringArray(items: string[]): number;
  getStringArray(ref: number | bigint): Array<string | null> | null;
  newObjectArray(refs: Array<number | bigint>): number;
  getObjectArray(ref: number | bigint): number[] | null;
  getString(ref: number | bigint): string | null;
  getBytes(ref: number | bigint): Uint8Array | null;
  /** 读取 `[C` (`jcharArray`, UTF-16) 内容 */
  getChars(ref: number | bigint): Uint16Array | null;
  /** 读取 `[I` (`jintArray`) 内容 */
  getInts(ref: number | bigint): Int32Array | null;
  /** 读取 `[J` (`jlongArray`) 内容 */
  getLongs(ref: number | bigint): BigInt64Array | null;
  /** 设置实例对象字段（支持基本类型、string、TypedArray、jobject 句柄及可选 JNI 签名 `sig`） */
  setField(objRef: number | bigint, fieldName: string, value: unknown, sig?: string): void;
  /** 查询实例对象字段：基本类型返回原值，对象/数组字段返回 `jobject` 句柄（配合 `getString`/`getBytes`/`getChars`/`getInts` 读取内容），未设置返回 `null` */
  getField(objRef: number | bigint, fieldName: string): unknown;
  /** 设置类静态字段（支持基本类型、string、Uint8Array(`[B`)、Uint16Array(`[C`)、Int32Array(`[I`)、BigInt64Array(`[J`)、jobject 句柄及可选 JNI 签名 `sig`） */
  setStaticField(className: string, fieldName: string, value: unknown, sig?: string): void;
  /** 查询已设置的类静态字段：基本类型返回原值，对象/数组字段返回 `jobject` 句柄（配合 `getString`/`getBytes`/`getChars`/`getInts` 读取内容），未设置返回 `null` */
  getStaticField(className: string, fieldName: string): unknown;
  /** 开启/关闭 FindClass 严格存在性校验（开启且已加载 DEX 时，非系统类不存在返回 NULL 并抛出 ClassNotFoundException） */
  setStrictFindClass(enabled: boolean): void;
  /** 按 FieldID 反查所属类名、字段名、签名与是否静态（ID 仅在当前进程内有效；未知返回 `null`；支持在 Hook 回调内调用） */
  describeField(fieldId: number | bigint): JniFieldInfo | null;
  /** 列出本次运行内已 intern 的全部字段（含实例与静态字段） */
  listFields(): JniFieldInfo[];
  /** 按 MethodID 反查所属类名、方法名、签名与是否静态（ID 仅在当前进程内有效；未知返回 `null`；支持在 Hook 回调内调用） */
  describeMethod(methodId: number | bigint): JniMethodInfo | null;
  /** 列出本次运行内已 intern 的全部方法 */
  listMethods(): JniMethodInfo[];
  /** 按 `jobject` / `jclass` 句柄反查真实类名与对象类型（支持在 Hook 回调内调用；未知返回 `null`） */
  describeObject(ref: number | bigint): JniObjectInfo | null;
  /** 结构化 JNI 事件追踪与实时订阅（默认关闭，零开销，无需硬编码虚表槽位） */
  readonly trace: JniTraceNamespace;
  pushLocalFrame(): void;
  popLocalFrame(keepRef?: number | bigint): number;
  withLocalFrame<T>(fn: () => T): T;
  objectCount(): number;
}

interface MemNamespace {
  alloc(size: number): number;
  free(addr: number | bigint): boolean;
  heapUsed(): number;
  readBytes(addr: number | bigint, len: number): Uint8Array;
  writeBytes(addr: number | bigint, bytes: Uint8Array): void;
  readCString(addr: number | bigint, maxLen?: number): string;
  writeCString(addr: number | bigint, str: string): number;
  readU32(addr: number | bigint): number;
  writeU32(addr: number | bigint, value: number): void;
  readU64(addr: number | bigint): bigint;
  writeU64(addr: number | bigint, value: number | bigint): void;
  scan(start: number | bigint, len: number, pattern: string): number[];
  patch(addr: number | bigint, bytes: Uint8Array): number;
  nop(addr: number | bigint, count?: number): number;
  ret(addr: number | bigint, retval?: number | bigint): number;
}

interface VirtualNicConfig {
  name?: string;
  ipv4?: string;
  netmask?: string;
  gateway?: string;
  mac?: string;
  ipv6?: string;
}

interface NetOptions {
  enabled?: boolean;
  capture?: boolean;
  allowHosts?: string[];
  nic?: VirtualNicConfig;
}

interface CapturedPacket {
  fd: number;
  dir: "send" | "recv";
  peer: string;
  len: number;
  hex: string;
  text: string;
}

interface PacketHookEvent {
  fd: number;
  peer: string;
  data: Uint8Array;
  text: string;
}

interface NetNamespace {
  enable(options?: boolean | NetOptions): void;
  disable(): void;
  setNic(nic: VirtualNicConfig): void;
  nic(): Required<Omit<VirtualNicConfig, "netmask">>;
  packets(): CapturedPacket[];
  clearPackets(): void;
  onSend(callback: ((pkt: PacketHookEvent) => Uint8Array | string | void) | null): void;
  onRecv(callback: ((pkt: PacketHookEvent) => Uint8Array | string | void) | null): void;
}

interface VfsNamespace {
  setProperty(key: string, value: string): void;
  writeFile(guestPath: string, data: string | Uint8Array): void;
  readFile(guestPath: string): Uint8Array | null;
  mountOverlay(guestDir: string, hostDir: string): void;
  setTime(unixSecs: number): void;
  useRealClock(enabled?: boolean): void;
  setDevice(presetOrConfig: DevicePresetName | DeviceProfileConfig): void;
  deviceProfile(): Required<Omit<DeviceProfileConfig, "preset">>;
}

interface TraceNamespace {
  start(options?: TraceOptions): void;
  stop(): TraceStats;
}

interface DiagReport {
  missingFiles: Record<string, number>;
  missingProperties: Record<string, number>;
  missingSyscalls: Record<string, number>;
  missingJni: Record<string, number>;
  missingHle: Record<string, number>;
  missingJniFields: Record<string, number>;
  missingAuxv: Record<string, number>;
}

interface DiagNamespace {
  enable(): void;
  disable(): void;
  clear(): void;
  report(): DiagReport;
  generatePatchJs(): string;
}

interface ApkHandle {
  readonly packageName: string | null;
  readonly abi: string;
  readonly libs: string[];
  readonly assets: string[];
  readonly signatureSize: number;
  loadLib(libName: string, opts?: LoadOptions): ModuleHandle;
}

interface CrashReport {
  readonly reason: string;
  readonly pc: number;
  readonly pcHex: string;
  readonly pcLocation: string;
  readonly lr: number;
  readonly lrLocation: string;
  readonly sp: number;
  readonly fp: number;
  readonly disasm: Array<{ addr: string; word: string; asm: string; isPc: boolean }>;
  readonly backtrace: Array<{ index: number; addr: string; location: string }>;
  readonly breadcrumbs: string[];
  readonly formatted: string;
}

interface DexClassInfo {
  readonly name: string;
  readonly superClass: string | null;
  readonly interfaces: string[];
  readonly fields: Array<{ name: string; sig: string; isStatic: boolean }>;
  readonly methods: Array<{ name: string; sig: string; isDirect: boolean }>;
  readonly staticValues: Record<string, unknown>;
}

interface DexNamespace {
  classes(prefix?: string): string[];
  classInfo(className: string): DexClassInfo | null;
}

interface EmuHandle {
  load(path: string, opts?: LoadOptions): ModuleHandle;
  /** 加载单个 `.dex`、路径数组或包含 `classes*.dex` 的目录到轻量元数据索引并挂载到 VFS */
  loadDex(pathOrPaths: string | string[]): {
    classes: number;
    addedClasses: number;
    totalClasses: number;
    dexCount: number;
  };
  readonly dex: DexNamespace;
  loadApk(path: string): ApkHandle;
  jniOnLoad(mod: ModuleHandle): number | null;
  call(addr: number | bigint, ...args: Array<number | bigint>): number;
  stop(): void;
  lastCrash(): CrashReport | null;
  setLimits(limits?: { timeoutMs?: number; maxInstructions?: number }): void;
  readonly diag: DiagNamespace;
  readonly regs: RegsNamespace;
  readonly hook: HookNamespace;
  readonly jni: JniNamespace;
  readonly mem: MemNamespace;
  readonly vfs: VfsNamespace;
  readonly net: NetNamespace;
  readonly trace: TraceNamespace;
  snapshot(): number;
  restore(snapshotId: number): void;
}

declare namespace Emu {
  function create(options?: EmuOptions): EmuHandle;
}
