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

type EmuBackendKind = "unicorn" | "dynarmic" | "kvm" | "hypervisor" | "hyper";

interface EmuOptions {
  /**
   * 底层 CPU 执行后端（默认 `"unicorn"`）：
   * - `"unicorn"`: 支持完整仿真 + Trace + GDB + 原生 Hook
   * - `"dynarmic"` / `"kvm"`（Linux 默认编译） / `"hypervisor"`（`"hyper"`，macOS 默认编译）: 仅限仿真模式
   */
  backend?: EmuBackendKind;
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
  /** 本次调用是否命中了用户通过 `hook`/`hookField`/`hookMethod` 注册的 JS Hook */
  readonly handled: boolean;
  /** 命中的 Hook 唯一 ID（对应 `listHooks()[i].id`）；未命中 Hook 时为 `null` */
  readonly hookId: number | null;
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

interface JniRegisteredHookInfo {
  readonly id: number;
  readonly kind: "field" | "method" | "any";
  readonly className: string;
  readonly name: string;
  readonly sig: string | null;
  readonly hits: number;
}

interface JniNamespace {
  readonly envPtr: number;
  /**
   * 拦截指定类（或接口/父类）的 JNI 方法或字段读取（支持运行时子类自动回退到声明接口/父类）。
   * - 带 `(` 的键（如 `"g()Lcas/c0;"`）自动注册为**方法专属 + 精确签名**；
   * - 带 `:` 的键（如 `"g:Ljava/lang/String;"` / `"field:g"`）自动注册为**字段专属**；
   * - 纯名称键注册到兼容通用表（建议存在字段/方法同名冲突时直接使用 `hookField` / `hookMethod`）。
   * - 优先级：精确签名专属 Hook > 无签名专属 Hook > 声明类专属 Hook > 通用 Hook > 内置模型 > `onUnhandled`。
   */
  hook(className: string, methods: Record<string, (...args: any[]) => any>): void;
  /** 显式注册**字段专属** Hook（支持 `"g"` 或 `"g:[C"`，绝不劫持同名方法） */
  hookField(className: string, fields: Record<string, (...args: any[]) => any>): void;
  /** 显式注册**方法专属** Hook（支持 `"g"` 或 `"g()Lcas/c0;"` 精确重载签名，绝不劫持同名字段） */
  hookMethod(className: string, methods: Record<string, (...args: any[]) => any>): void;
  /** 列出全部已注册的 JNI Hook（含类别 `field`/`method`/`any` 与签名，便于排查命中问题） */
  listHooks(): JniRegisteredHookInfo[];
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
  newByteArray(bytes: Uint8Array | number[]): number;
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
  /** 读取 `[C` (`jcharArray`, UTF-16) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getChars(ref: number | bigint): Uint16Array | null;
  /** 读取 `[I` (`jintArray`) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getInts(ref: number | bigint): Int32Array | null;
  /** 读取 `[J` (`jlongArray`) 内容（TypedArray 视图，支持在 Hook 回调内重入） */
  getLongs(ref: number | bigint): BigInt64Array | null;
  /** 读取 `[B` (`jbyteArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getByteArray(ref: number | bigint): number[];
  /** 读取 `[I` (`jintArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getIntArray(ref: number | bigint): number[];
  /** 读取 `[J` (`jlongArray`) 为普通 `number[]`（无效/非数组句柄返回 `[]`，支持在 Hook 回调内重入） */
  getLongArray(ref: number | bigint): number[];
  /** 读取 `[C` (`jcharArray`, UTF-16) 为 JS 字符串（无效/非数组句柄返回 `""`，支持在 Hook 回调内重入） */
  getCharArray(ref: number | bigint): string;
  /** 设置实例对象字段（支持基本类型、string、TypedArray、jobject 句柄及可选 JNI 签名 `sig`；支持在 Hook 回调内重入） */
  setField(objRef: number | bigint, fieldName: string, value: unknown, sig?: string): void;
  /** 查询实例对象字段：基本类型返回原值，对象/数组字段返回 `jobject` 句柄，未设置返回 `null`；支持在 Hook 回调内重入 */
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

interface TapeCheckpointInfo {
  readonly index: number;
  readonly label: string;
  readonly timestampMs: number;
  readonly sourceBackend: string;
  readonly insnCount: number;
  readonly isDelta: boolean;
  readonly storedPages: number;
  readonly zeroedPages: number;
  readonly removedPages: number;
  readonly compressedBytes: number;
  readonly uncompressedBytes: number;
  readonly modules: string[];
}

interface TapeTimelineInfo {
  readonly startInsn: number;
  readonly endInsn: number;
  readonly keyframeInterval: number;
  readonly eventCount: number;
  readonly clockEvents: number;
  readonly jniEvents: number;
  readonly hookEvents: number;
  readonly hostFileCount: number;
  readonly bookmarks: Array<{ insn: number; label: string }>;
}

interface TapeSummary {
  readonly version: number;
  readonly fileSize: number;
  readonly checkpoints: TapeCheckpointInfo[];
  readonly timeline: TapeTimelineInfo | null;
}

interface RecordOptions {
  /** 自动插入增量关键帧的指令间隔（默认 100000） */
  keyframeInterval?: number;
  /** 最大录制指令数（0 表示不限） */
  maxInsns?: number;
  /** 是否捕获外部 JNI 回调实现离线脱离 JS 重放（默认 true） */
  captureJni?: boolean;
}

interface RecordNamespace {
  start(opts?: RecordOptions): void;
  bookmark(label: string): number;
  insns(): number;
  isRecording(): boolean;
  stop(path: string): TapeSummary;
}

interface TimeTravelStopInfo {
  readonly reason: "step" | "breakpoint" | "watchpoint" | "log_begin" | "log_end";
  readonly insn: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly location: string;
  readonly watchAddr?: number;
  readonly watchAddrHex?: string;
  readonly watchAccessAddr?: number;
  readonly watchAccessAddrHex?: string;
  readonly watchSize?: number;
  readonly watchKind?: "write" | "read" | "access";
  readonly watchActualKind?: "write" | "read";
  readonly watchValue?: number;
  readonly watchValueHex?: string;
}

interface WatchHitInfo {
  readonly insn: number;
  readonly pc: number;
  readonly pcHex: string;
  readonly location: string;
  readonly addr: number;
  readonly addrHex: string;
  readonly size: number;
  readonly kind: "write" | "read" | "access";
  readonly actualKind: "write" | "read";
  readonly value: number;
  readonly valueHex: string;
}

interface TimeTravelHandle {
  readonly startInsn: number;
  readonly totalInsns: number;
  readonly keyframes: number;
  readonly bookmarks: Array<{ insn: number; label: string }>;
  readonly modules: Array<{ name: string; base: number; baseHex: string; size: number }>;
  currentInsn(): number;
  isLiveForked(): boolean;
  close(): boolean;
  seekInsn(insn: number): TimeTravelStopInfo;
  seekBookmark(label: string): TimeTravelStopInfo;
  stepForward(n?: number): TimeTravelStopInfo;
  stepBack(n?: number): TimeTravelStopInfo;
  findPrevWrite(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findPrevRead(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findPrevAccess(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextWrite(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextRead(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  findNextAccess(addr: number | bigint | string, len?: number): WatchHitInfo | null;
  regs(): Record<string, number>;
  readonly mem: {
    readBytes(addr: number | bigint | string, len: number): Uint8Array;
    readU32(addr: number | bigint | string): number;
    readU64(addr: number | bigint | string): bigint;
    readCString(addr: number | bigint | string, maxLen?: number): string;
  };
  verifyDeterminism(): { verifiedKeyframes: number };
}

interface LoadTapeOptions {
  /** 恢复到哪个目标后端（支持跨后端接力，如从 Dynarmic/Hyper/KVM 磁带切入 `"unicorn"` 做 Trace/GDB） */
  backend?: EmuBackendKind;
  /** 指定检查点序号、书签名或 `"latest"`（默认最新检查点） */
  checkpoint?: number | string;
  /** 额外追加的依赖库搜索路径（会保留并与磁带原路径合并） */
  searchPaths?: string[];
  device?: DevicePresetName | DeviceProfileConfig;
  realClock?: boolean;
  net?: boolean | NetOptions;
}

interface EmuHandle {
  /** 当前实例使用的规范化 CPU 执行后端名 */
  readonly backend: "unicorn" | "dynarmic" | "kvm" | "hypervisor";
  /** 是否支持 Trace 模式（仅 `"unicorn"` 为 true） */
  readonly supportsTrace: boolean;
  /** 是否支持 GDB 调试模式（仅 `"unicorn"` 为 true） */
  readonly supportsGdb: boolean;
  /** 若由 `Emu.loadTape()` 恢复，记录所加载的检查点摘要 */
  readonly tapeCheckpoint: TapeCheckpointInfo | null;
  load(path: string, opts?: LoadOptions): ModuleHandle;
  /** 列出当前已加载的全部 ELF 模块（含从 `.rtape` 磁带恢复的模块） */
  modules(): ModuleHandle[];
  /** 按模块名查找已加载模块（适用于从 `.rtape` 磁带恢复后直接取回符号表） */
  module(name: string): ModuleHandle | null;
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
  /** 将当前完整状态保存为 `.rtape` 磁盘磁带（首个全量稀疏基线检查点） */
  saveTape(path: string, label?: string): TapeSummary;
  /** 向已有 `.rtape` 磁带追加 4KB 脏页增量检查点（书签） */
  checkpointTape(path: string, label?: string): TapeCheckpointInfo;
  /** 将当前实例快进或倒带至 `.rtape` 磁带中的指定检查点（序号 / 书签名 / `"latest"`） */
  seekTape(path: string, checkpoint?: number | string): TapeCheckpointInfo;
  /** 二期指令级时间旅行录制控制器（仅 Unicorn 后端可用） */
  readonly record: RecordNamespace;
}

declare namespace Emu {
  /** 返回当前构建在当前操作系统上默认编译启用的执行后端列表 */
  function backends(): Array<"unicorn" | "dynarmic" | "kvm" | "hypervisor">;
  function create(options?: EmuOptions): EmuHandle;
  /** 从 `.rtape` 磁盘磁带直接拉起实例（支持跨进程秒启与跨后端接力） */
  function loadTape(path: string, options?: LoadTapeOptions): EmuHandle;
  /** 读取 `.rtape` 磁带文件摘要与全部检查点时间线 */
  function inspectTape(path: string): TapeSummary;
  /** 打开含二期时间旅行事件日志的 `.rtape` 磁带，进行指令级 seek / 单步回退 / 反向内存观察点追踪 */
  function openTimeTravel(path: string): TimeTravelHandle;
}
