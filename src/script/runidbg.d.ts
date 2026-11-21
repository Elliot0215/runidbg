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
  attach(addr: number | bigint, callbacks: AttachCallbacks): HookHandle;
  replace(addr: number | bigint, fn: (ctx: CpuContext) => number | bigint | boolean | void): HookHandle;
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

interface ModuleHandle {
  readonly name: string;
  readonly base: number;
  readonly size: number;
  symbol(name: string): number | null;
  exports(): string[];
  call(symOrAddr: string | number | bigint, ...args: Array<number | bigint>): number;
}

interface JniNamespace {
  readonly envPtr: number;
  hook(className: string, methods: Record<string, (...args: any[]) => any>): void;
  onUnhandled(callback: (info: UnhandledJniInfo) => any): void;
  registeredNatives(): RegisteredNativeInfo[];
  callNative(className: string, methodName: string, args?: Array<number | bigint>): number;
  findClass(className: string): number;
  newString(value: string): number;
  newByteArray(bytes: Uint8Array): number;
  newObject(className: string, fields?: Record<string, unknown>): number;
  newStringArray(items: string[]): number;
  getStringArray(ref: number | bigint): Array<string | null> | null;
  newObjectArray(refs: Array<number | bigint>): number;
  getObjectArray(ref: number | bigint): number[] | null;
  getString(ref: number | bigint): string | null;
  getBytes(ref: number | bigint): Uint8Array | null;
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
  loadLib(libName: string): ModuleHandle;
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

interface EmuHandle {
  load(path: string): ModuleHandle;
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
