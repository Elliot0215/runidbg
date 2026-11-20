/// <reference path="./runidbg.d.ts" />
// Start RPC server:
//   cargo run --bin runidbg-cli -- serve examples/scripts/rpc_demo.js --listen 127.0.0.1:8080
// Test with curl:
//   curl http://127.0.0.1:8080/health
//   curl -X POST http://127.0.0.1:8080/call/version
//   curl -X POST http://127.0.0.1:8080/rpc -H 'Content-Type: application/json' \
//        -d '{"jsonrpc":"2.0","id":1,"method":"version","params":[]}'

const emu = Emu.create({ packageName: "com.example.rpcdemo" });
const mod = emu.load("samples/libstatic-webp.so");
const baseSnap = emu.snapshot();

rpc.exports = {
  version() {
    emu.restore(baseSnap);
    const v = mod.call("WebPGetDecoderVersion");
    return { version: v, hex: "0x" + v.toString(16) };
  },
  echo(msg) {
    return { echo: String(msg) };
  },
};
