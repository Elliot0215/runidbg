typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef unsigned long size_t;
#define NULL ((void *)0)

/* 外部 libc 符号：链接时保留为未定义符号，运行时由模拟器 DynamicLinker 劫持到原生 Rust HLE 跳板 */
extern void *malloc(size_t size);
extern void free(void *ptr);
extern void *memcpy(void *dst, const void *src, size_t n);
extern int snprintf(char *str, size_t size, const char *fmt, ...);

/* 精简版 Android JNI 结构体定义（偏移与官方 NDK jni.h 100% 一致） */
typedef int32_t jint;
typedef uint8_t jboolean;
typedef int8_t jbyte;
typedef int32_t jsize;
typedef void *jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jbyteArray;
typedef void *jmethodID;

#define JNI_VERSION_1_6 0x00010006

typedef struct {
    const char *name;
    const char *signature;
    void *fnPtr;
} JNINativeMethod;

typedef const struct JNIInvokeInterface_ *JavaVM;
typedef const struct JNINativeInterface_ *JNIEnv;

struct JNIInvokeInterface_ {
    void *reserved[3];
    jint (*DestroyJavaVM)(JavaVM *);
    jint (*AttachCurrentThread)(JavaVM *, JNIEnv **, void *);
    jint (*DetachCurrentThread)(JavaVM *);
    jint (*GetEnv)(JavaVM *, void **, jint);
    jint (*AttachCurrentThreadAsDaemon)(JavaVM *, JNIEnv **, void *);
};

/* 按官方 jni.h 槽位编号精确填充 JNINativeInterface_ */
struct JNINativeInterface_ {
    void *slot0_5[6];
    jclass (*FindClass)(JNIEnv *, const char *);                         /* slot 6 */
    void *slot7_30[24];
    jclass (*GetObjectClass)(JNIEnv *, jobject);                         /* slot 31 */
    void *slot32;
    jmethodID (*GetMethodID)(JNIEnv *, jclass, const char *, const char *); /* slot 33 */
    jobject (*CallObjectMethod)(JNIEnv *, jobject, jmethodID, ...);      /* slot 34 */
    void *slot35_166[132];
    jstring (*NewStringUTF)(JNIEnv *, const char *);                     /* slot 167 */
    jsize (*GetStringUTFLength)(JNIEnv *, jstring);                      /* slot 168 */
    const char *(*GetStringUTFChars)(JNIEnv *, jstring, jboolean *);     /* slot 169 */
    void (*ReleaseStringUTFChars)(JNIEnv *, jstring, const char *);      /* slot 170 */
    jsize (*GetArrayLength)(JNIEnv *, jobject);                          /* slot 171 */
    void *slot172_183[12];
    jbyte *(*GetByteArrayElements)(JNIEnv *, jbyteArray, jboolean *);    /* slot 184 */
    void *slot185_191[7];
    void (*ReleaseByteArrayElements)(JNIEnv *, jbyteArray, jbyte *, jint); /* slot 192 */
    void *slot193_214[22];
    jint (*RegisterNatives)(JNIEnv *, jclass, const JNINativeMethod *, jint); /* slot 215 */
};

/* ============================================================================
 * 1. .init_array 构造器：反混淆主密钥 + SVC #0 ptrace 反调试检测
 * ============================================================================ */
static uint8_t g_master_key[16];
static int g_antidebug_ok = 0;

static long raw_syscall4(long nr, long a0, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
    return x0;
}

__attribute__((constructor))
static void init_crypto_module(void) {
    static const uint8_t enc_key[16] = {
        0x19, 0x3b, 0x26, 0x71, 0x5c, 0x62, 0x0f, 0x44,
        0x2a, 0x1d, 0x77, 0x68, 0x33, 0x05, 0x4e, 0x51
    };
    for (int i = 0; i < 16; i++) {
        g_master_key[i] = enc_key[i] ^ (uint8_t)(0x5A + i * 3);
    }
    /* AArch64 SYS_ptrace = 117, PTRACE_TRACEME = 0 */
    long rc = raw_syscall4(117, 0, 0, 0, 0);
    g_antidebug_ok = (rc == 0) ? 1 : 0;
}

/* ============================================================================
 * 2. 标准 SHA-256 (FIPS 180-4) 与 HMAC-SHA256 (RFC 2104)
 * ============================================================================ */
static const uint32_t SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    size_t datalen;
} Sha256Ctx;

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(Sha256Ctx *ctx, const uint8_t block[64]) {
    uint32_t m[64];
    for (int i = 0; i < 16; i++) {
        m[i] = ((uint32_t)block[i * 4] << 24)
             | ((uint32_t)block[i * 4 + 1] << 16)
             | ((uint32_t)block[i * 4 + 2] << 8)
             | ((uint32_t)block[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + m[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;

        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(Sha256Ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256Ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(Sha256Ctx *ctx, uint8_t out[32]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;

    ctx->bitlen += (uint64_t)ctx->datalen * 8;
    for (int j = 0; j < 8; j++) {
        ctx->data[63 - j] = (uint8_t)((ctx->bitlen >> (j * 8)) & 0xFF);
    }
    sha256_transform(ctx, ctx->data);

    for (int j = 0; j < 8; j++) {
        out[j * 4]     = (uint8_t)((ctx->state[j] >> 24) & 0xFF);
        out[j * 4 + 1] = (uint8_t)((ctx->state[j] >> 16) & 0xFF);
        out[j * 4 + 2] = (uint8_t)((ctx->state[j] >> 8) & 0xFF);
        out[j * 4 + 3] = (uint8_t)(ctx->state[j] & 0xFF);
    }
}

static void hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *msg, size_t msg_len,
    uint8_t out[32]
) {
    uint8_t k_pad[64];
    for (int i = 0; i < 64; i++) k_pad[i] = 0;
    if (key_len > 64) {
        Sha256Ctx kc;
        sha256_init(&kc);
        sha256_update(&kc, key, key_len);
        sha256_final(&kc, k_pad);
    } else {
        memcpy(k_pad, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }

    uint8_t inner[32];
    Sha256Ctx ictx;
    sha256_init(&ictx);
    sha256_update(&ictx, ipad, 64);
    sha256_update(&ictx, msg, msg_len);
    sha256_final(&ictx, inner);

    Sha256Ctx octx;
    sha256_init(&octx);
    sha256_update(&octx, opad, 64);
    sha256_update(&octx, inner, 32);
    sha256_final(&octx, out);
}

/* ============================================================================
 * 3. JNI 动态注册本地方法：sign(Context, String, byte[]) -> String
 * ============================================================================ */
static jstring native_sign(
    JNIEnv *env, jclass cls, jobject ctx, jstring payload, jbyteArray salt
) {
    (void)cls;
    if (!g_antidebug_ok) {
        return (*env)->NewStringUTF(env, "ERR_DEBUGGER");
    }

    /* 通过 JNI 反射调用 ctx.getPackageName() */
    jclass ctx_cls = (*env)->GetObjectClass(env, ctx);
    jmethodID mid = (*env)->GetMethodID(env, ctx_cls, "getPackageName", "()Ljava/lang/String;");
    jstring pkg_jstr = (jstring)(*env)->CallObjectMethod(env, ctx, mid);

    const char *pkg_str = (*env)->GetStringUTFChars(env, pkg_jstr, NULL);
    jsize pkg_len = (*env)->GetStringUTFLength(env, pkg_jstr);

    const char *pay_str = (*env)->GetStringUTFChars(env, payload, NULL);
    jsize pay_len = (*env)->GetStringUTFLength(env, payload);

    jsize salt_len = (*env)->GetArrayLength(env, salt);
    jbyte *salt_bytes = (*env)->GetByteArrayElements(env, salt, NULL);

    /* 派生密钥 = master_key[0..16] || pkg_name */
    size_t key_len = 16 + (size_t)pkg_len;
    uint8_t *key_buf = (uint8_t *)malloc(key_len);
    memcpy(key_buf, g_master_key, 16);
    memcpy(key_buf + 16, pkg_str, (size_t)pkg_len);

    /* 待签名消息 = payload || salt */
    size_t msg_len = (size_t)pay_len + (size_t)salt_len;
    uint8_t *msg_buf = (uint8_t *)malloc(msg_len);
    memcpy(msg_buf, pay_str, (size_t)pay_len);
    memcpy(msg_buf + pay_len, salt_bytes, (size_t)salt_len);

    uint8_t digest[32];
    hmac_sha256(key_buf, key_len, msg_buf, msg_len, digest);

    char hex[65];
    for (int i = 0; i < 32; i++) {
        snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }
    hex[64] = '\0';

    free(key_buf);
    free(msg_buf);
    (*env)->ReleaseByteArrayElements(env, salt, salt_bytes, 2);
    (*env)->ReleaseStringUTFChars(env, payload, pay_str);
    (*env)->ReleaseStringUTFChars(env, pkg_jstr, pkg_str);

    return (*env)->NewStringUTF(env, hex);
}

/* ============================================================================
 * 4. JNI_OnLoad 导出入口
 * ============================================================================ */
__attribute__((visibility("default")))
jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    JNIEnv *env = NULL;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != 0 || env == NULL) {
        return -1;
    }

    jclass cls = (*env)->FindClass(env, "com/demo/CryptoSigner");
    if (!cls) {
        return -1;
    }

    static const JNINativeMethod methods[1] = {
        {
            "sign",
            "(Landroid/content/Context;Ljava/lang/String;[B)Ljava/lang/String;",
            (void *)native_sign
        }
    };
    if ((*env)->RegisterNatives(env, cls, methods, 1) != 0) {
        return -1;
    }

    return JNI_VERSION_1_6;
}
