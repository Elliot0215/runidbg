use std::collections::HashMap;

/// 统一的 Android ARM64 设备参数画像（自动同步到系统属性、`/proc/*`、`uname` 与 JNI 环境）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceProfile {
    pub brand: String,
    pub manufacturer: String,
    pub model: String,
    pub device: String,
    pub product: String,
    pub board: String,
    pub hardware: String,
    pub soc_platform: String,
    pub fingerprint: String,
    pub build_id: String,
    pub build_display: String,
    pub incremental: String,
    pub security_patch: String,
    pub android_release: String,
    pub sdk_int: u32,
    pub abi: String,
    pub abi_list: String,
    pub cpu_cores: u32,
    pub cpu_implementer: String,
    pub cpu_part: String,
    pub ram_total_kb: u64,
    pub kernel_release: String,
    pub kernel_version: String,
    pub screen_width: u32,
    pub screen_height: u32,
    pub screen_dpi: u32,
    pub locale: String,
    pub timezone: String,
    pub carrier_name: String,
    pub carrier_mcc_mnc: String,
    pub serial_no: String,
    pub android_id: String,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::pixel_5()
    }
}

impl DeviceProfile {
    /// Google Pixel 5 (redfin, Android 11 / API 30) —— 默认兼容模板
    pub fn pixel_5() -> Self {
        Self {
            brand: "google".into(),
            manufacturer: "Google".into(),
            model: "Pixel 5".into(),
            device: "redfin".into(),
            product: "redfin".into(),
            board: "redfin".into(),
            hardware: "qcom".into(),
            soc_platform: "lito".into(),
            fingerprint: "google/redfin/redfin:11/RQ3A.211001.001/7641976:user/release-keys".into(),
            build_id: "RQ3A.211001.001".into(),
            build_display: "RQ3A.211001.001".into(),
            incremental: "7641976".into(),
            security_patch: "2021-10-05".into(),
            android_release: "11".into(),
            sdk_int: 30,
            abi: "arm64-v8a".into(),
            abi_list: "arm64-v8a,armeabi-v7a,armeabi".into(),
            cpu_cores: 8,
            cpu_implementer: "0x51".into(),
            cpu_part: "0x805".into(),
            ram_total_kb: 8 * 1024 * 1024,
            kernel_release: "5.4.147-android12-9".into(),
            kernel_version: "#1 SMP PREEMPT".into(),
            screen_width: 1080,
            screen_height: 2340,
            screen_dpi: 440,
            locale: "en-US".into(),
            timezone: "America/Los_Angeles".into(),
            carrier_name: "T-Mobile".into(),
            carrier_mcc_mnc: "310260".into(),
            serial_no: "0A121FDD400123".into(),
            android_id: "9774d56d682e549c".into(),
        }
    }

    /// Google Pixel 8 Pro (husky, Android 14 / API 34)
    pub fn pixel_8_pro() -> Self {
        Self {
            brand: "google".into(),
            manufacturer: "Google".into(),
            model: "Pixel 8 Pro".into(),
            device: "husky".into(),
            product: "husky".into(),
            board: "husky".into(),
            hardware: "husky".into(),
            soc_platform: "zuma".into(),
            fingerprint: "google/husky/husky:14/AP2A.240805.005/12025142:user/release-keys".into(),
            build_id: "AP2A.240805.005".into(),
            build_display: "AP2A.240805.005".into(),
            incremental: "12025142".into(),
            security_patch: "2024-08-05".into(),
            android_release: "14".into(),
            sdk_int: 34,
            abi: "arm64-v8a".into(),
            abi_list: "arm64-v8a".into(),
            cpu_cores: 9,
            cpu_implementer: "0x41".into(),
            cpu_part: "0xd47".into(),
            ram_total_kb: 12 * 1024 * 1024,
            kernel_release: "6.1.75-android14-11-g8a1b2c3d4e5f".into(),
            kernel_version: "#1 SMP PREEMPT Thu Aug  1 10:00:00 UTC 2024".into(),
            screen_width: 1344,
            screen_height: 2992,
            screen_dpi: 489,
            locale: "en-US".into(),
            timezone: "America/New_York".into(),
            carrier_name: "T-Mobile".into(),
            carrier_mcc_mnc: "310260".into(),
            serial_no: "38141FDJH00421".into(),
            android_id: "a1b2c3d4e5f60718".into(),
        }
    }

    /// Samsung Galaxy S24 Ultra (SM-S928B / e3q, Android 14 / API 34)
    pub fn samsung_s24_ultra() -> Self {
        Self {
            brand: "samsung".into(),
            manufacturer: "samsung".into(),
            model: "SM-S928B".into(),
            device: "e3q".into(),
            product: "e3qxxx".into(),
            board: "pineapple".into(),
            hardware: "qcom".into(),
            soc_platform: "pineapple".into(),
            fingerprint:
                "samsung/e3qxxx/e3q:14/UP1A.231005.007/S928BXXS3AXFE:user/release-keys".into(),
            build_id: "UP1A.231005.007".into(),
            build_display: "UP1A.231005.007.S928BXXS3AXFE".into(),
            incremental: "S928BXXS3AXFE".into(),
            security_patch: "2024-07-01".into(),
            android_release: "14".into(),
            sdk_int: 34,
            abi: "arm64-v8a".into(),
            abi_list: "arm64-v8a".into(),
            cpu_cores: 8,
            cpu_implementer: "0x41".into(),
            cpu_part: "0xd82".into(),
            ram_total_kb: 12 * 1024 * 1024,
            kernel_release: "6.1.75-android14-11-29137810".into(),
            kernel_version: "#1 SMP PREEMPT Mon Jul  1 08:30:00 KST 2024".into(),
            screen_width: 1440,
            screen_height: 3120,
            screen_dpi: 505,
            locale: "en-GB".into(),
            timezone: "Europe/London".into(),
            carrier_name: "Vodafone".into(),
            carrier_mcc_mnc: "23415".into(),
            serial_no: "R5CX10ABCDE".into(),
            android_id: "4f8e2c1a9b7d6035".into(),
        }
    }

    /// Xiaomi 14 (23127PN0CC / houji, Android 14 / API 34)
    pub fn xiaomi_14() -> Self {
        Self {
            brand: "Xiaomi".into(),
            manufacturer: "Xiaomi".into(),
            model: "23127PN0CC".into(),
            device: "houji".into(),
            product: "houji".into(),
            board: "pineapple".into(),
            hardware: "qcom".into(),
            soc_platform: "pineapple".into(),
            fingerprint:
                "Xiaomi/houji/houji:14/UKQ1.230804.001/V816.0.38.0.UNCCNXM:user/release-keys".into(),
            build_id: "UKQ1.230804.001".into(),
            build_display: "UKQ1.230804.001".into(),
            incremental: "V816.0.38.0.UNCCNXM".into(),
            security_patch: "2024-06-01".into(),
            android_release: "14".into(),
            sdk_int: 34,
            abi: "arm64-v8a".into(),
            abi_list: "arm64-v8a,armeabi-v7a,armeabi".into(),
            cpu_cores: 8,
            cpu_implementer: "0x41".into(),
            cpu_part: "0xd82".into(),
            ram_total_kb: 16 * 1024 * 1024,
            kernel_release: "6.1.57-android14-11-g2f4c8e9a1b0d".into(),
            kernel_version: "#1 SMP PREEMPT Wed Jun 12 14:22:10 CST 2024".into(),
            screen_width: 1200,
            screen_height: 2670,
            screen_dpi: 460,
            locale: "zh-CN".into(),
            timezone: "Asia/Shanghai".into(),
            carrier_name: "China Mobile".into(),
            carrier_mcc_mnc: "46000".into(),
            serial_no: "8a4f21c9".into(),
            android_id: "c7d8e9f012345678".into(),
        }
    }

    /// 按预设名称创建设备画像（支持 `pixel5`、`pixel8pro`、`s24ultra`、`xiaomi14`）
    pub fn from_preset(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "default" | "pixel5" | "pixel_5" | "redfin" => Some(Self::pixel_5()),
            "pixel8pro" | "pixel_8_pro" | "husky" => Some(Self::pixel_8_pro()),
            "s24ultra" | "s24_ultra" | "samsung_s24_ultra" | "e3q" => {
                Some(Self::samsung_s24_ultra())
            }
            "xiaomi14" | "xiaomi_14" | "houji" => Some(Self::xiaomi_14()),
            _ => None,
        }
    }

    /// 将当前设备画像导出为完整的 Android 系统属性表
    pub fn to_properties(&self) -> HashMap<String, String> {
        let mut p = HashMap::new();
        p.insert("ro.product.brand".into(), self.brand.clone());
        p.insert("ro.product.manufacturer".into(), self.manufacturer.clone());
        p.insert("ro.product.model".into(), self.model.clone());
        p.insert("ro.product.device".into(), self.device.clone());
        p.insert("ro.product.name".into(), self.product.clone());
        p.insert("ro.product.board".into(), self.board.clone());
        p.insert("ro.product.cpu.abi".into(), self.abi.clone());
        p.insert("ro.product.cpu.abilist".into(), self.abi_list.clone());
        p.insert("ro.product.cpu.abilist64".into(), self.abi.clone());
        p.insert("ro.hardware".into(), self.hardware.clone());
        p.insert("ro.board.platform".into(), self.soc_platform.clone());
        p.insert("ro.build.fingerprint".into(), self.fingerprint.clone());
        p.insert("ro.build.id".into(), self.build_id.clone());
        p.insert("ro.build.display.id".into(), self.build_display.clone());
        p.insert("ro.build.version.release".into(), self.android_release.clone());
        p.insert("ro.build.version.sdk".into(), self.sdk_int.to_string());
        p.insert("ro.build.version.incremental".into(), self.incremental.clone());
        p.insert(
            "ro.build.version.security_patch".into(),
            self.security_patch.clone(),
        );
        p.insert("ro.build.tags".into(), "release-keys".into());
        p.insert("ro.build.type".into(), "user".into());
        p.insert("ro.debuggable".into(), "0".into());
        p.insert("ro.secure".into(), "1".into());
        p.insert("ro.boot.verifiedbootstate".into(), "green".into());
        p.insert("ro.boot.flash.locked".into(), "1".into());
        p.insert("ro.serialno".into(), self.serial_no.clone());
        p.insert("ro.boot.serialno".into(), self.serial_no.clone());
        p.insert("persist.sys.locale".into(), self.locale.clone());
        p.insert("persist.sys.timezone".into(), self.timezone.clone());
        p.insert("gsm.operator.alpha".into(), self.carrier_name.clone());
        p.insert(
            "gsm.sim.operator.numeric".into(),
            self.carrier_mcc_mnc.clone(),
        );
        p.insert("ro.sf.lcd_density".into(), self.screen_dpi.to_string());
        p
    }

    /// 合成 `/proc/cpuinfo` 内容
    pub fn render_proc_cpuinfo(&self) -> String {
        let mut out = String::new();
        let cores = self.cpu_cores.max(1);
        for i in 0..cores {
            out.push_str(&format!(
                "processor\t: {i}\n\
                 BogoMIPS\t: 38.40\n\
                 Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp\n\
                 CPU implementer\t: {}\n\
                 CPU architecture: 8\n\
                 CPU variant\t: 0x1\n\
                 CPU part\t: {}\n\
                 CPU revision\t: 0\n\n",
                self.cpu_implementer, self.cpu_part
            ));
        }
        out.push_str(&format!(
            "Hardware\t: Qualcomm Technologies, Inc {}\n",
            self.soc_platform
        ));
        out
    }

    /// 合成 `/proc/meminfo` 内容
    pub fn render_proc_meminfo(&self) -> String {
        let total = self.ram_total_kb.max(1024 * 1024);
        let free = total / 4;
        let avail = (total * 3) / 5;
        format!(
            "MemTotal:       {total:>8} kB\n\
             MemFree:        {free:>8} kB\n\
             MemAvailable:   {avail:>8} kB\n\
             Buffers:          131072 kB\n\
             Cached:          2097152 kB\n\
             SwapTotal:       2097152 kB\n\
             SwapFree:        2097152 kB\n"
        )
    }

    /// 合成 `/proc/version` 内容
    pub fn render_proc_version(&self) -> String {
        format!(
            "Linux version {} (build-user@build-host) (Android clang 17.0.2) {}\n",
            self.kernel_release, self.kernel_version
        )
    }

    /// 合成 `/sys/devices/system/cpu/online` 与 `possible` 内容
    pub fn render_cpu_online(&self) -> String {
        let max_idx = self.cpu_cores.saturating_sub(1);
        format!("0-{max_idx}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::DeviceProfile;

    #[test]
    fn test_device_presets_and_rendering() {
        let p8 = DeviceProfile::from_preset("pixel8pro").expect("pixel8pro preset");
        assert_eq!(p8.sdk_int, 34);
        assert_eq!(p8.model, "Pixel 8 Pro");
        let props = p8.to_properties();
        assert_eq!(props.get("ro.product.model").map(String::as_str), Some("Pixel 8 Pro"));
        assert_eq!(props.get("ro.build.version.sdk").map(String::as_str), Some("34"));
        assert!(p8.render_proc_cpuinfo().contains("processor\t: 8"));
        assert!(p8.render_proc_meminfo().contains("MemTotal:"));
        assert!(p8.render_proc_version().contains("6.1.75"));
        assert_eq!(p8.render_cpu_online(), "0-8\n");

        assert!(DeviceProfile::from_preset("s24ultra").is_some());
        assert!(DeviceProfile::from_preset("xiaomi14").is_some());
        assert!(DeviceProfile::from_preset("nonexistent").is_none());
    }
}
