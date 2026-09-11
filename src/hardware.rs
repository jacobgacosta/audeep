use chrono::{DateTime, Utc};
use serde::Serialize;
use sysinfo::{Disks, Networks, System};

#[derive(Debug, Clone, Serialize)]
pub struct CpuInfo {
    pub brand: String,
    pub vendor: String,
    pub cores_physical: Option<usize>,
    pub cores_logical: usize,
    pub frequency_mhz: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryInfo {
    pub total_gb: f64,
    pub used_gb: f64,
    pub available_gb: f64,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_gb: f64,
    pub available_gb: f64,
    pub is_removable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetInterface {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareReport {
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub uptime_secs: u64,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub network_interfaces: Vec<NetInterface>,
}

fn bytes_to_gb(bytes: u64) -> f64 {
    // 1 GB = 1024^3
    (bytes as f64) / (1024.0 * 1024.0 * 1024.0)
}

pub fn collect_hardware_info() -> HardwareReport {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let uptime_secs = System::uptime();

    // CPU
    let cpus = sys.cpus();
    let first = cpus.first();
    let cpu = CpuInfo {
        brand: first.map(|c| c.brand().to_string()).unwrap_or_else(|| "unknown".to_string()),
        vendor: first.map(|c| c.vendor_id().to_string()).unwrap_or_else(|| "unknown".to_string()),
        cores_physical: sys.physical_core_count(),
        cores_logical: cpus.len(),
        frequency_mhz: first.map(|c| c.frequency()).unwrap_or(0),
    };

    // Memory
    let memory = MemoryInfo {
        total_bytes: sys.total_memory(),
        used_bytes: sys.used_memory(),
        total_gb: bytes_to_gb(sys.total_memory()),
        used_gb: bytes_to_gb(sys.used_memory()),
        available_gb: bytes_to_gb(sys.available_memory()),
    };

    // Disks - sysinfo 0.30 uses Disks struct
    let disks = Disks::new_with_refreshed_list()
        .iter()
        .map(|d| DiskInfo {
            name: d.name().to_string_lossy().to_string(),
            mount_point: d.mount_point().to_string_lossy().to_string(),
            file_system: d.file_system().to_string_lossy().to_string(),
            total_gb: bytes_to_gb(d.total_space()),
            available_gb: bytes_to_gb(d.available_space()),
            is_removable: d.is_removable(),
        })
        .collect();

    // Network interfaces - sysinfo 0.30 only exposes MAC + traffic, no IP
    // IPs se dejan vacías aquí; se pueden complementar con crate `if-addrs` o `local-ip-address` si se requiere
    let networks = Networks::new_with_refreshed_list();
    let network_interfaces = networks
        .iter()
        .map(|(name, data)| {
            let mac = format!("{}", data.mac_address());
            NetInterface {
                name: name.clone(),
                mac,
                ips: Vec::new(),
            }
        })
        .collect();

    HardwareReport {
        timestamp: Utc::now(),
        hostname,
        os_name,
        os_version,
        kernel_version,
        uptime_secs,
        cpu,
        memory,
        disks,
        network_interfaces,
    }
}
