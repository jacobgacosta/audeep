use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use sysinfo::{Components, Disks, Networks, System};

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
    /// IPs de la interfaz. `sysinfo` no las expone, se completan con `if-addrs`.
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SensorInfo {
    pub label: String,
    pub temperature_c: f32,
    pub max_c: f32,
    pub critical_c: Option<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HardwareReport {
    pub timestamp: DateTime<Utc>,
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub uptime_secs: u64,
    pub load_avg_one: f64,
    pub load_avg_five: f64,
    pub load_avg_fifteen: f64,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub network_interfaces: Vec<NetInterface>,
    pub sensors: Vec<SensorInfo>,
}

fn bytes_to_gb(bytes: u64) -> f64 {
    // 1 GB = 1024^3
    (bytes as f64) / (1024.0 * 1024.0 * 1024.0)
}

/// IPs por interfaz. `sysinfo 0.30` solo da MAC, así que las direcciones se
/// leen de `if-addrs` y se asocian por nombre de interfaz.
fn interface_ips() -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(list) = if_addrs::get_if_addrs() {
        for iface in list {
            let name = iface.name.clone();
            if let if_addrs::IfAddr::V4(v4) = iface.addr {
                if v4.ip.is_unspecified() {
                    continue;
                }
                map.entry(name).or_default().push(v4.ip.to_string());
            }
        }
    }
    map
}

pub fn collect_hardware_info() -> HardwareReport {
    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_string());
    let os_name = System::name().unwrap_or_else(|| "unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "unknown".to_string());
    let kernel_version = System::kernel_version().unwrap_or_else(|| "unknown".to_string());
    let uptime_secs = System::uptime();
    let load_avg = System::load_average();

    // CPU
    let cpus = sys.cpus();
    let first = cpus.first();
    let cpu = CpuInfo {
        brand: first
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        vendor: first
            .map(|c| c.vendor_id().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
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
        .map(|d| {
            let raw_name = d.name().to_string_lossy().to_string();
            let mount_point = d.mount_point().to_string_lossy().to_string();
            // En Windows el nombre del volumen suele venir vacío: usar el punto de montaje.
            let name = if raw_name.trim().is_empty() {
                mount_point.clone()
            } else {
                raw_name
            };
            DiskInfo {
                name,
                mount_point,
                file_system: d.file_system().to_string_lossy().to_string(),
                total_gb: bytes_to_gb(d.total_space()),
                available_gb: bytes_to_gb(d.available_space()),
                is_removable: d.is_removable(),
            }
        })
        .collect();

    // Network interfaces - sysinfo 0.30 only exposes MAC + traffic, no IP
    let ips_by_iface = interface_ips();
    let networks = Networks::new_with_refreshed_list();
    let network_interfaces = networks
        .iter()
        .map(|(name, data)| {
            let mac = format!("{}", data.mac_address());
            NetInterface {
                name: name.clone(),
                mac,
                ips: ips_by_iface.get(name).cloned().unwrap_or_default(),
            }
        })
        .collect();

    // Sensores (temperatura CPU etc, si disponible)
    let components = Components::new_with_refreshed_list();
    let sensors = components
        .iter()
        .map(|c| SensorInfo {
            label: c.label().to_string(),
            temperature_c: c.temperature(),
            max_c: c.max(),
            critical_c: c.critical(),
        })
        .collect();

    HardwareReport {
        timestamp: Utc::now(),
        hostname,
        os_name,
        os_version,
        kernel_version,
        uptime_secs,
        load_avg_one: load_avg.one,
        load_avg_five: load_avg.five,
        load_avg_fifteen: load_avg.fifteen,
        cpu,
        memory,
        disks,
        network_interfaces,
        sensors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gb_conversion_uses_1024_base() {
        assert!((bytes_to_gb(1024 * 1024 * 1024) - 1.0).abs() < 1e-9);
        assert!((bytes_to_gb(0) - 0.0).abs() < 1e-9);
    }

    #[test]
    fn hardware_report_is_populated() {
        let hw = collect_hardware_info();
        assert!(hw.cpu.cores_logical >= 1);
        assert!(hw.memory.total_bytes > 0);
        assert!(!hw.hostname.is_empty());
        // Los discos deben tener nombre no vacío (antes quedaba "" en Windows).
        for d in &hw.disks {
            assert!(
                !d.name.trim().is_empty(),
                "disco sin nombre ni punto de montaje"
            );
        }
    }
}
