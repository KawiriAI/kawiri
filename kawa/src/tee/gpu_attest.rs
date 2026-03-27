//! NVIDIA GPU Confidential Computing attestation via direct RM ioctls.
//!
//! Talks to `/dev/nvidiactl` + `/dev/nvidia0` using the open-source RM ioctl
//! interface (MIT-licensed headers from NVIDIA/open-gpu-kernel-modules 580.x).
//! No dlopen, no closed-source code, no libnvidia-ml.so.1.
//!
//! # Protocol
//!
//! 1. Open `/dev/nvidiactl` (control fd) and `/dev/nvidia0` (GPU fd)
//! 2. RM_ALLOC root client (class 0x41)
//! 3. RM_ALLOC device (class 0x80) under root
//! 4. RM_ALLOC subdevice (class 0x2080) under device
//! 5. RM_ALLOC conf_compute (class 0xcb33) under subdevice
//! 6. RM_CONTROL GET_GPU_CERTIFICATE → DER cert chains
//! 7. RM_CONTROL GET_GPU_ATTESTATION_REPORT → SPDM report
//! 8. RM_CONTROL SET_GPUS_STATE → mark GPU ready for CUDA
//! 9. RM_FREE all objects in reverse order
//!
//! # ioctl dispatch
//!
//! All RM operations go through `NV_ESC_IOCTL_XFER_CMD` (ioctl nr 211).
//! The RM escape codes (0x29/0x2A/0x2B) are NOT kernel ioctl numbers —
//! they are passed as `nv_ioctl_xfer_t.cmd` through the single transfer ioctl.
//!
//! # ABI references (all MIT-licensed, NVIDIA/open-gpu-kernel-modules 580.x)
//!
//! - `kernel-open/common/inc/nv-ioctl-numbers.h` — NV_ESC_IOCTL_XFER_CMD = 211
//! - `kernel-open/common/inc/nv-ioctl.h` — nv_ioctl_xfer_t struct
//! - `src/nvidia/arch/nvalloc/unix/include/nv_escape.h` — RM escape codes
//! - `src/common/sdk/nvidia/inc/nvos.h` — NVOS64/NVOS54/NVOS00 structs
//! - `src/common/sdk/nvidia/inc/ctrl/ctrlcb33.h` — CC control commands
//! - `src/common/sdk/nvidia/inc/class/cl0080.h` — NV0080_ALLOC_PARAMETERS
//! - `src/common/sdk/nvidia/inc/class/cl2080.h` — NV2080_ALLOC_PARAMETERS
//! - `src/common/sdk/nvidia/inc/class/clcb33.h` — NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use tracing::{debug, info, warn};

// ── ioctl constants ──────────────────────────────────────────────────

/// Pre-computed ioctl request number: _IOWR('F', 211, NvIoctlXfer).
/// 211 = NV_ESC_IOCTL_XFER_CMD (kernel-open/common/inc/nv-ioctl-numbers.h).
/// = (3 << 30) | (sizeof(NvIoctlXfer) << 16) | ('F' << 8) | 211
/// = (3 << 30) | (16 << 16) | (0x46 << 8) | 0xD3
/// = 0xC01046D3
const XFER_IOCTL_NR: libc::Ioctl = 0xC010_46D3u32 as i32 as libc::Ioctl;

/// RM escape codes — passed as nv_ioctl_xfer_t.cmd, NOT as ioctl numbers.
/// Source: src/nvidia/arch/nvalloc/unix/include/nv_escape.h
const NV_ESC_RM_FREE: u32 = 0x29;
const NV_ESC_RM_CONTROL: u32 = 0x2A;
const NV_ESC_RM_ALLOC: u32 = 0x2B;

/// RM class IDs for object allocation.
const NV01_ROOT_CLIENT: u32 = 0x0041;
const NV01_DEVICE_0: u32 = 0x0080;
const NV20_SUBDEVICE_0: u32 = 0x2080;
const NV_CONFIDENTIAL_COMPUTE: u32 = 0xcb33;

/// CC control command IDs (from ctrlcb33.h).
const CMD_GET_CAPABILITIES: u32 = 0xcb33_0101;
const CMD_SET_GPUS_STATE: u32 = 0xcb33_0105;
const CMD_GET_GPU_CERTIFICATE: u32 = 0xcb33_0109;
const CMD_GET_GPU_ATTESTATION_REPORT: u32 = 0xcb33_010a;

/// Buffer sizes (from ctrlcb33.h).
const CERT_CHAIN_MAX: usize = 0x1000; // 4 KiB
const ATTEST_CERT_CHAIN_MAX: usize = 0x1400; // 5 KiB
const ATTEST_REPORT_MAX: usize = 0x2000; // 8 KiB
const CEC_REPORT_MAX: usize = 0x1000; // 4 KiB
const NONCE_SIZE: usize = 0x20; // 32 bytes

// ── ioctl transfer wrapper ───────────────────────────────────────────

/// Transfer wrapper for all RM operations.
/// Source: kernel-open/common/inc/nv-ioctl.h: nv_ioctl_xfer_t
///
/// ```c
/// typedef struct nv_ioctl_xfer {
///     NvU32   cmd;
///     NvU32   size;
///     NvP64   ptr  NV_ALIGN_BYTES(8);
/// } nv_ioctl_xfer_t;
/// ```
#[repr(C)]
struct NvIoctlXfer {
    cmd: u32,  // RM escape code (e.g. NV_ESC_RM_ALLOC)
    size: u32, // sizeof(params struct)
    ptr: u64,  // user-space pointer to params (NvP64 = void* on x86_64)
}

// ── #[repr(C)] RM structs ────────────────────────────────────────────

/// RM_ALLOC parameters.
/// Source: src/common/sdk/nvidia/inc/nvos.h: NVOS64_PARAMETERS
///
/// ```c
/// typedef struct {
///     NvHandle hRoot;
///     NvHandle hObjectParent;
///     NvHandle hObjectNew;
///     NvV32    hClass;
///     NvP64    pAllocParms NV_ALIGN_BYTES(8);
///     NvP64    pRightsRequested NV_ALIGN_BYTES(8);
///     NvU32    paramsSize;
///     NvU32    flags;
///     NvV32    status;
/// } NVOS64_PARAMETERS;
/// ```
#[repr(C)]
#[derive(Default)]
struct RmAlloc {
    h_root: u32,
    h_object_parent: u32,
    h_object_new: u32,
    h_class: u32,
    p_alloc_parms: u64,      // NvP64 — pointer to class-specific alloc params
    p_rights_requested: u64, // NvP64 — NULL for us (no access mask)
    params_size: u32,
    flags: u32,
    status: u32,
    // 4 bytes trailing padding (struct alignment = 8 due to u64 fields)
}

/// RM_CONTROL parameters.
/// Source: src/common/sdk/nvidia/inc/nvos.h: NVOS54_PARAMETERS
///
/// ```c
/// typedef struct {
///     NvHandle hClient;
///     NvHandle hObject;
///     NvV32    cmd;
///     NvU32    flags;
///     NvP64    params NV_ALIGN_BYTES(8);
///     NvU32    paramsSize;
///     NvV32    status;
/// } NVOS54_PARAMETERS;
/// ```
#[repr(C)]
#[derive(Default)]
struct RmControl {
    h_client: u32,
    h_object: u32,
    cmd: u32,
    flags: u32,
    params: u64, // NvP64 — pointer to command-specific params
    params_size: u32,
    status: u32,
}

/// RM_FREE parameters.
/// Source: src/common/sdk/nvidia/inc/nvos.h: NVOS00_PARAMETERS
///
/// ```c
/// typedef struct {
///     NvHandle  hRoot;
///     NvHandle  hObjectParent;
///     NvHandle  hObjectOld;
///     NvV32     status;
/// } NVOS00_PARAMETERS;
/// ```
#[repr(C)]
#[derive(Default)]
struct RmFree {
    h_root: u32,
    h_object_parent: u32,
    h_object_old: u32,
    status: u32,
}

/// Device allocation params.
/// Source: src/common/sdk/nvidia/inc/class/cl0080.h: NV0080_ALLOC_PARAMETERS
#[repr(C)]
#[derive(Default)]
struct DeviceAllocParams {
    device_id: u32,
    h_client_share: u32,
    h_target_client: u32,
    h_target_device: u32,
    flags: u32,
    // NV_DECLARE_ALIGNED(NvU64 ..., 8) — u64 in #[repr(C)] already 8-byte aligned
    va_space_size: u64,
    va_start_internal: u64,
    va_limit_internal: u64,
    va_mode: u32,
}

/// Subdevice allocation params.
/// Source: src/common/sdk/nvidia/inc/class/cl2080.h: NV2080_ALLOC_PARAMETERS
#[repr(C)]
#[derive(Default)]
struct SubdeviceAllocParams {
    sub_device_id: u32,
}

/// Conf compute allocation params.
/// Source: src/common/sdk/nvidia/inc/class/clcb33.h: NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS
#[repr(C)]
#[derive(Default)]
struct ConfComputeAllocParams {
    h_client: u32,
}

// ── CC control command param structs (from ctrlcb33.h) ───────────────

/// GET_CAPABILITIES response.
/// NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_GET_CAPABILITIES_PARAMS
#[repr(C)]
#[derive(Default)]
struct GetCapabilitiesParams {
    cpu_capability: u8,
    gpus_capability: u8,
    environment: u8,
    cc_feature: u8,
    dev_tools_mode: u8,
    multi_gpu_mode: u8,
}

/// SET_GPUS_STATE request.
/// NV_CONF_COMPUTE_CTRL_CMD_SYSTEM_SET_GPUS_STATE_PARAMS
///
/// NvBool = NvU8 (1 byte), NOT u32.
#[repr(C)]
#[derive(Default)]
struct SetGpusStateParams {
    b_accept_client_request: u8, // NvBool: 0 = NV_FALSE, 1 = NV_TRUE
}

/// GET_GPU_CERTIFICATE response.
/// NV_CONF_COMPUTE_CTRL_CMD_GET_GPU_CERTIFICATE_PARAMS
#[repr(C)]
struct GetCertificateParams {
    h_sub_device: u32,
    cert_chain: [u8; CERT_CHAIN_MAX],
    cert_chain_size: u32,
    attestation_cert_chain: [u8; ATTEST_CERT_CHAIN_MAX],
    attestation_cert_chain_size: u32,
}

impl Default for GetCertificateParams {
    fn default() -> Self {
        Self {
            h_sub_device: 0,
            cert_chain: [0u8; CERT_CHAIN_MAX],
            cert_chain_size: 0,
            attestation_cert_chain: [0u8; ATTEST_CERT_CHAIN_MAX],
            attestation_cert_chain_size: 0,
        }
    }
}

/// GET_GPU_ATTESTATION_REPORT request/response.
/// NV_CONF_COMPUTE_CTRL_CMD_GET_GPU_ATTESTATION_REPORT_PARAMS
///
/// isCecAttestationReportPresent is NvBool (u8), which affects layout:
/// the cecAttestationReport array starts 1 byte after, not 4.
#[repr(C)]
struct GetAttestationReportParams {
    h_sub_device: u32,
    nonce: [u8; NONCE_SIZE],
    attestation_report: [u8; ATTEST_REPORT_MAX],
    attestation_report_size: u32,
    is_cec_present: u8, // NvBool — 1 byte, NOT u32
    cec_attestation_report: [u8; CEC_REPORT_MAX],
    cec_attestation_report_size: u32,
}

impl Default for GetAttestationReportParams {
    fn default() -> Self {
        Self {
            h_sub_device: 0,
            nonce: [0u8; NONCE_SIZE],
            attestation_report: [0u8; ATTEST_REPORT_MAX],
            attestation_report_size: 0,
            is_cec_present: 0,
            cec_attestation_report: [0u8; CEC_REPORT_MAX],
            cec_attestation_report_size: 0,
        }
    }
}

// ── ioctl helper ─────────────────────────────────────────────────────

/// Issue an RM ioctl via NV_ESC_IOCTL_XFER_CMD.
///
/// Wraps the params in nv_ioctl_xfer_t and sends it through the single
/// kernel transfer ioctl (nr 211). The kernel copies params from xfer.ptr,
/// dispatches based on xfer.cmd, and copies results back.
///
/// # Safety
/// `params` must be a valid `#[repr(C)]` struct matching the RM escape `esc`.
unsafe fn rm_ioctl<T>(fd: i32, esc: u32, params: &mut T) -> Result<(), GpuAttestError> {
    let mut xfer = NvIoctlXfer {
        cmd: esc,
        size: std::mem::size_of::<T>() as u32,
        ptr: params as *mut T as u64,
    };
    let ret = libc::ioctl(fd, XFER_IOCTL_NR, &mut xfer as *mut NvIoctlXfer);
    if ret < 0 {
        return Err(GpuAttestError::Ioctl(esc, std::io::Error::last_os_error()));
    }
    Ok(())
}

// ── Public types ─────────────────────────────────────────────────────

/// GPU CC attestation evidence — certificates + SPDM report.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuEvidence {
    /// GPU index (0, 1, ...).
    pub gpu_index: u32,
    /// DER-encoded GPU certificate chain (base64).
    pub cert_chain: String,
    /// DER-encoded attestation certificate chain (base64).
    pub attestation_cert_chain: String,
    /// SPDM attestation report (base64).
    pub attestation_report: String,
    /// CEC attestation report if present (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cec_attestation_report: Option<String>,
    /// Nonce used for report generation (hex).
    pub nonce: String,
    /// CC capabilities from GET_CAPABILITIES.
    pub capabilities: GpuCcCapabilities,
}

/// CC capability flags from GET_CAPABILITIES.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuCcCapabilities {
    pub cpu_capability: u8,
    pub gpus_capability: u8,
    pub environment: u8,
    pub cc_feature: u8,
    pub dev_tools_mode: u8,
    pub multi_gpu_mode: u8,
}

#[derive(Debug, thiserror::Error)]
pub enum GpuAttestError {
    #[error("failed to open {0}: {1}")]
    Open(&'static str, std::io::Error),
    #[error("RM ioctl 0x{0:02x} failed: {1}")]
    Ioctl(u32, std::io::Error),
    #[error("RM call 0x{cmd:08x} returned status 0x{status:08x}")]
    RmStatus { cmd: u32, status: u32 },
}

// ── RM session management ────────────────────────────────────────────

/// Handles to allocated RM objects — freed on drop.
struct RmSession {
    fd_ctl: File,
    #[allow(dead_code)] // kept open so the kernel associates this process with the GPU
    fd_gpu: File,
    h_client: u32,
    h_device: u32,
    h_subdevice: u32,
    h_cc: u32,
}

impl RmSession {
    /// Open device files and allocate the full RM object hierarchy.
    fn open(gpu_index: u32) -> Result<Self, GpuAttestError> {
        let fd_ctl = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/nvidiactl")
            .map_err(|e| GpuAttestError::Open("/dev/nvidiactl", e))?;

        let gpu_path = format!("/dev/nvidia{gpu_index}");
        let fd_gpu = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&gpu_path)
            .map_err(|e| GpuAttestError::Open("/dev/nvidiaX", e))?;

        let fd = fd_ctl.as_raw_fd();

        // 1. Allocate root client (class 0x41, no parent)
        let h_client = Self::rm_alloc_client(fd)?;
        debug!(h_client, "RM root client allocated");

        // 2. Allocate device under root
        let h_device = match Self::rm_alloc_device(fd, h_client, gpu_index) {
            Ok(h) => h,
            Err(e) => {
                Self::rm_free_one(fd, h_client, h_client, h_client);
                return Err(e);
            }
        };
        debug!(h_device, "RM device allocated");

        // 3. Allocate subdevice under device
        let h_subdevice = match Self::rm_alloc_subdevice(fd, h_client, h_device) {
            Ok(h) => h,
            Err(e) => {
                Self::rm_free_one(fd, h_client, h_client, h_device);
                Self::rm_free_one(fd, h_client, h_client, h_client);
                return Err(e);
            }
        };
        debug!(h_subdevice, "RM subdevice allocated");

        // 4. Allocate conf_compute under root client (system-level resource,
        //    NOT per-GPU — parent must be RmClientResource, not subdevice)
        let h_cc = match Self::rm_alloc_conf_compute(fd, h_client) {
            Ok(h) => h,
            Err(e) => {
                Self::rm_free_one(fd, h_client, h_device, h_subdevice);
                Self::rm_free_one(fd, h_client, h_client, h_device);
                Self::rm_free_one(fd, h_client, h_client, h_client);
                return Err(e);
            }
        };
        debug!(h_cc, "RM conf_compute allocated");

        Ok(Self {
            fd_ctl,
            fd_gpu,
            h_client,
            h_device,
            h_subdevice,
            h_cc,
        })
    }

    fn ctl_fd(&self) -> i32 {
        self.fd_ctl.as_raw_fd()
    }

    // ── Allocation helpers ───────────────────────────────────────────

    fn rm_alloc_client(fd: i32) -> Result<u32, GpuAttestError> {
        let mut params = RmAlloc {
            h_root: 0,
            h_object_parent: 0,
            h_object_new: 0, // 0 = kernel generates handle
            h_class: NV01_ROOT_CLIENT,
            p_alloc_parms: 0, // NULL — no class-specific params for root client
            p_rights_requested: 0,
            params_size: 0,
            flags: 0,
            status: 0,
        };
        // SAFETY: RmAlloc matches NVOS64_PARAMETERS layout (verified by tests below).
        unsafe { rm_ioctl(fd, NV_ESC_RM_ALLOC, &mut params)? };
        if params.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: NV01_ROOT_CLIENT,
                status: params.status,
            });
        }
        Ok(params.h_object_new)
    }

    fn rm_alloc_device(fd: i32, h_client: u32, gpu_id: u32) -> Result<u32, GpuAttestError> {
        let mut dev_params = DeviceAllocParams {
            device_id: gpu_id,
            ..Default::default()
        };
        let mut params = RmAlloc {
            h_root: h_client,
            h_object_parent: h_client,
            h_object_new: 0,
            h_class: NV01_DEVICE_0,
            p_alloc_parms: &mut dev_params as *mut _ as u64,
            p_rights_requested: 0,
            params_size: std::mem::size_of::<DeviceAllocParams>() as u32,
            flags: 0,
            status: 0,
        };
        unsafe { rm_ioctl(fd, NV_ESC_RM_ALLOC, &mut params)? };
        if params.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: NV01_DEVICE_0,
                status: params.status,
            });
        }
        Ok(params.h_object_new)
    }

    fn rm_alloc_subdevice(fd: i32, h_client: u32, h_device: u32) -> Result<u32, GpuAttestError> {
        let mut sub_params = SubdeviceAllocParams { sub_device_id: 0 };
        let mut params = RmAlloc {
            h_root: h_client,
            h_object_parent: h_device,
            h_object_new: 0,
            h_class: NV20_SUBDEVICE_0,
            p_alloc_parms: &mut sub_params as *mut _ as u64,
            p_rights_requested: 0,
            params_size: std::mem::size_of::<SubdeviceAllocParams>() as u32,
            flags: 0,
            status: 0,
        };
        unsafe { rm_ioctl(fd, NV_ESC_RM_ALLOC, &mut params)? };
        if params.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: NV20_SUBDEVICE_0,
                status: params.status,
            });
        }
        Ok(params.h_object_new)
    }

    fn rm_alloc_conf_compute(fd: i32, h_client: u32) -> Result<u32, GpuAttestError> {
        let mut cc_params = ConfComputeAllocParams { h_client };
        let mut params = RmAlloc {
            h_root: h_client,
            h_object_parent: h_client, // system-level: parent is root client
            h_object_new: 0,
            h_class: NV_CONFIDENTIAL_COMPUTE,
            p_alloc_parms: &mut cc_params as *mut _ as u64,
            p_rights_requested: 0,
            params_size: std::mem::size_of::<ConfComputeAllocParams>() as u32,
            flags: 0,
            status: 0,
        };
        unsafe { rm_ioctl(fd, NV_ESC_RM_ALLOC, &mut params)? };
        if params.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: NV_CONFIDENTIAL_COMPUTE,
                status: params.status,
            });
        }
        Ok(params.h_object_new)
    }

    fn rm_free_one(fd: i32, h_root: u32, h_parent: u32, h_object: u32) {
        let mut params = RmFree {
            h_root,
            h_object_parent: h_parent,
            h_object_old: h_object,
            status: 0,
        };
        // Best-effort cleanup — ignore errors during teardown.
        unsafe {
            let _ = rm_ioctl(fd, NV_ESC_RM_FREE, &mut params);
        }
    }

    // ── CC control commands ──────────────────────────────────────────

    fn get_capabilities(&self) -> Result<GetCapabilitiesParams, GpuAttestError> {
        let mut caps = GetCapabilitiesParams::default();
        let mut ctrl = RmControl {
            h_client: self.h_client,
            h_object: self.h_cc,
            cmd: CMD_GET_CAPABILITIES,
            flags: 0,
            params: &mut caps as *mut _ as u64,
            params_size: std::mem::size_of::<GetCapabilitiesParams>() as u32,
            status: 0,
        };
        unsafe { rm_ioctl(self.ctl_fd(), NV_ESC_RM_CONTROL, &mut ctrl)? };
        if ctrl.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: CMD_GET_CAPABILITIES,
                status: ctrl.status,
            });
        }
        Ok(caps)
    }

    fn get_certificate(&self) -> Result<GetCertificateParams, GpuAttestError> {
        let mut cert = GetCertificateParams {
            h_sub_device: self.h_subdevice,
            ..Default::default()
        };
        let mut ctrl = RmControl {
            h_client: self.h_client,
            h_object: self.h_cc,
            cmd: CMD_GET_GPU_CERTIFICATE,
            flags: 0,
            params: &mut cert as *mut _ as u64,
            params_size: std::mem::size_of::<GetCertificateParams>() as u32,
            status: 0,
        };
        unsafe { rm_ioctl(self.ctl_fd(), NV_ESC_RM_CONTROL, &mut ctrl)? };
        if ctrl.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: CMD_GET_GPU_CERTIFICATE,
                status: ctrl.status,
            });
        }
        Ok(cert)
    }

    fn get_attestation_report(
        &self,
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<GetAttestationReportParams, GpuAttestError> {
        let mut report = GetAttestationReportParams {
            h_sub_device: self.h_subdevice,
            nonce: *nonce,
            ..Default::default()
        };
        let mut ctrl = RmControl {
            h_client: self.h_client,
            h_object: self.h_cc,
            cmd: CMD_GET_GPU_ATTESTATION_REPORT,
            flags: 0,
            params: &mut report as *mut _ as u64,
            params_size: std::mem::size_of::<GetAttestationReportParams>() as u32,
            status: 0,
        };
        unsafe { rm_ioctl(self.ctl_fd(), NV_ESC_RM_CONTROL, &mut ctrl)? };
        if ctrl.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: CMD_GET_GPU_ATTESTATION_REPORT,
                status: ctrl.status,
            });
        }
        Ok(report)
    }

    fn set_ready_state(&self) -> Result<(), GpuAttestError> {
        let mut state = SetGpusStateParams {
            b_accept_client_request: 1, // NV_TRUE
        };
        let mut ctrl = RmControl {
            h_client: self.h_client,
            h_object: self.h_cc,
            cmd: CMD_SET_GPUS_STATE,
            flags: 0,
            params: &mut state as *mut _ as u64,
            params_size: std::mem::size_of::<SetGpusStateParams>() as u32,
            status: 0,
        };
        unsafe { rm_ioctl(self.ctl_fd(), NV_ESC_RM_CONTROL, &mut ctrl)? };
        if ctrl.status != 0 {
            return Err(GpuAttestError::RmStatus {
                cmd: CMD_SET_GPUS_STATE,
                status: ctrl.status,
            });
        }
        Ok(())
    }
}

impl Drop for RmSession {
    fn drop(&mut self) {
        let fd = self.fd_ctl.as_raw_fd();
        // Free in reverse allocation order
        Self::rm_free_one(fd, self.h_client, self.h_client, self.h_cc);
        Self::rm_free_one(fd, self.h_client, self.h_device, self.h_subdevice);
        Self::rm_free_one(fd, self.h_client, self.h_client, self.h_device);
        Self::rm_free_one(fd, self.h_client, self.h_client, self.h_client);
        debug!("RM session cleaned up");
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// NV_ERR_INVALID_OBJECT_PARENT — returned when GPU CC subsystem
/// isn't ready yet (SPDM handshake in progress after driver load).
const NV_ERR_INVALID_OBJECT_PARENT: u32 = 0x36;

/// Retry RM session open with backoff for transient GPU init errors.
///
/// After nvidia.ko loads, the GPU's SPDM secure channel and CC subsystem
/// take several seconds to initialize (key exchange with GPU TEE firmware).
/// Two transient errors can occur:
/// - EIO on /dev/nvidia0 open: GPU device not ready yet (PCI probe/SPDM)
/// - 0x36 on conf_compute alloc: CC subsystem not initialized yet
fn retry_rm_session_open(gpu_index: u32) -> Result<RmSession, GpuAttestError> {
    const MAX_RETRIES: u32 = 30;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

    let mut last_err = None;
    for attempt in 1..=MAX_RETRIES {
        match RmSession::open(gpu_index) {
            Ok(session) => {
                if attempt > 1 {
                    info!(gpu_index, attempt, "GPU CC subsystem ready");
                }
                return Ok(session);
            }
            Err(GpuAttestError::RmStatus { cmd, status })
                if cmd == NV_CONFIDENTIAL_COMPUTE && status == NV_ERR_INVALID_OBJECT_PARENT =>
            {
                info!(
                    gpu_index,
                    attempt,
                    "conf_compute not ready (0x36), retrying in {}s",
                    RETRY_DELAY.as_secs()
                );
                last_err = Some(GpuAttestError::RmStatus { cmd, status });
                std::thread::sleep(RETRY_DELAY);
            }
            Err(GpuAttestError::Open(path, ref io_err))
                if io_err.raw_os_error() == Some(libc::EIO) =>
            {
                info!(
                    gpu_index,
                    attempt,
                    "GPU device not ready (EIO), retrying in {}s",
                    RETRY_DELAY.as_secs()
                );
                last_err = Some(GpuAttestError::Open(
                    path,
                    std::io::Error::from_raw_os_error(libc::EIO),
                ));
                std::thread::sleep(RETRY_DELAY);
            }
            Err(e) => return Err(e),
        }
    }

    Err(last_err.unwrap())
}

/// Collect GPU CC attestation evidence for a single GPU.
///
/// Opens an RM session, retrieves certificates and SPDM attestation report,
/// then sets the GPU ready state so CUDA workloads can proceed.
///
/// The GPU CC subsystem (conf_compute) may not be ready immediately after
/// the nvidia driver loads — the SPDM handshake with the GPU TEE takes time.
/// Retries RM session open on NV_ERR_INVALID_OBJECT_PARENT (0x36) which
/// indicates the CC subsystem isn't initialized yet.
pub fn collect_gpu_evidence(
    gpu_index: u32,
    nonce: &[u8; 32],
) -> Result<GpuEvidence, GpuAttestError> {
    info!(gpu_index, "collecting GPU CC attestation evidence");

    let session = retry_rm_session_open(gpu_index)?;

    // Query capabilities first to verify CC is active
    let caps = session.get_capabilities()?;
    info!(
        gpu_index,
        cc_feature = caps.cc_feature,
        environment = caps.environment,
        "GPU CC capabilities"
    );

    // Get certificate chains
    let cert = session.get_certificate()?;
    // Clamp sizes to buffer max to prevent OOB if kernel returns garbage
    let cert_chain_len = (cert.cert_chain_size as usize).min(CERT_CHAIN_MAX);
    let attest_cert_len = (cert.attestation_cert_chain_size as usize).min(ATTEST_CERT_CHAIN_MAX);
    info!(
        gpu_index,
        cert_chain_bytes = cert_chain_len,
        attest_cert_bytes = attest_cert_len,
        "GPU certificates retrieved"
    );

    // Get attestation report with caller's nonce
    let report = session.get_attestation_report(nonce)?;
    let report_len = (report.attestation_report_size as usize).min(ATTEST_REPORT_MAX);
    let cec_present = report.is_cec_present != 0;
    let cec_len = (report.cec_attestation_report_size as usize).min(CEC_REPORT_MAX);
    info!(
        gpu_index,
        report_bytes = report_len,
        cec_present,
        cec_bytes = cec_len,
        "GPU attestation report retrieved"
    );

    // Set ready state — unlocks GPU for CUDA after attestation
    session.set_ready_state()?;
    info!(gpu_index, "GPU ready state set");

    // CRITICAL: Do NOT drop the RmSession. Freeing the conf_compute RM object
    // revokes the GPU ready state (confComputeDestruct sets state=NV_FALSE).
    // We must keep the RM handles and /dev/nvidia* fds alive for the lifetime
    // of the kawa process so CUDA workloads can use the GPU.
    std::mem::forget(session);

    Ok(GpuEvidence {
        gpu_index,
        cert_chain: BASE64.encode(&cert.cert_chain[..cert_chain_len]),
        attestation_cert_chain: BASE64.encode(&cert.attestation_cert_chain[..attest_cert_len]),
        attestation_report: BASE64.encode(&report.attestation_report[..report_len]),
        cec_attestation_report: if cec_present {
            Some(BASE64.encode(&report.cec_attestation_report[..cec_len]))
        } else {
            None
        },
        nonce: hex::encode(nonce),
        capabilities: GpuCcCapabilities {
            cpu_capability: caps.cpu_capability,
            gpus_capability: caps.gpus_capability,
            environment: caps.environment,
            cc_feature: caps.cc_feature,
            dev_tools_mode: caps.dev_tools_mode,
            multi_gpu_mode: caps.multi_gpu_mode,
        },
    })
    // session drops here → RM_FREE all objects
}

/// Detect available NVIDIA GPUs by probing /dev/nvidia0..N.
pub fn detect_gpus() -> Vec<u32> {
    let mut gpus = Vec::new();
    for i in 0..16 {
        let path = format!("/dev/nvidia{i}");
        if std::path::Path::new(&path).exists() {
            gpus.push(i);
        }
    }
    gpus
}

/// Collect attestation evidence from all detected GPUs.
///
/// Returns evidence for each GPU that successfully attests.
/// Logs warnings for GPUs that fail but continues with remaining GPUs.
pub fn collect_all_gpu_evidence(nonce: &[u8; 32]) -> Vec<GpuEvidence> {
    let gpu_ids = detect_gpus();
    if gpu_ids.is_empty() {
        debug!("no NVIDIA GPUs detected");
        return Vec::new();
    }

    info!(
        count = gpu_ids.len(),
        "detected NVIDIA GPUs, collecting CC evidence"
    );
    let mut evidence = Vec::new();

    for gpu_id in gpu_ids {
        match collect_gpu_evidence(gpu_id, nonce) {
            Ok(ev) => evidence.push(ev),
            Err(e) => {
                warn!(gpu_index = gpu_id, error = %e, "GPU attestation failed, skipping");
            }
        }
    }

    evidence
}

// ── Tests ────────────────────────────────────────────────────────────
//
// Struct layout tests are the most critical tests in this module.
// A single wrong offset means the ioctl silently reads/writes to the
// wrong memory, causing data corruption or kernel panics. These tests
// verify our #[repr(C)] structs match the NVIDIA C ABI exactly.

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // ── ioctl number ─────────────────────────────────────────────────

    #[test]
    fn xfer_ioctl_nr_matches_iowr_computation() {
        // _IOWR('F', 211, nv_ioctl_xfer_t)
        // direction=3 (RW), size=16, type='F'=0x46, nr=211=0xD3
        // Compute in u32 to avoid sign-extension differences between glibc (u64) and musl (i32)
        let computed: u32 =
            (3u32 << 30) | ((size_of::<NvIoctlXfer>() as u32) << 16) | (0x46 << 8) | 211;
        assert_eq!(XFER_IOCTL_NR, computed as i32 as libc::Ioctl);
        assert_eq!(computed, 0xC010_46D3u32);
    }

    // ── nv_ioctl_xfer_t layout ───────────────────────────────────────

    #[test]
    fn nv_ioctl_xfer_layout() {
        assert_eq!(size_of::<NvIoctlXfer>(), 16, "nv_ioctl_xfer_t size");
        assert_eq!(offset_of!(NvIoctlXfer, cmd), 0);
        assert_eq!(offset_of!(NvIoctlXfer, size), 4);
        assert_eq!(offset_of!(NvIoctlXfer, ptr), 8); // NvP64 aligned to 8
    }

    // ── NVOS64_PARAMETERS (RmAlloc) ──────────────────────────────────

    #[test]
    fn rm_alloc_layout_matches_nvos64() {
        // NVOS64_PARAMETERS: 48 bytes on x86_64
        assert_eq!(size_of::<RmAlloc>(), 48, "NVOS64_PARAMETERS size");
        assert_eq!(offset_of!(RmAlloc, h_root), 0);
        assert_eq!(offset_of!(RmAlloc, h_object_parent), 4);
        assert_eq!(offset_of!(RmAlloc, h_object_new), 8);
        assert_eq!(offset_of!(RmAlloc, h_class), 12);
        assert_eq!(offset_of!(RmAlloc, p_alloc_parms), 16); // NvP64, 8-byte aligned
        assert_eq!(offset_of!(RmAlloc, p_rights_requested), 24); // NvP64
        assert_eq!(offset_of!(RmAlloc, params_size), 32);
        assert_eq!(offset_of!(RmAlloc, flags), 36);
        assert_eq!(offset_of!(RmAlloc, status), 40);
    }

    // ── NVOS54_PARAMETERS (RmControl) ────────────────────────────────

    #[test]
    fn rm_control_layout_matches_nvos54() {
        // NVOS54_PARAMETERS: 32 bytes on x86_64
        assert_eq!(size_of::<RmControl>(), 32, "NVOS54_PARAMETERS size");
        assert_eq!(offset_of!(RmControl, h_client), 0);
        assert_eq!(offset_of!(RmControl, h_object), 4);
        assert_eq!(offset_of!(RmControl, cmd), 8);
        assert_eq!(offset_of!(RmControl, flags), 12);
        assert_eq!(offset_of!(RmControl, params), 16); // NvP64, 8-byte aligned
        assert_eq!(offset_of!(RmControl, params_size), 24);
        assert_eq!(offset_of!(RmControl, status), 28);
    }

    // ── NVOS00_PARAMETERS (RmFree) ───────────────────────────────────

    #[test]
    fn rm_free_layout_matches_nvos00() {
        // NVOS00_PARAMETERS: 16 bytes
        assert_eq!(size_of::<RmFree>(), 16, "NVOS00_PARAMETERS size");
        assert_eq!(offset_of!(RmFree, h_root), 0);
        assert_eq!(offset_of!(RmFree, h_object_parent), 4);
        assert_eq!(offset_of!(RmFree, h_object_old), 8);
        assert_eq!(offset_of!(RmFree, status), 12);
    }

    // ── NV0080_ALLOC_PARAMETERS (DeviceAllocParams) ──────────────────

    #[test]
    fn device_alloc_params_layout() {
        // 5 × u32 + pad(4) + 3 × u64 + u32 + pad(4) = 56 bytes
        assert_eq!(
            size_of::<DeviceAllocParams>(),
            56,
            "NV0080_ALLOC_PARAMETERS size"
        );
        assert_eq!(offset_of!(DeviceAllocParams, device_id), 0);
        assert_eq!(offset_of!(DeviceAllocParams, h_client_share), 4);
        assert_eq!(offset_of!(DeviceAllocParams, h_target_client), 8);
        assert_eq!(offset_of!(DeviceAllocParams, h_target_device), 12);
        assert_eq!(offset_of!(DeviceAllocParams, flags), 16);
        // 4 bytes padding here (u64 alignment)
        assert_eq!(offset_of!(DeviceAllocParams, va_space_size), 24);
        assert_eq!(offset_of!(DeviceAllocParams, va_start_internal), 32);
        assert_eq!(offset_of!(DeviceAllocParams, va_limit_internal), 40);
        assert_eq!(offset_of!(DeviceAllocParams, va_mode), 48);
    }

    // ── NV2080_ALLOC_PARAMETERS (SubdeviceAllocParams) ───────────────

    #[test]
    fn subdevice_alloc_params_layout() {
        assert_eq!(
            size_of::<SubdeviceAllocParams>(),
            4,
            "NV2080_ALLOC_PARAMETERS size"
        );
        assert_eq!(offset_of!(SubdeviceAllocParams, sub_device_id), 0);
    }

    // ── NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS ─────────────────────────

    #[test]
    fn conf_compute_alloc_params_layout() {
        assert_eq!(
            size_of::<ConfComputeAllocParams>(),
            4,
            "NV_CONFIDENTIAL_COMPUTE_ALLOC_PARAMS size"
        );
        assert_eq!(offset_of!(ConfComputeAllocParams, h_client), 0);
    }

    // ── CC control command param structs ──────────────────────────────

    #[test]
    fn get_capabilities_params_layout() {
        // 6 × u8 = 6 bytes, no padding (max alignment = 1)
        assert_eq!(size_of::<GetCapabilitiesParams>(), 6);
        assert_eq!(offset_of!(GetCapabilitiesParams, cpu_capability), 0);
        assert_eq!(offset_of!(GetCapabilitiesParams, gpus_capability), 1);
        assert_eq!(offset_of!(GetCapabilitiesParams, environment), 2);
        assert_eq!(offset_of!(GetCapabilitiesParams, cc_feature), 3);
        assert_eq!(offset_of!(GetCapabilitiesParams, dev_tools_mode), 4);
        assert_eq!(offset_of!(GetCapabilitiesParams, multi_gpu_mode), 5);
    }

    #[test]
    fn set_gpus_state_params_layout() {
        // NvBool = u8 → 1 byte
        assert_eq!(size_of::<SetGpusStateParams>(), 1);
        assert_eq!(offset_of!(SetGpusStateParams, b_accept_client_request), 0);
    }

    #[test]
    fn get_certificate_params_layout() {
        // h_sub_device(4) + cert_chain(0x1000) + cert_chain_size(4) +
        // attestation_cert_chain(0x1400) + attestation_cert_chain_size(4) = 9228
        let expected = 4 + CERT_CHAIN_MAX + 4 + ATTEST_CERT_CHAIN_MAX + 4;
        assert_eq!(size_of::<GetCertificateParams>(), expected);
        assert_eq!(offset_of!(GetCertificateParams, h_sub_device), 0);
        assert_eq!(offset_of!(GetCertificateParams, cert_chain), 4);
        assert_eq!(
            offset_of!(GetCertificateParams, cert_chain_size),
            4 + CERT_CHAIN_MAX
        );
        assert_eq!(
            offset_of!(GetCertificateParams, attestation_cert_chain),
            4 + CERT_CHAIN_MAX + 4
        );
        assert_eq!(
            offset_of!(GetCertificateParams, attestation_cert_chain_size),
            4 + CERT_CHAIN_MAX + 4 + ATTEST_CERT_CHAIN_MAX
        );
    }

    #[test]
    fn get_attestation_report_params_layout() {
        // Field offsets (NvBool = u8 = 1 byte, affects layout):
        //   h_sub_device:                  0         (4 bytes)
        //   nonce:                         4         (32 bytes)
        //   attestation_report:            36        (8192 bytes)
        //   attestation_report_size:       8228      (4 bytes)
        //   is_cec_present:                8232      (1 byte — NvBool)
        //   cec_attestation_report:        8233      (4096 bytes)
        //   cec_attestation_report_size:   12329 → aligned to 12332 (4 bytes)
        assert_eq!(offset_of!(GetAttestationReportParams, h_sub_device), 0);
        assert_eq!(offset_of!(GetAttestationReportParams, nonce), 4);
        assert_eq!(
            offset_of!(GetAttestationReportParams, attestation_report),
            4 + NONCE_SIZE
        );
        assert_eq!(
            offset_of!(GetAttestationReportParams, attestation_report_size),
            4 + NONCE_SIZE + ATTEST_REPORT_MAX
        );
        // NvBool is u8: 1 byte, right after attestation_report_size
        assert_eq!(
            offset_of!(GetAttestationReportParams, is_cec_present),
            4 + NONCE_SIZE + ATTEST_REPORT_MAX + 4
        );
        // u8 array starts 1 byte after is_cec_present (no alignment needed)
        assert_eq!(
            offset_of!(GetAttestationReportParams, cec_attestation_report),
            4 + NONCE_SIZE + ATTEST_REPORT_MAX + 4 + 1
        );
        // u32 after u8 array: may have padding for 4-byte alignment
        let cec_end = 4 + NONCE_SIZE + ATTEST_REPORT_MAX + 4 + 1 + CEC_REPORT_MAX;
        let aligned_cec_size_offset = (cec_end + 3) & !3; // round up to 4
        assert_eq!(
            offset_of!(GetAttestationReportParams, cec_attestation_report_size),
            aligned_cec_size_offset
        );
    }

    // ── Constant verification ────────────────────────────────────────

    #[test]
    fn escape_codes_match_header() {
        // nv_escape.h values
        assert_eq!(NV_ESC_RM_FREE, 0x29);
        assert_eq!(NV_ESC_RM_CONTROL, 0x2A);
        assert_eq!(NV_ESC_RM_ALLOC, 0x2B);
    }

    #[test]
    fn class_ids_match_header() {
        assert_eq!(NV01_ROOT_CLIENT, 0x0041);
        assert_eq!(NV01_DEVICE_0, 0x0080);
        assert_eq!(NV20_SUBDEVICE_0, 0x2080);
        assert_eq!(NV_CONFIDENTIAL_COMPUTE, 0xcb33);
    }

    #[test]
    fn cc_cmd_ids_match_ctrlcb33() {
        assert_eq!(CMD_GET_CAPABILITIES, 0xcb33_0101);
        assert_eq!(CMD_SET_GPUS_STATE, 0xcb33_0105);
        assert_eq!(CMD_GET_GPU_CERTIFICATE, 0xcb33_0109);
        assert_eq!(CMD_GET_GPU_ATTESTATION_REPORT, 0xcb33_010a);
    }

    #[test]
    fn buffer_sizes_match_ctrlcb33() {
        assert_eq!(CERT_CHAIN_MAX, 0x1000);
        assert_eq!(ATTEST_CERT_CHAIN_MAX, 0x1400);
        assert_eq!(ATTEST_REPORT_MAX, 0x2000);
        assert_eq!(CEC_REPORT_MAX, 0x1000);
        assert_eq!(NONCE_SIZE, 0x20);
    }

    // ── detect_gpus (works without GPU hardware) ─────────────────────

    #[test]
    fn detect_gpus_returns_empty_without_nvidia_devices() {
        // On machines without NVIDIA GPUs, /dev/nvidia0 doesn't exist.
        // This test documents that detect_gpus is safe to call anywhere.
        let gpus = detect_gpus();
        // Can't assert empty (CI might have GPUs), but can assert bounded
        assert!(gpus.len() <= 16);
        for &id in &gpus {
            assert!(id < 16);
        }
    }

    // ── GpuEvidence serialization ────────────────────────────────────

    #[test]
    fn gpu_evidence_json_serialization() {
        let evidence = GpuEvidence {
            gpu_index: 0,
            cert_chain: "AAAA".into(),
            attestation_cert_chain: "BBBB".into(),
            attestation_report: "CCCC".into(),
            cec_attestation_report: None,
            nonce: "ab".repeat(32),
            capabilities: GpuCcCapabilities {
                cpu_capability: 2,
                gpus_capability: 1,
                environment: 1,
                cc_feature: 1,
                dev_tools_mode: 0,
                multi_gpu_mode: 0,
            },
        };

        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["gpuIndex"], 0);
        assert_eq!(json["certChain"], "AAAA");
        assert_eq!(json["attestationCertChain"], "BBBB");
        assert_eq!(json["attestationReport"], "CCCC");
        // cecAttestationReport should be absent (skip_serializing_if = None)
        assert!(json.get("cecAttestationReport").is_none());
        assert_eq!(json["capabilities"]["ccFeature"], 1);
        assert_eq!(json["capabilities"]["cpuCapability"], 2);
    }

    #[test]
    fn gpu_evidence_json_with_cec() {
        let evidence = GpuEvidence {
            gpu_index: 1,
            cert_chain: "cert".into(),
            attestation_cert_chain: "attest".into(),
            attestation_report: "report".into(),
            cec_attestation_report: Some("cec_report".into()),
            nonce: "00".repeat(32),
            capabilities: GpuCcCapabilities {
                cpu_capability: 0,
                gpus_capability: 0,
                environment: 0,
                cc_feature: 0,
                dev_tools_mode: 0,
                multi_gpu_mode: 0,
            },
        };

        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["cecAttestationReport"], "cec_report");
        assert_eq!(json["gpuIndex"], 1);
    }

    // ── Bounds clamping ──────────────────────────────────────────────

    #[test]
    fn size_clamping_prevents_oob() {
        // Simulate kernel returning sizes larger than buffer max
        let oversized: u32 = 0xFFFF_FFFF;
        assert_eq!((oversized as usize).min(CERT_CHAIN_MAX), CERT_CHAIN_MAX);
        assert_eq!(
            (oversized as usize).min(ATTEST_CERT_CHAIN_MAX),
            ATTEST_CERT_CHAIN_MAX
        );
        assert_eq!(
            (oversized as usize).min(ATTEST_REPORT_MAX),
            ATTEST_REPORT_MAX
        );
        assert_eq!((oversized as usize).min(CEC_REPORT_MAX), CEC_REPORT_MAX);
    }
}
