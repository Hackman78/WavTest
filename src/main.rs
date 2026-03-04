use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use windows::core::{implement, IUnknown, Interface, Result, GUID, HRESULT, PCWSTR, PROPVARIANT};
use windows::Win32::Foundation::{CloseHandle, E_FAIL, HANDLE, WAIT_TIMEOUT};
use windows::Win32::Media::Audio::{
    eConsole, eRender, ActivateAudioInterfaceAsync, IAudioCaptureClient, IAudioClient,
    IActivateAudioInterfaceAsyncOperation, IActivateAudioInterfaceCompletionHandler,
    IActivateAudioInterfaceCompletionHandler_Impl, IMMDeviceEnumerator, MMDeviceEnumerator,
    AUDIOCLIENT_ACTIVATION_PARAMS, AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
    AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS, AUDCLNT_BUFFERFLAGS_SILENT, AUDCLNT_SHAREMODE_SHARED,
    AUDCLNT_STREAMFLAGS_LOOPBACK, PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE,
    WAVEFORMATEX, WAVEFORMATEXTENSIBLE,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_ALL, COINIT_MULTITHREADED,
};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, SetEvent, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};

const REFTIMES_PER_SEC: i64 = 10_000_000;
const ACTIVATION_TIMEOUT_MS: u32 = 5000;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);

// IAudioClient IID
const AUDIO_CLIENT_IID: GUID = GUID::from_u128(0x1cb9ad4c_dbfa_4c32_b178_c2f568a703b2);

fn print_usage() {
    eprintln!("Usage: wasabi.exe -p <pid> -f <filepath>");
    eprintln!();
    eprintln!("Captures audio from a specific process to a WAV file.");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p <pid>       Process ID to capture audio from");
    eprintln!("  -f <filepath>  Output WAV file path");
}

struct Args {
    pid: u32,
    filepath: String,
}

fn parse_args() -> Option<Args> {
    let args: Vec<String> = env::args().collect();
    let mut pid: Option<u32> = None;
    let mut filepath: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                if i + 1 < args.len() {
                    pid = args[i + 1].parse().ok();
                    i += 2;
                } else {
                    eprintln!("Error: -p requires a process ID");
                    return None;
                }
            }
            "-f" => {
                if i + 1 < args.len() {
                    filepath = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: -f requires a filepath");
                    return None;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    match (pid, filepath) {
        (Some(p), Some(f)) if p > 0 => Some(Args { pid: p, filepath: f }),
        (None, _) => {
            eprintln!("Error: -p <pid> is required");
            None
        }
        (_, None) => {
            eprintln!("Error: -f <filepath> is required");
            None
        }
        _ => {
            eprintln!("Error: Invalid arguments");
            None
        }
    }
}

/// Verify that a process with the given PID exists
fn verify_process_exists(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => {
                let _ = CloseHandle(h);
                true
            }
            Err(_) => false,
        }
    }
}

/// RAII wrapper for Windows event handle
struct EventHandle(HANDLE);

impl EventHandle {
    fn new() -> Result<Self> {
        unsafe {
            let handle = CreateEventW(None, true, false, PCWSTR::null())?;
            Ok(Self(handle))
        }
    }

    fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EventHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Completion handler for ActivateAudioInterfaceAsync
#[implement(IActivateAudioInterfaceCompletionHandler)]
struct ActivationHandler {
    event: HANDLE,
}

impl IActivateAudioInterfaceCompletionHandler_Impl for ActivationHandler_Impl {
    fn ActivateCompleted(
        &self,
        _activate_operation: Option<&IActivateAudioInterfaceAsyncOperation>,
    ) -> Result<()> {
        unsafe {
            let _ = SetEvent(self.event);
        }
        Ok(())
    }
}

/// Get the audio format from the default audio render endpoint
fn get_default_audio_format() -> Result<*mut WAVEFORMATEX> {
    unsafe {
        let enumerator: IMMDeviceEnumerator =
            CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)?;
        let device = enumerator.GetDefaultAudioEndpoint(eRender, eConsole)?;
        let audio_client: IAudioClient = device.Activate(CLSCTX_ALL, None)?;
        audio_client.GetMixFormat()
    }
}

/// Activate an audio client for capturing audio from a specific process
fn activate_audio_client_for_process(pid: u32) -> Result<IAudioClient> {
    unsafe {
        let event = EventHandle::new()?;

        // Set up process loopback parameters
        let loopback_params = AUDIOCLIENT_PROCESS_LOOPBACK_PARAMS {
            TargetProcessId: pid,
            ProcessLoopbackMode: PROCESS_LOOPBACK_MODE_INCLUDE_TARGET_PROCESS_TREE,
        };

        let mut activation_params = AUDIOCLIENT_ACTIVATION_PARAMS {
            ActivationType: AUDIOCLIENT_ACTIVATION_TYPE_PROCESS_LOOPBACK,
            Anonymous: std::mem::zeroed(),
        };
        activation_params.Anonymous.ProcessLoopbackParams = loopback_params;

        // Create PROPVARIANT with blob pointing to activation params
        let blob_data = windows_core::imp::BLOB {
            cbSize: size_of::<AUDIOCLIENT_ACTIVATION_PARAMS>() as u32,
            pBlobData: &activation_params as *const _ as *mut u8,
        };

        let mut raw_propvariant: windows_core::imp::PROPVARIANT = std::mem::zeroed();
        raw_propvariant.Anonymous.Anonymous.vt = 65; // VT_BLOB
        raw_propvariant.Anonymous.Anonymous.Anonymous.blob = blob_data;

        let prop_variant = PROPVARIANT::from_raw(raw_propvariant);

        // Create completion handler
        let handler = ActivationHandler {
            event: event.handle(),
        };
        let handler: IActivateAudioInterfaceCompletionHandler = handler.into();

        // Device ID for process loopback
        let device_id: Vec<u16> = "VAD\\Process_Loopback\0".encode_utf16().collect();

        // Activate audio interface
        let operation = ActivateAudioInterfaceAsync(
            PCWSTR(device_id.as_ptr()),
            &AUDIO_CLIENT_IID,
            Some(&prop_variant),
            &handler,
        )?;

        // Wait for activation with timeout
        let wait_result = WaitForSingleObject(event.handle(), ACTIVATION_TIMEOUT_MS);
        if wait_result == WAIT_TIMEOUT {
            return Err(windows::core::Error::new(
                E_FAIL,
                "Timeout waiting for audio activation",
            ));
        }

        // Get activation result
        let mut hr = HRESULT::default();
        let mut activated_interface: Option<IUnknown> = None;
        operation.GetActivateResult(&mut hr, &mut activated_interface)?;

        if hr.0 < 0 {
            return Err(windows::core::Error::new(
                hr,
                format!("Audio activation failed (0x{:08X})", hr.0),
            ));
        }

        let audio_client: IAudioClient = activated_interface
            .ok_or_else(|| windows::core::Error::new(E_FAIL, "Activation returned null"))?
            .cast()?;

        // Prevent PROPVARIANT from freeing our stack-allocated blob
        std::mem::forget(prop_variant);

        Ok(audio_client)
    }
}

/// Audio format information for WAV writing
struct WavFormat {
    channels: u16,
    sample_rate: u32,
    bits_per_sample: u16,
    bytes_per_sec: u32,
    block_align: u16,
}

/// Write a WAV header with placeholder zeros for the two size fields.
/// The caller must seek back and fix offsets 4 and 40 when done.
fn write_wav_header_placeholder(writer: &mut BufWriter<File>, format: &WavFormat) -> std::io::Result<()> {
    let fmt_chunk_size: u32 = 16;

    // RIFF header
    writer.write_all(b"RIFF")?;
    writer.write_all(&0u32.to_le_bytes())?; // offset 4: RIFF chunk size — fixed at end
    writer.write_all(b"WAVE")?;

    // fmt chunk
    writer.write_all(b"fmt ")?;
    writer.write_all(&fmt_chunk_size.to_le_bytes())?;
    writer.write_all(&1u16.to_le_bytes())?; // PCM format
    writer.write_all(&format.channels.to_le_bytes())?;
    writer.write_all(&format.sample_rate.to_le_bytes())?;
    writer.write_all(&format.bytes_per_sec.to_le_bytes())?;
    writer.write_all(&format.block_align.to_le_bytes())?;
    writer.write_all(&format.bits_per_sample.to_le_bytes())?;

    // data chunk header
    writer.write_all(b"data")?;
    writer.write_all(&0u32.to_le_bytes())?; // offset 40: data chunk size — fixed at end

    writer.flush()?;
    Ok(())
}

/// Convert 32-bit float audio samples to 16-bit PCM
fn convert_float_to_pcm16(float_data: &[u8]) -> Vec<u8> {
    let sample_count = float_data.len() / 4;
    let mut pcm_data = Vec::with_capacity(sample_count * 2);

    for i in 0..sample_count {
        let offset = i * 4;
        if offset + 4 <= float_data.len() {
            let float_bytes: [u8; 4] = [
                float_data[offset],
                float_data[offset + 1],
                float_data[offset + 2],
                float_data[offset + 3],
            ];
            let sample = f32::from_le_bytes(float_bytes);
            let clamped = sample.clamp(-1.0, 1.0);
            let pcm_sample = (clamped * 32767.0) as i16;
            pcm_data.extend_from_slice(&pcm_sample.to_le_bytes());
        }
    }

    pcm_data
}

fn main() {
    let args = match parse_args() {
        Some(a) => a,
        None => {
            print_usage();
            std::process::exit(1);
        }
    };

    // Verify process exists
    if !verify_process_exists(args.pid) {
        eprintln!("Process {} not found", args.pid);
        std::process::exit(1);
    }

    // Initialize COM
    unsafe {
        if let Err(e) = CoInitializeEx(None, COINIT_MULTITHREADED).ok() {
            eprintln!("COM init failed: {}", e);
            std::process::exit(1);
        }
    }

    // Set up signal handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let _ = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    });

    let result = capture_audio(args.pid, &args.filepath, running);

    // Cleanup
    unsafe {
        CoUninitialize();
    }

    if let Err(e) = result {
        eprintln!("{}", e);
        std::process::exit(1);
    }
}

fn capture_audio(pid: u32, output_file: &str, running: Arc<AtomicBool>) -> Result<()> {
    unsafe {
        // Activate audio client for target process
        let audio_client = activate_audio_client_for_process(pid)?;

        // Get format from default endpoint (process loopback doesn't support GetMixFormat)
        let mix_format_ptr = get_default_audio_format()?;
        let mix_format = &*mix_format_ptr;

        // Extract format info
        let n_channels = mix_format.nChannels;
        let n_samples_per_sec = mix_format.nSamplesPerSec;
        let w_format_tag = mix_format.wFormatTag;
        let n_block_align = mix_format.nBlockAlign;

        // Check if format is IEEE float
        let is_float = w_format_tag == 3
            || (w_format_tag == 0xFFFE && {
                let ext = &*(mix_format_ptr as *const WAVEFORMATEXTENSIBLE);
                ext.SubFormat.data1 == 3
            });

        // Initialize audio client
        audio_client.Initialize(
            AUDCLNT_SHAREMODE_SHARED,
            AUDCLNT_STREAMFLAGS_LOOPBACK,
            REFTIMES_PER_SEC,
            0,
            mix_format_ptr,
            None,
        )?;

        // Get capture client
        let capture_client: IAudioCaptureClient = audio_client.GetService()?;

        // Calculate sleep duration
        let buffer_frame_count = audio_client.GetBufferSize()?;
        let sleep_duration_ms = (buffer_frame_count as u64 * 500 / n_samples_per_sec as u64).max(5);
        let sleep_duration = Duration::from_millis(sleep_duration_ms);

        // Open output file and write placeholder WAV header immediately
        let wav_format = WavFormat {
            channels: n_channels,
            sample_rate: n_samples_per_sec,
            bits_per_sample: 16,
            bytes_per_sec: n_samples_per_sec * n_channels as u32 * 2,
            block_align: n_channels * 2,
        };

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(output_file)
            .map_err(|e| windows::core::Error::new(E_FAIL, format!("Failed to open file: {}", e)))?;

        let mut writer = BufWriter::new(file);

        write_wav_header_placeholder(&mut writer, &wav_format)
            .map_err(|e| windows::core::Error::new(E_FAIL, format!("Failed to write header: {}", e)))?;

        // Start capture
        audio_client.Start()?;

        let mut bytes_written: u64 = 0;
        let bytes_per_frame = n_block_align as usize;
        let mut last_flush = Instant::now();

        while running.load(Ordering::SeqCst) {
            let mut packet_length = match capture_client.GetNextPacketSize() {
                Ok(len) => len,
                Err(_) => break,
            };

            while packet_length > 0 && running.load(Ordering::SeqCst) {
                let mut data_ptr: *mut u8 = null_mut();
                let mut num_frames: u32 = 0;
                let mut flags: u32 = 0;

                if capture_client
                    .GetBuffer(&mut data_ptr, &mut num_frames, &mut flags, None, None)
                    .is_err()
                {
                    break;
                }

                if num_frames > 0 {
                    let data_size = num_frames as usize * bytes_per_frame;

                    let raw_chunk: &[u8] = if flags & AUDCLNT_BUFFERFLAGS_SILENT.0 as u32 != 0 {
                        // WASAPI says treat as silence — write zeroed bytes
                        &vec![0u8; data_size]
                    } else if !data_ptr.is_null() {
                        std::slice::from_raw_parts(data_ptr, data_size)
                    } else {
                        &[]
                    };

                    if !raw_chunk.is_empty() {
                        let pcm = if is_float {
                            convert_float_to_pcm16(raw_chunk)
                        } else {
                            raw_chunk.to_vec()
                        };

                        writer.write_all(&pcm).map_err(|e| {
                            windows::core::Error::new(E_FAIL, format!("Write failed: {}", e))
                        })?;

                        bytes_written += pcm.len() as u64;
                    }
                }

                let _ = capture_client.ReleaseBuffer(num_frames);

                packet_length = match capture_client.GetNextPacketSize() {
                    Ok(len) => len,
                    Err(_) => break,
                };
            }

            // Flush BufWriter to OS every second so the file is usable for clip copies
            if last_flush.elapsed() >= FLUSH_INTERVAL {
                let _ = writer.flush();
                last_flush = Instant::now();
            }

            thread::sleep(sleep_duration);
        }

        // Stop capture
        let _ = audio_client.Stop();

        // Nothing captured — delete the stub file and exit cleanly
        if bytes_written == 0 {
            drop(writer);
            let _ = std::fs::remove_file(output_file);
            return Ok(());
        }

        // Flush remaining buffer and get the underlying file back for seeking
        let mut file = writer.into_inner().map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Final flush failed: {}", e))
        })?;

        // Fix RIFF chunk size at offset 4: total file size minus the 8-byte "RIFF????WAVE" prefix
        let riff_size = (bytes_written + 36) as u32;
        file.seek(SeekFrom::Start(4)).map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Seek failed: {}", e))
        })?;
        file.write_all(&riff_size.to_le_bytes()).map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Header fix failed: {}", e))
        })?;

        // Fix data chunk size at offset 40
        file.seek(SeekFrom::Start(40)).map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Seek failed: {}", e))
        })?;
        file.write_all(&(bytes_written as u32).to_le_bytes()).map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Header fix failed: {}", e))
        })?;

        file.flush().map_err(|e| {
            windows::core::Error::new(E_FAIL, format!("Final flush failed: {}", e))
        })?;

        Ok(())
    }
}
