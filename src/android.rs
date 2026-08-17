//! JNI surface for the Android app.
//!
//! Intentionally tiny: parse the same CLI string the binary accepts, run
//! [`crate::server`] on a background Tokio runtime, and push log lines plus
//! the `tg://` link back into Kotlin.  Start/stop is cooperative — completing
//! the watch channel breaks the accept loop the same way a Ctrl+C would.

use std::io::{self, Write};
use std::sync::{Mutex, OnceLock};

use jni::objects::{Global, JClass, JObject, JString, JValue, JValueOwned};
use jni::signature::MethodSignature;
use jni::strings::JNIString;
use jni::sys::{JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6, jboolean, jstring};
use jni::{EnvUnowned, Outcome, jni_sig};
use tokio::sync::watch;
use tracing_subscriber::fmt::MakeWriter;

use crate::config::Config;
use crate::server;

static JVM: OnceLock<jni::JavaVM> = OnceLock::new();
/// Cached in [`JNI_OnLoad`] / the first `native*` call, while the thread still
/// has the app class loader.  `FindClass` after `AttachCurrentThread` on a
/// Tokio worker sees only the system loader, which cannot see `NativeProxy`
/// and leaves a pending `ClassNotFoundException` that kills the process.
static NATIVE_CLASS: OnceLock<Global<JClass<'static>>> = OnceLock::new();

/// Signatures of the static Kotlin callbacks (`onNativeLog`, `onNativeError`,
/// `onNativeListening`, `onNativeStopped`), parsed at compile time.
static LOG_SIG: MethodSignature = jni_sig!((arg: JString) -> void);
static VOID_SIG: MethodSignature = jni_sig!(() -> void);

struct ProxyState {
    shutdown: Option<watch::Sender<bool>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

static STATE: Mutex<ProxyState> = Mutex::new(ProxyState {
    shutdown: None,
    thread: None,
});

const NATIVE_CLASS_NAME: &str = "com/github/valnesfjord/tg_ws_proxy_rs/NativeProxy";

#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(
    vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    // SAFETY: JNI_OnLoad is given a valid JavaVM pointer by the runtime.
    let vm = unsafe { jni::JavaVM::from_raw(vm) };
    let _ = vm.with_top_local_frame(|env| {
        cache_native_class_by_name(env);
        jni::errors::Result::Ok(())
    });
    let _ = JVM.set(vm);
    JNI_VERSION_1_6
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_valnesfjord_tg_1ws_1proxy_1rs_NativeProxy_nativeStart<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
    args: JString<'caller>,
) -> jstring {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jstring> {
            cache_native_class(env, &class);
            let args: String = match args.try_to_string(env) {
                Ok(s) => s,
                Err(e) => {
                    // A failed read leaves a pending exception; NewStringUTF
                    // below is not callable while one is pending, so clear it.
                    env.exception_clear();
                    return throw_string(env, &format!("invalid arguments: {e}"));
                }
            };

            match start_proxy(&args) {
                Ok(()) => Ok(std::ptr::null_mut()),
                Err(e) => throw_string(env, &e),
            }
        })
        .into_outcome()
        .into_value()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_valnesfjord_tg_1ws_1proxy_1rs_NativeProxy_nativeStop<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
) {
    unowned_env
        .with_env(|env| -> jni::errors::Result<()> {
            cache_native_class(env, &class);
            stop_proxy();
            Ok(())
        })
        .into_outcome()
        .into_value();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_github_valnesfjord_tg_1ws_1proxy_1rs_NativeProxy_nativeIsRunning<
    'caller,
>(
    mut unowned_env: EnvUnowned<'caller>,
    class: JClass<'caller>,
) -> jboolean {
    unowned_env
        .with_env(|env| -> jni::errors::Result<jboolean> {
            cache_native_class(env, &class);
            Ok(match STATE.lock() {
                Ok(state) => {
                    if state.thread.as_ref().is_some_and(|t| !t.is_finished()) {
                        JNI_TRUE
                    } else {
                        JNI_FALSE
                    }
                }
                Err(_) => JNI_FALSE,
            })
        })
        .into_outcome()
        .into_value()
}

/// Extract the value from a `with_env` outcome, falling back to the default on
/// any JNI error or panic — the Kotlin side is only ever told success or an
/// error `jstring`, never made to observe a Rust panic.
trait OutcomeValue {
    type Value;
    fn into_value(self) -> Self::Value;
}

impl<T: Default> OutcomeValue for Outcome<T, jni::errors::Error> {
    type Value = T;

    fn into_value(self) -> T {
        match self {
            Outcome::Ok(value) => value,
            Outcome::Err(_) | Outcome::Panic(_) => T::default(),
        }
    }
}

fn cache_native_class(env: &mut jni::Env, class: &JClass) {
    if NATIVE_CLASS.get().is_some() {
        return;
    }
    if let Ok(global) = env.new_global_ref(class) {
        let _ = NATIVE_CLASS.set(global);
    }
}

fn cache_native_class_by_name(env: &mut jni::Env) {
    if NATIVE_CLASS.get().is_some() {
        return;
    }
    match env.find_class(JNIString::new(NATIVE_CLASS_NAME)) {
        Ok(class) => cache_native_class(env, &class),
        Err(_) => {
            env.exception_clear();
        }
    }
}

fn throw_string(env: &mut jni::Env, msg: &str) -> jni::errors::Result<jstring> {
    match JString::new(env, msg) {
        Ok(s) => Ok(s.into_raw()),
        Err(_) => Ok(std::ptr::null_mut()),
    }
}

fn start_proxy(args: &str) -> Result<(), String> {
    let mut state = STATE
        .lock()
        .map_err(|_| "proxy state lock poisoned".to_string())?;
    if state.thread.as_ref().is_some_and(|t| !t.is_finished()) {
        return Err("proxy is already running".into());
    }

    let config = Config::try_from_cli_line(args)?;
    install_logging(&config);
    server::install_crypto_provider();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let thread = std::thread::Builder::new()
        .name("tg-ws-proxy".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("tg-ws-worker")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    emit_error(&format!("failed to start runtime: {e}"));
                    return;
                }
            };

            let result = rt.block_on(async move {
                let shutdown = async move {
                    let mut rx = shutdown_rx;
                    loop {
                        if *rx.borrow() {
                            break;
                        }
                        if rx.changed().await.is_err() {
                            break;
                        }
                    }
                };
                server::run_with_listen(config, shutdown, |info| {
                    emit_listening(&info.tg_link);
                })
                .await
            });

            match result {
                Ok(()) => emit_stopped(),
                Err(e) => emit_error(&format!("proxy failed: {e}")),
            }
        })
        .map_err(|e| format!("failed to spawn proxy thread: {e}"))?;

    state.shutdown = Some(shutdown_tx);
    state.thread = Some(thread);
    Ok(())
}

fn stop_proxy() {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(_) => return,
    };
    if let Some(tx) = state.shutdown.take() {
        let _ = tx.send(true);
    }
    let thread = state.thread.take();
    drop(state);
    if let Some(thread) = thread {
        let _ = thread.join();
    }
}

fn install_logging(config: &Config) {
    let log_level = if config.quiet {
        "off"
    } else if config.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_ansi(false)
        .with_target(false)
        .with_writer(AndroidMakeWriter)
        .try_init();
}

struct AndroidMakeWriter;

impl<'a> MakeWriter<'a> for AndroidMakeWriter {
    type Writer = AndroidWriter;

    fn make_writer(&'a self) -> Self::Writer {
        AndroidWriter { buf: Vec::new() }
    }
}

struct AndroidWriter {
    buf: Vec<u8>,
}

impl Write for AndroidWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        drain_lines(&mut self.buf);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buf.is_empty() {
            let line = String::from_utf8_lossy(&self.buf).into_owned();
            self.buf.clear();
            forward_line(&line);
        }
        Ok(())
    }
}

impl Drop for AndroidWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn drain_lines(buf: &mut Vec<u8>) {
    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let mut line: Vec<u8> = buf.drain(..=pos).collect();
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if !line.is_empty() {
            forward_line(&String::from_utf8_lossy(&line));
        }
    }
}

fn forward_line(line: &str) {
    logcat(line);
    emit_log(line);
}

fn logcat(line: &str) {
    const ANDROID_LOG_INFO: i32 = 4;
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(
            prio: i32,
            tag: *const std::ffi::c_char,
            text: *const std::ffi::c_char,
        ) -> i32;
    }

    let Ok(text) = std::ffi::CString::new(line.replace('\0', "")) else {
        return;
    };
    let tag = c"tg-ws-proxy";
    // SAFETY: both pointers are valid C strings for the duration of the call.
    unsafe {
        __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
    }
}

fn emit_log(line: &str) {
    call_static("onNativeLog", line);
}

/// Report a startup failure the way `nativeStart`'s return value would have,
/// had it been synchronous: the app flips out of the running state and shows
/// the message as the current error instead of a scrollback-only log line.
fn emit_error(line: &str) {
    logcat(line);
    call_static("onNativeError", line);
}

fn emit_listening(link: &str) {
    call_static("onNativeListening", link);
}

/// Report a clean worker exit — `--check` success or a graceful shutdown —
/// so the app leaves the running state even though no error occurred.
fn emit_stopped() {
    call_static_void("onNativeStopped");
}

fn call_static(method: &str, arg: &str) {
    call_static_impl(|env, class| {
        let jarg = JString::new(env, arg)?;
        let jarg: JObject = jarg.into();
        env.call_static_method(
            class,
            JNIString::new(method),
            &LOG_SIG,
            &[JValue::Object(&jarg)],
        )
    });
}

fn call_static_void(method: &str) {
    call_static_impl(|env, class| {
        env.call_static_method(class, JNIString::new(method), &VOID_SIG, &[])
    });
}

fn call_static_impl(
    call: impl for<'l> FnOnce(
        &mut jni::Env<'l>,
        &Global<JClass<'static>>,
    ) -> jni::errors::Result<JValueOwned<'l>>,
) {
    let Some(vm) = JVM.get() else {
        return;
    };
    let Some(class) = NATIVE_CLASS.get() else {
        return;
    };
    let _ = vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        if call(env, class).is_err() {
            // A pending exception on a detached worker is fatal (this is what
            // crashed Start: ClassNotFoundException from FindClass).
            env.exception_clear();
        }
        Ok(())
    });
}
