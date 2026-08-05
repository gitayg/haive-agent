// Windows tray icon + embedded chat window (Phase 2). Windows-only. Runs its own
// event loop on a dedicated thread (tao's with_any_thread), so the agent's main
// thread keeps serving. Best-effort: any GUI init failure (Session 0 service, no
// interactive desktop) just ends this thread — the agent keeps running headless.

use std::time::Duration;

use tao::dpi::LogicalSize;
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopWindowTarget};
use tao::platform::windows::EventLoopBuilderExtWindows;
use tao::window::{Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder, TrayIconEvent};
use wry::WebView;

/// Start the tray on a background thread. Waits for the loopback server to bind so
/// it knows the local chat URL.
pub fn spawn() {
    std::thread::spawn(|| {
        let mut port = 0u16;
        for _ in 0..150 {
            port = crate::http::loopback_port();
            if port != 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if port == 0 {
            return;
        }
        // A GUI panic (e.g. no desktop) must not take the process down.
        let _ = std::panic::catch_unwind(move || run(port));
    });
}

/// A simple 16x16 icon so the tray always has something to show.
fn icon() -> Option<Icon> {
    let (w, h) = (16u32, 16u32);
    let mut rgba = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h {
        for x in 0..w {
            let edge = x == 0 || y == 0 || x == w - 1 || y == h - 1;
            let (r, g, b) = if edge { (28, 33, 48) } else { (91, 157, 255) };
            rgba.extend_from_slice(&[r, g, b, 255]);
        }
    }
    Icon::from_rgba(rgba, w, h).ok()
}

fn run(port: u16) {
    let url = format!("http://127.0.0.1:{port}/chat");

    let menu = Menu::new();
    let open_item = MenuItem::new("Ask AI…", true, None);
    let quit_item = MenuItem::new("Quit IT-AI", true, None);
    let _ = menu.append(&open_item);
    let _ = menu.append(&quit_item);
    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();

    let event_loop = EventLoopBuilder::new().with_any_thread(true).build();

    // Keep the tray alive for the loop's lifetime.
    let mut tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("IT-AI — Ask AI")
        .with_icon(icon().unwrap_or_else(|| Icon::from_rgba(vec![91, 157, 255, 255], 1, 1).unwrap()))
        .build()
        .ok();

    let menu_rx = MenuEvent::receiver();
    let tray_rx = TrayIconEvent::receiver();

    let mut win: Option<(Window, WebView)> = None;

    event_loop.run(move |event, target, control_flow| {
        *control_flow = ControlFlow::Wait;

        // Clicking the window's X fires CloseRequested. Without handling it the X
        // does nothing. Hide instead of destroy so "Ask AI" reopens with the
        // conversation intact.
        if let tao::event::Event::WindowEvent { event: tao::event::WindowEvent::CloseRequested, .. } = &event {
            if let Some((w, _)) = &win {
                w.set_visible(false);
            }
        }

        while let Ok(ev) = menu_rx.try_recv() {
            if ev.id == open_id {
                open_chat(&mut win, target, &url);
            } else if ev.id == quit_id {
                tray.take();
                std::process::exit(0);
            }
        }
        while let Ok(_ev) = tray_rx.try_recv() {
            open_chat(&mut win, target, &url);
        }
    });
}

fn open_chat(win: &mut Option<(Window, WebView)>, target: &EventLoopWindowTarget<()>, url: &str) {
    if let Some((w, _)) = win {
        w.set_visible(true);
        w.set_focus();
        return;
    }
    let window = match WindowBuilder::new()
        .with_title("IT-AI — IT Assistant")
        .with_inner_size(LogicalSize::new(420.0, 640.0))
        .build(target)
    {
        Ok(w) => w,
        Err(_) => return,
    };
    match wry::WebViewBuilder::new(&window).with_url(url).build() {
        Ok(webview) => *win = Some((window, webview)),
        Err(_) => {}
    }
}
