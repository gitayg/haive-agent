// Mouse + keyboard injection on a dedicated thread (enigo is not Send).
use std::sync::mpsc::Receiver;

use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};

pub enum Ev {
    Move(f64, f64),
    Down(u8, f64, f64),
    Up(u8),
    Scroll(i32),
    Key(bool, String), // (is_down, key)
}

pub fn run(rx: Receiver<Ev>, geo: (i32, i32, u32, u32)) {
    let mut enigo = match Enigo::new(&Settings::default()) {
        Ok(e) => e,
        Err(_) => return,
    };
    let (gx, gy, gw, gh) = geo;
    let abs = |nx: f64, ny: f64| -> (i32, i32) {
        (gx + (nx * gw as f64) as i32, gy + (ny * gh as f64) as i32)
    };
    let btn = |b: u8| match b {
        1 => Button::Middle,
        2 => Button::Right,
        _ => Button::Left,
    };
    while let Ok(ev) = rx.recv() {
        let _ = match ev {
            Ev::Move(x, y) => {
                let (ax, ay) = abs(x, y);
                enigo.move_mouse(ax, ay, Coordinate::Abs)
            }
            Ev::Down(b, x, y) => {
                let (ax, ay) = abs(x, y);
                let _ = enigo.move_mouse(ax, ay, Coordinate::Abs);
                enigo.button(btn(b), Direction::Press)
            }
            Ev::Up(b) => enigo.button(btn(b), Direction::Release),
            Ev::Scroll(d) => enigo.scroll(d, Axis::Vertical),
            Ev::Key(down, k) => match map_key(&k) {
                Some(key) => enigo.key(key, if down { Direction::Press } else { Direction::Release }),
                None => Ok(()),
            },
        };
    }
}

fn map_key(k: &str) -> Option<Key> {
    Some(match k {
        "Enter" => Key::Return,
        "Backspace" => Key::Backspace,
        "Tab" => Key::Tab,
        "Escape" => Key::Escape,
        " " => Key::Space,
        "Delete" => Key::Delete,
        "ArrowUp" => Key::UpArrow,
        "ArrowDown" => Key::DownArrow,
        "ArrowLeft" => Key::LeftArrow,
        "ArrowRight" => Key::RightArrow,
        "Shift" => Key::Shift,
        "Control" => Key::Control,
        "Alt" => Key::Alt,
        "Meta" => Key::Meta,
        "CapsLock" => Key::CapsLock,
        "Home" => Key::Home,
        "End" => Key::End,
        "PageUp" => Key::PageUp,
        "PageDown" => Key::PageDown,
        "F1" => Key::F1,
        "F2" => Key::F2,
        "F3" => Key::F3,
        "F4" => Key::F4,
        "F5" => Key::F5,
        "F6" => Key::F6,
        "F7" => Key::F7,
        "F8" => Key::F8,
        "F9" => Key::F9,
        "F10" => Key::F10,
        "F11" => Key::F11,
        "F12" => Key::F12,
        _ => {
            let mut chars = k.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            Key::Unicode(c)
        }
    })
}
