// Hide the console window on Windows for a release build: the Agent lives in the tray.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    zbacs_agent_lib::run();
}
