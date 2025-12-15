use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format!($($t)*)))
}

#[wasm_bindgen(start)]
pub fn init() {
    console_log!("wasm loaded");
}

#[wasm_bindgen]
pub fn do_something(input: &str) -> String {
    format!("processed: {}", input)
}