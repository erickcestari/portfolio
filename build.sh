#!/bin/bash
wasm-pack build --target web --release
cp -r pkg static/