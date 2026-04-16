---
title: hello world
date: 2026-04-15
description: first post, a quick note on why this blog exists and what to expect.
slug: hello-world
---

This is the first post on this site. Everything here is written in markdown, rendered at build time by a small Rust generator, then served as plain static HTML by [featherserve](https://github.com/erickcestari/portfolio). A custom web server running this domain.

## what you'll find here

- notes from security research on Bitcoin and Lightning
- fuzzing findings and disclosures
- occasional rabbit holes: emulators, low-level Rust, and whatever else I'm building

## why static html

No JavaScript on the page, no client-side rendering, no tracking.

```rust
fn main() {
    println!("hello, world!");
}
```

More soon.
