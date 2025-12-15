use std::{
    fs,
    io::{BufReader, prelude::*},
    net::{TcpListener, TcpStream},
    path::Path,
    thread,
};

use pool::ThreadPool;

pub struct Featherserve {
    listener: TcpListener,
    pool: ThreadPool,
    static_dir: String,
}

impl Featherserve {
    pub fn new(listener: TcpListener) -> Self {
        let num_threads = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        Self {
            listener,
            pool: ThreadPool::new(num_threads),
            static_dir: "pages".to_string(),
        }
    }

    pub fn with_threads(mut self, num_threads: usize) -> Self {
        self.pool = ThreadPool::new(num_threads);
        self
    }

    pub fn with_static_dir(mut self, dir: impl Into<String>) -> Self {
        self.static_dir = dir.into();
        self
    }

    pub fn run(self) {
        println!(
            "Featherserve listening on {}",
            self.listener.local_addr().unwrap()
        );

        for stream in self.listener.incoming() {
            match stream {
                Ok(stream) => {
                    let static_dir = self.static_dir.clone();
                    self.pool.execute(move || {
                        Self::handle_connection(stream, &static_dir);
                    });
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
    }

    fn handle_connection(mut stream: TcpStream, static_dir: &str) {
        let buf_reader = BufReader::new(&stream);
        let request_line = match buf_reader.lines().next() {
            Some(Ok(line)) => line,
            _ => return,
        };

        let (_method, path, _protocol) = Self::parse_request_line(&request_line);

        println!("Request: {}", path);

        let file_path = Self::resolve_path(path, static_dir);

        let (status_line, file_path) = if Path::new(&file_path).exists() {
            ("HTTP/1.1 200 OK", file_path)
        } else {
            ("HTTP/1.1 404 NOT FOUND", format!("{}/404.html", static_dir))
        };

        let contents = match fs::read(&file_path) {
            Ok(c) => c,
            Err(_) => b"Not Found".to_vec(),
        };

        let content_type = Self::get_content_type(&file_path);
        let length = contents.len();

        let response = format!(
            "{status_line}\r\nContent-Length: {length}\r\nContent-Type: {content_type}\r\n\r\n"
        );

        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&contents);
    }

    fn resolve_path(path: &str, static_dir: &str) -> String {
        if path == "/" {
            format!("{}/index.html", static_dir)
        } else if !path.contains('.') {
            format!("{}{}.html", static_dir, path)
        } else {
            format!("{}{}", static_dir, path)
        }
    }

    fn parse_request_line(request_line: &str) -> (&str, &str, &str) {
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("/");
        let protocol = parts.next().unwrap_or("");
        (method, path, protocol)
    }

    fn get_content_type(filename: &str) -> &'static str {
        match Path::new(filename).extension().and_then(|ext| ext.to_str()) {
            Some("html") => "text/html",
            Some("css") => "text/css",
            Some("js") => "application/javascript",
            Some("json") => "application/json",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("jpeg" | "jpg") => "image/jpeg",
            Some("ico") => "image/x-icon",
            Some("woff") => "font/woff",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        }
    }
}
