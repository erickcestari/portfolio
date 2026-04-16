use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use pulldown_cmark::{html, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd};

const SITE_URL: &str = "https://erickcestari.dev";

struct Post {
    slug: String,
    title: String,
    date: String,
    description: String,
    html: String,
    toc: String,
}

struct Heading {
    level: u8,
    id: String,
    text: String,
}

fn main() -> ExitCode {
    let root = project_root();
    let content_dir = root.join("content/blog");
    let out_dir = root.join("static/blog");
    let templates_dir = root.join("templates");

    let post_tmpl = match fs::read_to_string(templates_dir.join("post.html")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read templates/post.html: {e}");
            return ExitCode::FAILURE;
        }
    };
    let list_tmpl = match fs::read_to_string(templates_dir.join("list.html")) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read templates/list.html: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut posts: Vec<(Post, Option<PathBuf>)> = Vec::new();
    let read_dir = match fs::read_dir(&content_dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", content_dir.display());
            return ExitCode::FAILURE;
        }
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let (md_path, asset_dir, default_slug) = if path.is_file() {
            if path.extension().and_then(|e| e.to_str()) != Some("md") {
                continue;
            }
            let slug = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("post")
                .to_string();
            (path.clone(), None, slug)
        } else if path.is_dir() {
            let index = path.join("index.md");
            if !index.is_file() {
                continue;
            }
            let slug = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("post")
                .to_string();
            (index, Some(path.clone()), slug)
        } else {
            continue;
        };

        match parse_post(&md_path, &default_slug) {
            Ok(p) => posts.push((p, asset_dir)),
            Err(e) => {
                eprintln!("Skipping {}: {e}", md_path.display());
            }
        }
    }
    posts.sort_by(|a, b| b.0.date.cmp(&a.0.date));

    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("Failed to create {}: {e}", out_dir.display());
        return ExitCode::FAILURE;
    }

    for (post, asset_dir) in &posts {
        let dir = out_dir.join(&post.slug);
        if let Err(e) = fs::create_dir_all(&dir) {
            eprintln!("Failed to create {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
        let rendered = render_post(&post_tmpl, post);
        if let Err(e) = fs::write(dir.join("index.html"), rendered) {
            eprintln!("Failed to write post {}: {e}", post.slug);
            return ExitCode::FAILURE;
        }
        if let Some(src) = asset_dir {
            if let Err(e) = copy_assets(src, &dir) {
                eprintln!("Failed to copy assets for {}: {e}", post.slug);
                return ExitCode::FAILURE;
            }
        }
    }

    let bare_posts: Vec<&Post> = posts.iter().map(|(p, _)| p).collect();
    let list_html = render_list(&list_tmpl, &bare_posts);
    if let Err(e) = fs::write(out_dir.join("index.html"), list_html) {
        eprintln!("Failed to write blog index: {e}");
        return ExitCode::FAILURE;
    }

    let feed = render_atom(&bare_posts);
    if let Err(e) = fs::write(out_dir.join("feed.xml"), feed) {
        eprintln!("Failed to write feed: {e}");
        return ExitCode::FAILURE;
    }

    let sitemap = render_sitemap(&bare_posts);
    if let Err(e) = fs::write(root.join("static/sitemap.xml"), sitemap) {
        eprintln!("Failed to write sitemap: {e}");
        return ExitCode::FAILURE;
    }

    println!("Generated {} post(s)", posts.len());
    ExitCode::SUCCESS
}

fn project_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("manifest has a parent")
        .to_path_buf()
}

fn parse_post(path: &Path, default_slug: &str) -> Result<Post, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let (meta, body) = split_frontmatter(&raw);

    let mut title = String::new();
    let mut date = String::new();
    let mut description = String::new();
    let mut slug = default_slug.to_string();

    for line in meta.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim().trim_matches('"').trim_matches('\'').to_string();
        match key {
            "title" => title = val,
            "date" => date = val,
            "description" => description = val,
            "slug" => slug = val,
            _ => {}
        }
    }

    if title.is_empty() {
        return Err("missing frontmatter: title".into());
    }
    if date.is_empty() {
        return Err("missing frontmatter: date".into());
    }

    let (html_out, headings) = render_markdown(body);
    let toc = render_toc(&headings);

    Ok(Post {
        slug,
        title,
        date,
        description,
        html: html_out,
        toc,
    })
}

fn render_markdown(body: &str) -> (String, Vec<Heading>) {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_FOOTNOTES);

    let events: Vec<Event> = Parser::new_ext(body, options).collect();

    let mut headings: Vec<Heading> = Vec::new();
    let mut heading_ids: Vec<Option<String>> = vec![None; events.len()];
    let mut seen_ids: HashMap<String, u32> = HashMap::new();

    let mut i = 0;
    while i < events.len() {
        if let Event::Start(Tag::Heading { level, .. }) = &events[i] {
            let level_u8 = heading_level_u8(*level);
            let mut text = String::new();
            let mut j = i + 1;
            while j < events.len() {
                match &events[j] {
                    Event::End(TagEnd::Heading(_)) => break,
                    Event::Text(t) => text.push_str(t),
                    Event::Code(t) => text.push_str(t),
                    _ => {}
                }
                j += 1;
            }
            let slug = slugify(&text);
            let id = uniquify(&mut seen_ids, slug);
            heading_ids[i] = Some(id.clone());
            headings.push(Heading {
                level: level_u8,
                id,
                text,
            });
            i = j + 1;
        } else {
            i += 1;
        }
    }

    let rewritten: Vec<Event> = events
        .into_iter()
        .enumerate()
        .map(|(idx, ev)| match (heading_ids[idx].take(), ev) {
            (
                Some(new_id),
                Event::Start(Tag::Heading {
                    level,
                    classes,
                    attrs,
                    ..
                }),
            ) => Event::Start(Tag::Heading {
                level,
                id: Some(CowStr::Boxed(new_id.into_boxed_str())),
                classes,
                attrs,
            }),
            (_, ev) => ev,
        })
        .collect();

    let mut html_out = String::new();
    html::push_html(&mut html_out, rewritten.into_iter());
    (wrap_images_in_figures(&html_out), headings)
}

fn wrap_images_in_figures(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut cursor = 0;
    let bytes = html.as_bytes();
    while cursor < bytes.len() {
        let Some(rel) = html[cursor..].find("<p><img ") else {
            out.push_str(&html[cursor..]);
            break;
        };
        let p_start = cursor + rel;
        let inner_start = p_start + "<p>".len();
        let Some(p_end_rel) = html[inner_start..].find("</p>") else {
            out.push_str(&html[cursor..]);
            break;
        };
        let inner_end = inner_start + p_end_rel;
        let p_end = inner_end + "</p>".len();
        let inner = &html[inner_start..inner_end];

        if inner.starts_with("<img ") && inner.ends_with("/>") && !inner[5..].contains('<') {
            if let Some(alt) = extract_alt_attr(inner) {
                out.push_str(&html[cursor..p_start]);
                out.push_str("<figure>\n");
                out.push_str(inner);
                out.push_str("\n<figcaption>");
                out.push_str(&alt);
                out.push_str("</figcaption>\n</figure>");
                cursor = p_end;
                continue;
            }
        }
        out.push_str(&html[cursor..p_end]);
        cursor = p_end;
    }
    out
}

fn extract_alt_attr(img_tag: &str) -> Option<String> {
    let marker = " alt=\"";
    let start = img_tag.find(marker)? + marker.len();
    let rest = &img_tag[start..];
    let end = rest.find('"')?;
    let alt = &rest[..end];
    if alt.is_empty() {
        None
    } else {
        Some(alt.to_string())
    }
}

fn heading_level_u8(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_dash = false;
    for c in s.chars() {
        let lc = c.to_ascii_lowercase();
        if lc.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            out.push(lc);
            pending_dash = false;
        } else {
            pending_dash = true;
        }
    }
    if out.is_empty() {
        out.push_str("heading");
    }
    out
}

fn uniquify(seen: &mut HashMap<String, u32>, base: String) -> String {
    let count = seen.entry(base.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        base
    } else {
        format!("{}-{}", base, *count - 1)
    }
}

fn render_toc(headings: &[Heading]) -> String {
    let items: Vec<&Heading> = headings
        .iter()
        .filter(|h| h.level == 2 || h.level == 3)
        .collect();
    if items.len() < 2 {
        return String::new();
    }
    let mut out = String::from(
        "<nav class=\"toc\" aria-label=\"table of contents\">\n  <details open>\n    <summary>contents</summary>\n    <ul>\n",
    );
    for h in &items {
        out.push_str(&format!(
            "      <li class=\"toc-h{}\"><a href=\"#{}\">{}</a></li>\n",
            h.level,
            h.id,
            escape_html(&h.text)
        ));
    }
    out.push_str("    </ul>\n  </details>\n</nav>\n");
    out
}

fn split_frontmatter(raw: &str) -> (&str, &str) {
    let trimmed = raw.trim_start_matches('\u{feff}');
    let rest = match trimmed.strip_prefix("---\n") {
        Some(r) => r,
        None => match trimmed.strip_prefix("---\r\n") {
            Some(r) => r,
            None => return ("", raw),
        },
    };
    if let Some(end) = rest.find("\n---") {
        let meta = &rest[..end];
        let after = &rest[end + 4..];
        let body = after
            .strip_prefix("\r\n")
            .or_else(|| after.strip_prefix('\n'))
            .unwrap_or(after);
        return (meta, body);
    }
    ("", raw)
}

fn render_post(tmpl: &str, p: &Post) -> String {
    tmpl.replace("{{title}}", &escape_html(&p.title))
        .replace("{{date}}", &escape_html(&p.date))
        .replace("{{description}}", &escape_html(&p.description))
        .replace("{{slug}}", &p.slug)
        .replace("{{url}}", &format!("{}/blog/{}/", SITE_URL, p.slug))
        .replace("{{toc}}", &p.toc)
        .replace("{{content}}", &p.html)
}

fn render_list(tmpl: &str, posts: &[&Post]) -> String {
    let mut items = String::new();
    for p in posts {
        items.push_str(&format!(
            "        <li><time>{}</time> <a href=\"/blog/{}/\">{}</a></li>\n",
            escape_html(&p.date),
            p.slug,
            escape_html(&p.title)
        ));
    }
    tmpl.replace("{{items}}", items.trim_end())
}

fn render_atom(posts: &[&Post]) -> String {
    let updated = posts
        .first()
        .map(|p| format!("{}T00:00:00Z", p.date))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into());

    let mut entries = String::new();
    for p in posts {
        entries.push_str(&format!(
            "  <entry>\n    <title>{title}</title>\n    <link href=\"{site}/blog/{slug}/\"/>\n    <id>{site}/blog/{slug}/</id>\n    <updated>{date}T00:00:00Z</updated>\n    <summary>{desc}</summary>\n  </entry>\n",
            title = escape_html(&p.title),
            site = SITE_URL,
            slug = p.slug,
            date = p.date,
            desc = escape_html(&p.description),
        ));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<feed xmlns=\"http://www.w3.org/2005/Atom\">\n  <title>erickcestari.dev</title>\n  <link href=\"{site}/blog/feed.xml\" rel=\"self\"/>\n  <link href=\"{site}/blog\"/>\n  <id>{site}/blog</id>\n  <updated>{updated}</updated>\n{entries}</feed>\n",
        site = SITE_URL,
        updated = updated,
        entries = entries,
    )
}

fn render_sitemap(posts: &[&Post]) -> String {
    let mut urls = String::from(
        "  <url>\n    <loc>https://erickcestari.dev/</loc>\n    <priority>1.0</priority>\n  </url>\n  <url>\n    <loc>https://erickcestari.dev/about</loc>\n    <priority>0.8</priority>\n  </url>\n  <url>\n    <loc>https://erickcestari.dev/blog</loc>\n    <priority>0.8</priority>\n  </url>\n  <url>\n    <loc>https://erickcestari.dev/contact</loc>\n    <priority>0.7</priority>\n  </url>\n",
    );
    for p in posts {
        urls.push_str(&format!(
            "  <url>\n    <loc>{}/blog/{}/</loc>\n    <priority>0.6</priority>\n  </url>\n",
            SITE_URL, p.slug
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n{}</urlset>\n",
        urls
    )
}

fn copy_assets(src: &Path, dst: &Path) -> Result<(), String> {
    let read_dir = fs::read_dir(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    for entry in read_dir.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if name == "index.md" || name.ends_with(".md") {
            continue;
        }
        let out = dst.join(name);
        fs::copy(&path, &out)
            .map_err(|e| format!("copy {} -> {}: {e}", path.display(), out.display()))?;
    }
    Ok(())
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}
