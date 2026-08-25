use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use pulldown_cmark::{
    html, CodeBlockKind, CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd,
};

mod highlight;
use highlight::Highlighter;

const SITE_URL: &str = "https://erickcestari.dev";

/// Pages that are pure layout: no data to interpolate beyond the shared chrome.
const STATIC_PAGES: [&str; 2] = ["books.html", "404.html"];

struct Post {
    slug: String,
    title: String,
    date: String,
    description: String,
    html: String,
    toc: String,
    reading_time: u32,
}

struct Heading {
    level: u8,
    id: String,
    text: String,
}

/// Renders `content/blog` and `templates` into `static`, relative to `root`.
/// Returns the number of posts generated.
pub fn generate(root: &Path) -> Result<usize, String> {
    let content_dir = root.join("content/blog");
    let static_dir = root.join("static");
    let out_dir = static_dir.join("blog");
    let templates_dir = root.join("templates");

    let layout = Layout::load(&templates_dir)?;
    let post_tmpl = layout.template(&templates_dir, "post.html")?;
    let list_tmpl = layout.template(&templates_dir, "list.html")?;
    let home_tmpl = layout.template(&templates_dir, "home.html")?;

    let highlighter = Highlighter::new();

    let mut posts: Vec<(Post, Option<PathBuf>)> = Vec::new();
    let read_dir =
        fs::read_dir(&content_dir).map_err(|e| format!("read {}: {e}", content_dir.display()))?;
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

        match parse_post(&md_path, &default_slug, &highlighter) {
            Ok(p) => posts.push((p, asset_dir)),
            Err(e) => {
                eprintln!("Skipping {}: {e}", md_path.display());
            }
        }
    }
    posts.sort_by(|a, b| b.0.date.cmp(&a.0.date));

    fs::create_dir_all(&out_dir).map_err(|e| format!("create {}: {e}", out_dir.display()))?;

    for (post, asset_dir) in &posts {
        let dir = out_dir.join(&post.slug);
        fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        write(&dir.join("index.html"), render_post(&post_tmpl, post))?;
        if let Some(src) = asset_dir {
            copy_assets(src, &dir)?;
        }
    }

    let bare_posts: Vec<&Post> = posts.iter().map(|(p, _)| p).collect();
    write(
        &out_dir.join("index.html"),
        render_list(&list_tmpl, &bare_posts),
    )?;
    write(
        &static_dir.join("index.html"),
        render_list(&home_tmpl, &bare_posts),
    )?;
    write(&out_dir.join("feed.xml"), render_atom(&bare_posts))?;
    write(&static_dir.join("sitemap.xml"), render_sitemap(&bare_posts))?;

    for page in STATIC_PAGES {
        write(
            &static_dir.join(page),
            layout.template(&templates_dir, page)?,
        )?;
    }

    Ok(posts.len())
}

/// The chrome shared by every page, injected wherever a template says
/// `{{header}}` / `{{footer}}`.
struct Layout {
    header: String,
    footer: String,
}

impl Layout {
    fn load(templates_dir: &Path) -> Result<Self, String> {
        let partials = templates_dir.join("partials");
        Ok(Layout {
            header: read(&partials.join("header.html"))?,
            footer: read(&partials.join("footer.html"))?,
        })
    }

    /// Reads a template and wraps it in the shared chrome. Trailing newlines are
    /// trimmed so a partial's own newline is the only one at the seam.
    fn template(&self, templates_dir: &Path, name: &str) -> Result<String, String> {
        let tmpl = read(&templates_dir.join(name))?;
        Ok(tmpl
            .replace("{{header}}", self.header.trim_end())
            .replace("{{footer}}", self.footer.trim_end()))
    }
}

fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

fn write(path: &Path, contents: String) -> Result<(), String> {
    fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

fn parse_post(path: &Path, default_slug: &str, hl: &Highlighter) -> Result<Post, String> {
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

    let (html_out, headings) = render_markdown(body, hl);
    let toc = render_toc(&headings);
    let reading_time = estimate_reading_minutes(body);

    Ok(Post {
        slug,
        title,
        date,
        description,
        html: html_out,
        toc,
        reading_time,
    })
}

fn estimate_reading_minutes(body: &str) -> u32 {
    let words = body.split_whitespace().count() as u32;
    ((words as f32) / 220.0).ceil().max(1.0) as u32
}

fn render_markdown(body: &str, hl: &Highlighter) -> (String, Vec<Heading>) {
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
    html::push_html(
        &mut html_out,
        highlight_code_blocks(rewritten, hl).into_iter(),
    );
    (wrap_images_in_figures(&html_out), headings)
}

/// Swaps each fenced block for pre-highlighted HTML, so pulldown-cmark's own
/// (unstyled) code-block rendering never runs.
fn highlight_code_blocks<'a>(events: Vec<Event<'a>>, hl: &Highlighter) -> Vec<Event<'a>> {
    let mut out = Vec::with_capacity(events.len());
    // Set while inside a fence: the language, and the source collected so far.
    let mut fence: Option<(Option<String>, String)> = None;

    for ev in events {
        match ev {
            Event::Start(Tag::CodeBlock(kind)) => {
                fence = Some((fence_language(&kind), String::new()));
            }
            Event::Text(text) => match fence.as_mut() {
                Some((_, code)) => code.push_str(&text),
                None => out.push(Event::Text(text)),
            },
            Event::End(TagEnd::CodeBlock) => match fence.take() {
                Some((lang, code)) => {
                    let html = hl.block(lang.as_deref(), &code);
                    out.push(Event::Html(CowStr::Boxed(html.into_boxed_str())));
                }
                None => out.push(Event::End(TagEnd::CodeBlock)),
            },
            other => out.push(other),
        }
    }
    out
}

/// ```` ```rust,ignore ```` -> `Some("rust")`; a bare or indented fence -> `None`.
fn fence_language(kind: &CodeBlockKind) -> Option<String> {
    let CodeBlockKind::Fenced(info) = kind else {
        return None;
    };
    let token = info
        .split(|c: char| c == ',' || c.is_whitespace())
        .next()
        .unwrap_or("");
    (!token.is_empty()).then(|| token.to_ascii_lowercase())
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

/// "2026-07-04" -> "July 4, 2026"; anything unparseable passes through as-is.
fn humanize_date(iso: &str) -> String {
    const MONTHS: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let mut parts = iso.splitn(3, '-');
    let (Some(year), Some(month), Some(day)) = (parts.next(), parts.next(), parts.next()) else {
        return iso.to_string();
    };
    let month_name = month
        .parse::<usize>()
        .ok()
        .filter(|m| (1..=12).contains(m))
        .map(|m| MONTHS[m - 1]);
    match month_name {
        Some(m) => format!("{} {}, {}", m, day.trim_start_matches('0'), year),
        None => iso.to_string(),
    }
}

fn render_post(tmpl: &str, p: &Post) -> String {
    tmpl.replace("{{title}}", &escape_html(&p.title))
        .replace("{{date_iso}}", &escape_html(&p.date))
        .replace("{{date}}", &escape_html(&humanize_date(&p.date)))
        .replace("{{description}}", &escape_html(&p.description))
        .replace("{{slug}}", &p.slug)
        .replace("{{url}}", &format!("{}/blog/{}/", SITE_URL, p.slug))
        .replace("{{toc}}", &p.toc)
        .replace("{{reading_time}}", &p.reading_time.to_string())
        .replace("{{content}}", &p.html)
}

/// Posts are sorted newest-first, so runs of equal years are contiguous;
/// each run opens with a year marker and its own <ul>.
fn render_list(tmpl: &str, posts: &[&Post]) -> String {
    let mut items = String::new();
    let mut current_year = "";
    for p in posts {
        let year = p.date.get(..4).unwrap_or("");
        if year != current_year {
            if !current_year.is_empty() {
                items.push_str("            </ul>\n");
            }
            items.push_str(&format!(
                "            <h3 class=\"year\">{}</h3>\n            <ul class=\"post-list\">\n",
                escape_html(year)
            ));
            current_year = year;
        }
        items.push_str(&format!(
            "                <li><a href=\"/blog/{}/\">{}</a><time datetime=\"{}\">{}</time></li>\n",
            p.slug,
            escape_html(&p.title),
            escape_html(&p.date),
            escape_html(&humanize_date(&p.date))
        ));
    }
    if !current_year.is_empty() {
        items.push_str("            </ul>");
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
        "  <url>\n    <loc>https://erickcestari.dev/</loc>\n    <priority>1.0</priority>\n  </url>\n  <url>\n    <loc>https://erickcestari.dev/blog</loc>\n    <priority>0.8</priority>\n  </url>\n  <url>\n    <loc>https://erickcestari.dev/books</loc>\n    <priority>0.7</priority>\n  </url>\n",
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
