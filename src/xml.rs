//! Small XML tree with namespaces and Canonical XML 1.0 (inclusive and exclusive, with or
//! without comments), as needed for XML signatures (XAdES).
//!
//! Supports UTF-8 documents without custom entities; the DOCTYPE is skipped (as C14N does).

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail};
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

pub const NS_XML: &str = "http://www.w3.org/XML/1998/namespace";
pub const C14N: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub const C14N_11: &str = "http://www.w3.org/2006/12/xml-c14n11";
pub const C14N_11_COMMENTS: &str = "http://www.w3.org/2006/12/xml-c14n11#WithComments";

#[derive(Clone, Debug)]
pub struct Attr {
    pub prefix: String,
    pub local: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub enum Kind {
    Document,
    Element { prefix: String, local: String, attrs: Vec<Attr>, ns: Vec<(String, String)> },
    Text(String),
    Comment(String),
    Pi(String, String),
}

#[derive(Clone, Debug)]
pub struct Node {
    pub kind: Kind,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    /// Byte offset of the start tag in the source.
    pub start: usize,
    /// Byte offset of the end tag (`</...>`, or the end of an empty element).
    pub end_tag: usize,
}

#[derive(Clone, Debug)]
pub struct Doc {
    pub nodes: Vec<Node>,
}

fn eol(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\r', "\n")
}

fn split_qname(q: &str) -> (String, String) {
    match q.split_once(':') {
        Some((p, l)) => (p.to_string(), l.to_string()),
        None => (String::new(), q.to_string()),
    }
}

pub fn parse(bytes: &[u8]) -> Result<Doc> {
    let bom = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) { 3 } else { 0 };
    let text = std::str::from_utf8(&bytes[bom..]).map_err(|_| anyhow!("only UTF-8 XML is supported"))?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = true;
    let mut doc = Doc { nodes: vec![Node { kind: Kind::Document, parent: None, children: vec![], start: 0, end_tag: 0 }] };
    let mut stack = vec![0usize];
    let push = |doc: &mut Doc, stack: &[usize], kind: Kind, start: usize| -> usize {
        let parent = *stack.last().unwrap();
        let id = doc.nodes.len();
        doc.nodes.push(Node { kind, parent: Some(parent), children: vec![], start, end_tag: start });
        doc.nodes[parent].children.push(id);
        id
    };
    let push_text = |doc: &mut Doc, stack: &[usize], s: &str, start: usize| {
        let parent = *stack.last().unwrap();
        if let Some(&last) = doc.nodes[parent].children.last()
            && let Kind::Text(t) = &mut doc.nodes[last].kind
        {
            t.push_str(s);
            return;
        }
        push(doc, stack, Kind::Text(s.to_string()), start);
    };
    loop {
        let start = reader.buffer_position() as usize + bom;
        let ev = reader.read_event().map_err(|e| anyhow!("XML: {e} (at byte {start})"))?;
        let end = reader.buffer_position() as usize + bom;
        match ev {
            Event::Decl(d) => {
                if let Some(Ok(enc)) = d.encoding()
                    && !enc.eq_ignore_ascii_case("utf-8")
                    && !enc.eq_ignore_ascii_case("utf8")
                {
                    bail!("only UTF-8 XML is supported (encoding=\"{}\")", enc);
                }
            }
            Event::Start(e) | Event::Empty(e) => {
                let empty = end > 1 && bytes.get(end - 2) == Some(&b'/');
                let (prefix, local) = split_qname(e.name().as_ref());
                let mut attrs = Vec::new();
                let mut ns = Vec::new();
                for a in e.attributes() {
                    let a = a.map_err(|e| anyhow!("XML: {e}"))?;
                    let key = a.key.as_ref().to_string();
                    let value = a.normalized_value(quick_xml::XmlVersion::Implicit1_0).map_err(|e| anyhow!("XML: {e}"))?.into_owned();
                    if key == "xmlns" {
                        ns.push((String::new(), value));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        ns.push((p.to_string(), value));
                    } else {
                        let (prefix, local) = split_qname(&key);
                        attrs.push(Attr { prefix, local, value });
                    }
                }
                let id = push(&mut doc, &stack, Kind::Element { prefix, local, attrs, ns }, start);
                if empty {
                    doc.nodes[id].end_tag = start;
                } else {
                    stack.push(id);
                }
            }
            Event::End(_) => {
                let id = stack.pop().ok_or_else(|| anyhow!("XML: unbalanced end tag"))?;
                doc.nodes[id].end_tag = start;
            }
            Event::Text(t) => {
                if stack.len() > 1 {
                    push_text(&mut doc, &stack, &t.xml10_content(), start);
                }
            }
            Event::CData(t) => push_text(&mut doc, &stack, &t.xml10_content(), start),
            Event::GeneralRef(r) => {
                let s = match r.resolve_char_ref().map_err(|e| anyhow!("XML: {e}"))? {
                    Some(c) => c.to_string(),
                    None => resolve_predefined_entity(&r).ok_or_else(|| anyhow!("XML: unknown entity &{};", &*r))?.to_string(),
                };
                push_text(&mut doc, &stack, &s, start);
            }
            Event::Comment(c) => {
                push(&mut doc, &stack, Kind::Comment(c.xml10_content().into_owned()), start);
            }
            Event::PI(p) => {
                let target = p.target().to_string();
                let data = eol(p.content().trim_start());
                push(&mut doc, &stack, Kind::Pi(target, data), start);
            }
            Event::DocType(_) => {}
            Event::Eof => break,
        }
    }
    if stack.len() != 1 || doc.root().is_none() {
        bail!("XML: no document element");
    }
    Ok(doc)
}

impl Doc {
    pub fn root(&self) -> Option<usize> {
        self.nodes[0].children.iter().copied().find(|&c| matches!(self.nodes[c].kind, Kind::Element { .. }))
    }

    pub fn ancestors(&self, id: usize) -> impl Iterator<Item = usize> + '_ {
        std::iter::successors(self.nodes[id].parent, |&p| self.nodes[p].parent)
    }

    /// In-scope namespaces of element `id` (prefix -> URI; "" = default).
    pub fn scope(&self, id: usize) -> BTreeMap<String, String> {
        let mut chain: Vec<usize> = self.ancestors(id).collect();
        chain.reverse();
        chain.push(id);
        let mut m = BTreeMap::new();
        for n in chain {
            if let Kind::Element { ns, .. } = &self.nodes[n].kind {
                for (p, u) in ns {
                    m.insert(p.clone(), u.clone());
                }
            }
        }
        m
    }

    /// Namespace URI and local name of element `id`.
    pub fn name(&self, id: usize) -> Option<(String, &str)> {
        let Kind::Element { prefix, local, .. } = &self.nodes[id].kind else { return None };
        Some((self.scope(id).get(prefix).cloned().unwrap_or_default(), local))
    }

    pub fn is(&self, id: usize, ns: &str, local: &str) -> bool {
        self.name(id).is_some_and(|(n, l)| n == ns && l == local)
    }

    pub fn attr(&self, id: usize, local: &str) -> Option<&str> {
        let Kind::Element { attrs, .. } = &self.nodes[id].kind else { return None };
        attrs.iter().find(|a| a.prefix.is_empty() && a.local == local).map(|a| a.value.as_str())
    }

    pub fn elements(&self, id: usize) -> impl Iterator<Item = usize> + '_ {
        self.nodes[id].children.iter().copied().filter(|&c| matches!(self.nodes[c].kind, Kind::Element { .. }))
    }

    pub fn child(&self, id: usize, ns: &str, local: &str) -> Option<usize> {
        self.elements(id).find(|&c| self.is(c, ns, local))
    }

    /// All elements in document order (depth first).
    pub fn descendants(&self, id: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack: Vec<usize> = self.nodes[id].children.iter().rev().copied().collect();
        while let Some(n) = stack.pop() {
            if matches!(self.nodes[n].kind, Kind::Element { .. }) {
                out.push(n);
                stack.extend(self.nodes[n].children.iter().rev());
            }
        }
        out
    }

    /// Concatenated text content.
    pub fn text(&self, id: usize) -> String {
        let mut s = String::new();
        for &c in &self.nodes[id].children {
            match &self.nodes[c].kind {
                Kind::Text(t) => s.push_str(t),
                Kind::Element { .. } => s.push_str(&self.text(c)),
                _ => {}
            }
        }
        s
    }

    /// Element whose `Id` / `ID` / `id` attribute is `value`.
    pub fn by_id(&self, value: &str) -> Option<usize> {
        self.descendants(0).into_iter().find(|&n| ["Id", "ID", "id"].iter().any(|a| self.attr(n, a) == Some(value)))
    }
}

/// Canonicalization settings.
#[derive(Clone, Debug, Default)]
pub struct C14n {
    pub exclusive: bool,
    pub comments: bool,
    /// Exclusive only: prefixes treated as in inclusive C14N (`#default` = the default namespace).
    pub inclusive_prefixes: Vec<String>,
    /// Canonical XML 1.1: only xml:lang and xml:space are inherited onto the apex (not xml:id).
    pub v11: bool,
}

impl C14n {
    pub fn from_uri(uri: &str) -> Option<C14n> {
        let (exclusive, comments, v11) = match uri {
            C14N => (false, false, false),
            C14N_COMMENTS => (false, true, false),
            C14N_11 => (false, false, true),
            C14N_11_COMMENTS => (false, true, true),
            EXC_C14N => (true, false, false),
            EXC_C14N_COMMENTS => (true, true, false),
            _ => return None,
        };
        Some(C14n { exclusive, comments, inclusive_prefixes: vec![], v11 })
    }
}

fn esc_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn esc_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

/// Canonical form of node `id` (the document node or an element subtree), leaving out the
/// subtree `exclude` (enveloped-signature transform).
pub fn canonicalize(doc: &Doc, id: usize, opts: &C14n, exclude: Option<usize>) -> Vec<u8> {
    let mut out = String::new();
    if id == 0 {
        let mut seen_root = false;
        for &c in &doc.nodes[0].children {
            match &doc.nodes[c].kind {
                Kind::Element { .. } => {
                    seen_root = true;
                    element(doc, c, opts, exclude, &BTreeMap::new(), doc.scope(c), true, &mut out);
                }
                Kind::Comment(_) | Kind::Pi(..) if opts.comments || matches!(doc.nodes[c].kind, Kind::Pi(..)) => {
                    if seen_root {
                        out.push('\n');
                    }
                    misc(&doc.nodes[c].kind, &mut out);
                    if !seen_root {
                        out.push('\n');
                    }
                }
                _ => {}
            }
        }
    } else {
        element(doc, id, opts, exclude, &BTreeMap::new(), doc.scope(id), true, &mut out);
    }
    out.into_bytes()
}

fn misc(kind: &Kind, out: &mut String) {
    match kind {
        Kind::Comment(c) => {
            out.push_str("<!--");
            out.push_str(c);
            out.push_str("-->");
        }
        Kind::Pi(t, d) => {
            out.push_str("<?");
            out.push_str(t);
            if !d.is_empty() {
                out.push(' ');
                out.push_str(d);
            }
            out.push_str("?>");
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn element(doc: &Doc, id: usize, opts: &C14n, exclude: Option<usize>, rendered: &BTreeMap<String, String>, scope: BTreeMap<String, String>, apex: bool, out: &mut String) {
    if Some(id) == exclude {
        return;
    }
    let Kind::Element { prefix, local, attrs, .. } = &doc.nodes[id].kind else { return };
    // Namespace declarations to output.
    let mut decls: BTreeMap<String, String> = BTreeMap::new();
    let candidates: Vec<String> = if opts.exclusive {
        let mut v = vec![prefix.clone()];
        v.extend(attrs.iter().filter(|a| !a.prefix.is_empty() && a.prefix != "xml").map(|a| a.prefix.clone()));
        for p in &opts.inclusive_prefixes {
            v.push(if p == "#default" { String::new() } else { p.clone() });
        }
        v
    } else {
        scope.keys().cloned().chain(std::iter::once(String::new())).collect()
    };
    for p in candidates {
        if p == "xml" {
            continue;
        }
        let uri = scope.get(&p).cloned().unwrap_or_default();
        let inclusive_only = opts.exclusive && !(p == *prefix || attrs.iter().any(|a| a.prefix == p));
        if inclusive_only && !scope.contains_key(&p) {
            continue;
        }
        let before = rendered.get(&p);
        let needed = if uri.is_empty() { before.is_some_and(|b| !b.is_empty()) } else { before != Some(&uri) };
        if needed {
            decls.insert(p, uri);
        }
    }
    out.push('<');
    let qname = if prefix.is_empty() { local.clone() } else { format!("{prefix}:{local}") };
    out.push_str(&qname);
    for (p, u) in &decls {
        out.push_str(if p.is_empty() { " xmlns" } else { " xmlns:" });
        out.push_str(p);
        out.push_str("=\"");
        esc_attr(u, out);
        out.push('"');
    }
    // Attributes, sorted by namespace URI then local name; inclusive C14N copies inherited xml:*
    // attributes onto the apex of a subtree.
    let mut list: Vec<(String, String, String, String)> = attrs
        .iter()
        .map(|a| {
            let ns = if a.prefix.is_empty() { String::new() } else if a.prefix == "xml" { NS_XML.into() } else { scope.get(&a.prefix).cloned().unwrap_or_default() };
            (ns, a.local.clone(), a.prefix.clone(), a.value.clone())
        })
        .collect();
    if apex && !opts.exclusive {
        for anc in doc.ancestors(id) {
            if let Kind::Element { attrs, .. } = &doc.nodes[anc].kind {
                for a in attrs.iter().filter(|a| a.prefix == "xml" && (!opts.v11 || a.local == "lang" || a.local == "space")) {
                    if !list.iter().any(|(ns, l, _, _)| ns == NS_XML && *l == a.local) {
                        list.push((NS_XML.into(), a.local.clone(), "xml".into(), a.value.clone()));
                    }
                }
            }
        }
    }
    list.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    for (_, l, p, v) in &list {
        out.push(' ');
        if !p.is_empty() {
            out.push_str(p);
            out.push(':');
        }
        out.push_str(l);
        out.push_str("=\"");
        esc_attr(v, out);
        out.push('"');
    }
    out.push('>');
    let mut now_rendered = rendered.clone();
    for (p, u) in decls {
        now_rendered.insert(p, u);
    }
    for &c in &doc.nodes[id].children {
        match &doc.nodes[c].kind {
            Kind::Element { ns, .. } => {
                let mut child_scope = scope.clone();
                for (p, u) in ns {
                    child_scope.insert(p.clone(), u.clone());
                }
                element(doc, c, opts, exclude, &now_rendered, child_scope, false, out);
            }
            Kind::Text(t) => esc_text(t, out),
            Kind::Comment(_) if opts.comments => misc(&doc.nodes[c].kind, out),
            Kind::Pi(..) => misc(&doc.nodes[c].kind, out),
            _ => {}
        }
    }
    out.push_str("</");
    out.push_str(&qname);
    out.push('>');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c14n(xml: &str, opts: &C14n) -> String {
        String::from_utf8(canonicalize(&parse(xml.as_bytes()).unwrap(), 0, opts, None)).unwrap()
    }

    /// Examples from the Canonical XML 1.0 specification (section 3).
    #[test]
    fn w3c_examples() {
        let pis = "<?xml version=\"1.0\"?>\r\n\r\n<?xml-stylesheet   href=\"doc.xsl\"\r\n   type=\"text/xsl\"   ?>\r\n\r\n<doc>Hello, world!<!-- Comment 1 --></doc>\r\n\r\n<?pi-without-data     ?>\r\n\r\n<!-- Comment 2 -->\r\n\r\n<!-- Comment 3 -->";
        assert_eq!(c14n(pis, &C14n::default()), "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!</doc>\n<?pi-without-data?>");
        assert_eq!(
            c14n(pis, &C14n { comments: true, ..Default::default() }),
            "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n<doc>Hello, world!<!-- Comment 1 --></doc>\n<?pi-without-data?>\n<!-- Comment 2 -->\n<!-- Comment 3 -->"
        );
        let start_end = r#"<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>"#;
        let expected = r#"<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>"#;
        assert_eq!(c14n(start_end, &C14n::default()), expected);
        let chars = "<doc>\r\n   <text>First line&#x0d;&#10;Second line</text>\r\n   <value>&#x32;</value>\r\n   <compute><![CDATA[value>\"0\" && value<\"10\" ?\"valid\":\"error\"]]></compute>\r\n   <compute expr='value>\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"'>valid</compute>\r\n   <norm attr=' &apos;   &#x20;&#13;&#xa;&#9;   &apos; '/>\r\n</doc>";
        let expected = "<doc>\n   <text>First line&#xD;\nSecond line</text>\n   <value>2</value>\n   <compute>value&gt;\"0\" &amp;&amp; value&lt;\"10\" ?\"valid\":\"error\"</compute>\n   <compute expr=\"value>&quot;0&quot; &amp;&amp; value&lt;&quot;10&quot; ?&quot;valid&quot;:&quot;error&quot;\">valid</compute>\n   <norm attr=\" '    &#xD;&#xA;&#x9;   ' \"></norm>\n</doc>";
        assert_eq!(c14n(chars, &C14n::default()), expected);
    }

    #[test]
    fn exclusive_only_renders_visibly_used_namespaces() {
        let xml = r#"<n0:a xmlns:n0="urn:0" xmlns:n1="urn:1" xmlns="urn:d"><n1:b n0:x="1"><c/></n1:b></n0:a>"#;
        let doc = parse(xml.as_bytes()).unwrap();
        let b = doc.descendants(0)[1];
        let exc = C14n { exclusive: true, ..Default::default() };
        assert_eq!(String::from_utf8(canonicalize(&doc, b, &exc, None)).unwrap(), r#"<n1:b xmlns:n0="urn:0" xmlns:n1="urn:1" n0:x="1"><c xmlns="urn:d"></c></n1:b>"#);
        // Inclusive renders all in-scope namespaces on the apex.
        assert_eq!(String::from_utf8(canonicalize(&doc, b, &C14n::default(), None)).unwrap(), r#"<n1:b xmlns="urn:d" xmlns:n0="urn:0" xmlns:n1="urn:1" n0:x="1"><c></c></n1:b>"#);
        // Excluding a subtree (enveloped signature).
        let c = doc.descendants(0)[2];
        assert_eq!(String::from_utf8(canonicalize(&doc, b, &exc, Some(c))).unwrap(), r#"<n1:b xmlns:n0="urn:0" xmlns:n1="urn:1" n0:x="1"></n1:b>"#);
    }

    #[test]
    fn keeps_offsets_for_insertion() {
        let xml = "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<a><b/>текст</a>\n";
        let bytes = xml.as_bytes();
        let doc = parse(bytes).unwrap();
        let root = doc.root().unwrap();
        assert!(bytes[doc.nodes[root].end_tag..].starts_with(b"</a>"));
        assert_eq!(doc.text(root), "текст");
        assert!(parse(b"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a/>").is_err());
        assert!(parse(b"<a>&custom;</a>").is_err());
    }
}
