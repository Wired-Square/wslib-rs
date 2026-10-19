//! Checking a BIMI logo against the SVG Tiny Portable/Secure profile
//! (draft-svg-tiny-ps-abrotman), the parts mailbox providers enforce.

use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;

const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";

/// The BIMI Group's guidance for a logo's size, in bytes.
pub const LOGO_SIZE_GUIDANCE: usize = 32 * 1024;

/// How far a `viewBox` may be from square, in user units.
const SQUARE_TOLERANCE: f64 = 0.5;

/// Scripting, hyperlinks, raster and foreign content, animation, embedded
/// media and filters, compared without case against the local name.
const PROHIBITED_ELEMENTS: &[&str] = &[
    "script",
    "a",
    "image",
    "foreignobject",
    "animate",
    "animatemotion",
    "animatetransform",
    "animatecolor",
    "set",
    "video",
    "audio",
    "iframe",
    "filter",
];

/// Every way a logo breaks the profile, and its decompressed size.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct LogoValidation {
    pub violations: Vec<SvgViolation>,
    pub size: usize,
}

impl LogoValidation {
    pub fn is_conformant(&self) -> bool {
        self.violations.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SvgViolation {
    pub rule: SvgRule,
    /// A byte offset into the logo, where the parser knows one.
    pub offset: Option<usize>,
    /// The element, attribute or value concerned.
    pub detail: Option<String>,
}

/// A rule of the profile. The serialised names are stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SvgRule {
    NotUtf8,
    /// Not well-formed XML; nothing after the fault is checked.
    Malformed,
    /// A `<!DOCTYPE>`, entity declaration or entity reference.
    Doctype,
    /// The root isn't `<svg>` in the SVG namespace.
    Root,
    Version,
    BaseProfile,
    /// No non-empty `<title>` directly under the root.
    Title,
    /// `x` or `y` on the root.
    RootPosition,
    /// The `viewBox`, or `width` and `height`, aren't square.
    AspectRatio,
    ProhibitedElement,
    /// An `on*` attribute.
    EventHandler,
    /// A link, `url()` or `@import` to anything but a `#fragment`.
    ExternalReference,
}

/// Neutral wording for the rule; consumers may write their own.
impl std::fmt::Display for SvgRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NotUtf8 => "not UTF-8",
            Self::Malformed => "not well-formed XML",
            Self::Doctype => "DOCTYPE or entities are not allowed",
            Self::Root => "the root must be <svg> in the SVG namespace",
            Self::Version => "root <svg> must declare version=\"1.2\"",
            Self::BaseProfile => "root <svg> must declare baseProfile=\"tiny-ps\"",
            Self::Title => "a non-empty <title> must be a direct child of the root",
            Self::RootPosition => "root <svg> must not set x or y",
            Self::AspectRatio => "the viewBox (and width and height) must be square",
            Self::ProhibitedElement => "prohibited element",
            Self::EventHandler => "event handler attribute",
            Self::ExternalReference => "external reference",
        })
    }
}

impl std::fmt::Display for SvgViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.rule)?;
        if let Some(detail) = &self.detail {
            write!(f, ": {detail}")?;
        }
        if let Some(offset) = self.offset {
            write!(f, " (at byte {offset})")?;
        }
        Ok(())
    }
}

/// Checks an uncompressed SVG logo and reports every violation found.
pub fn validate_logo(svg: &[u8]) -> LogoValidation {
    let mut check = Check::default();
    match std::str::from_utf8(svg) {
        Ok(text) => check.run(text),
        Err(error) => check.flag(SvgRule::NotUtf8, Some(error.valid_up_to()), None),
    }
    LogoValidation {
        violations: check.violations,
        size: svg.len(),
    }
}

#[derive(Default)]
struct Check {
    violations: Vec<SvgViolation>,
    depth: usize,
    seen_root: bool,
    seen_title: bool,
    /// Text of a `<title>` directly under the root, while it's open.
    title: Option<String>,
    in_style: bool,
}

impl Check {
    fn flag(&mut self, rule: SvgRule, offset: Option<usize>, detail: Option<String>) {
        self.violations.push(SvgViolation {
            rule,
            offset,
            detail,
        });
    }

    fn run(&mut self, text: &str) {
        let mut reader = Reader::from_str(text);
        loop {
            let offset = usize::try_from(reader.buffer_position()).ok();
            let event = match reader.read_event() {
                Ok(event) => event,
                Err(error) => {
                    let at = usize::try_from(reader.error_position()).ok();
                    self.flag(SvgRule::Malformed, at, Some(error.to_string()));
                    break;
                }
            };
            match event {
                Event::Eof => break,
                Event::DocType(_) => self.flag(SvgRule::Doctype, offset, None),
                Event::GeneralRef(reference) => {
                    let name = String::from_utf8_lossy(&reference).into_owned();
                    let predefined = matches!(name.as_str(), "amp" | "lt" | "gt" | "quot" | "apos");
                    if !predefined && !reference.is_char_ref() {
                        self.flag(SvgRule::Doctype, offset, Some(format!("&{name};")));
                    }
                }
                Event::Start(element) => {
                    self.element(&element, offset);
                    self.depth += 1;
                }
                Event::Empty(element) => {
                    self.element(&element, offset);
                    let name = local(element.name().as_ref());
                    if self.depth == 1 && name == "title" {
                        self.title = None;
                    }
                    if name == "style" {
                        self.in_style = false;
                    }
                }
                Event::End(element) => {
                    self.depth = self.depth.saturating_sub(1);
                    let name = local(element.name().as_ref());
                    if name == "title" && self.depth == 1 {
                        let text = self.title.take().unwrap_or_default();
                        self.seen_title |= !text.trim().is_empty();
                    }
                    if name == "style" {
                        self.in_style = false;
                    }
                }
                Event::Text(text) => {
                    let text = String::from_utf8_lossy(&text).into_owned();
                    self.text(&text, offset);
                }
                Event::CData(text) => {
                    let text = String::from_utf8_lossy(&text).into_owned();
                    self.text(&text, offset);
                }
                _ => {}
            }
        }
        if !self.seen_root {
            self.flag(SvgRule::Root, None, Some("no root element".into()));
        }
        if !self.seen_title {
            self.flag(SvgRule::Title, None, None);
        }
    }

    fn text(&mut self, text: &str, offset: Option<usize>) {
        if let Some(title) = &mut self.title {
            title.push_str(text);
        }
        if self.in_style {
            self.css(text, offset);
        }
    }

    fn element(&mut self, element: &BytesStart<'_>, offset: Option<usize>) {
        let name = local(element.name().as_ref());
        if !self.seen_root {
            self.seen_root = true;
            self.root(element, &name, offset);
        } else if PROHIBITED_ELEMENTS.contains(&name.as_str()) {
            self.flag(SvgRule::ProhibitedElement, offset, Some(name.clone()));
        }
        if self.depth == 1 && name == "title" {
            self.title = Some(String::new());
        }
        if name == "style" {
            self.in_style = true;
        }
        for attribute in element.attributes().with_checks(false).flatten() {
            let key = local(attribute.key.as_ref());
            let value = String::from_utf8_lossy(&attribute.value).into_owned();
            if key.starts_with("on") {
                self.flag(SvgRule::EventHandler, offset, Some(key.clone()));
            }
            if key == "href" && !value.trim().starts_with('#') {
                self.flag(SvgRule::ExternalReference, offset, Some(value.clone()));
            }
            self.css(&value, offset);
        }
    }

    /// `url()` and `@import` in a `style` attribute, a presentation
    /// attribute such as `fill`, or a `<style>` element's text.
    fn css(&mut self, value: &str, offset: Option<usize>) {
        let lower = value.to_ascii_lowercase();
        if lower.contains("@import") {
            self.flag(SvgRule::ExternalReference, offset, Some("@import".into()));
        }
        for (at, _) in lower.match_indices("url(") {
            let target = lower[at + 4..].trim_start().trim_start_matches(['\'', '"']);
            if !target.starts_with('#') {
                let end = target.find(')').unwrap_or(target.len());
                self.flag(
                    SvgRule::ExternalReference,
                    offset,
                    Some(format!("url({})", &target[..end])),
                );
            }
        }
    }

    fn root(&mut self, element: &BytesStart<'_>, name: &str, offset: Option<usize>) {
        let raw = String::from_utf8_lossy(element.name().as_ref()).into_owned();
        let prefix = raw.split_once(':').map(|(prefix, _)| prefix.to_owned());
        let namespace_attribute =
            prefix.map_or("xmlns".to_owned(), |prefix| format!("xmlns:{prefix}"));
        let attribute = |key: &str| {
            element
                .attributes()
                .with_checks(false)
                .flatten()
                .find(|a| a.key.as_ref() == key.as_bytes())
                .map(|a| String::from_utf8_lossy(&a.value).trim().to_owned())
        };
        let local_attribute = |key: &str| {
            element
                .attributes()
                .with_checks(false)
                .flatten()
                .find(|a| local(a.key.as_ref()) == key)
                .map(|a| String::from_utf8_lossy(&a.value).trim().to_owned())
        };
        if name != "svg" || attribute(&namespace_attribute).as_deref() != Some(SVG_NAMESPACE) {
            self.flag(SvgRule::Root, offset, Some(raw));
        }
        if local_attribute("version").as_deref() != Some("1.2") {
            self.flag(SvgRule::Version, offset, local_attribute("version"));
        }
        if !local_attribute("baseprofile")
            .is_some_and(|profile| profile.eq_ignore_ascii_case("tiny-ps"))
        {
            self.flag(SvgRule::BaseProfile, offset, local_attribute("baseprofile"));
        }
        for position in ["x", "y"] {
            if local_attribute(position).is_some() {
                self.flag(SvgRule::RootPosition, offset, Some(position.into()));
            }
        }
        match local_attribute("viewbox") {
            None => self.flag(SvgRule::AspectRatio, offset, Some("no viewBox".into())),
            Some(view_box) => {
                if let Err(problem) = square_view_box(&view_box) {
                    self.flag(SvgRule::AspectRatio, offset, Some(problem));
                }
            }
        }
        if let (Some(width), Some(height)) = (local_attribute("width"), local_attribute("height"))
            && !same_length(&width, &height)
        {
            self.flag(
                SvgRule::AspectRatio,
                offset,
                Some(format!("width {width}, height {height}")),
            );
        }
    }
}

fn square_view_box(view_box: &str) -> Result<(), String> {
    let numbers: Vec<f64> = view_box
        .split([' ', ',', '\t', '\n'])
        .filter(|part| !part.is_empty())
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| format!("viewBox {view_box:?} isn't numeric"))?;
    let [_, _, width, height] = numbers[..] else {
        return Err(format!("viewBox {view_box:?} needs four numbers"));
    };
    if width <= 0.0 || height <= 0.0 {
        return Err(format!("viewBox {view_box:?} has no area"));
    }
    if (width - height).abs() > SQUARE_TOLERANCE {
        return Err(format!("viewBox {view_box:?} isn't square"));
    }
    Ok(())
}

/// Whether two lengths are equal: the same unit and a number within the
/// tolerance, or the same text.
fn same_length(width: &str, height: &str) -> bool {
    let split = |length: &str| {
        let unit_at = length
            .find(|c: char| c.is_ascii_alphabetic() || c == '%')
            .unwrap_or(length.len());
        let (number, unit) = length.split_at(unit_at);
        (
            number.trim().parse::<f64>().ok(),
            unit.trim().to_ascii_lowercase(),
        )
    };
    match (split(width), split(height)) {
        ((Some(w), wu), (Some(h), hu)) => wu == hu && (w - h).abs() <= SQUARE_TOLERANCE,
        _ => width.eq_ignore_ascii_case(height),
    }
}

/// The lowercased local part of an element or attribute name.
fn local(name: &[u8]) -> String {
    let local = name.rsplit(|&b| b == b':').next().unwrap_or(name);
    String::from_utf8_lossy(local).to_ascii_lowercase()
}

#[cfg(test)]
mod tests;
