//! Where a logo's marks fall once rendered: the BIMI Group's guidance is a
//! centred mark that survives a circle crop, on a solid background.

use usvg::tiny_skia_path::{PathSegment, Point};
use usvg::{Group, Node, Path};

/// What a logo's geometry is measured against, in thousandths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct RenderOptions {
    /// How far the marks' centre may sit from the viewBox's, as thousandths
    /// of its width or height.
    pub off_centre_limit: u32,
    /// How far the marks may reach past the inscribed circle, as thousandths
    /// of its radius.
    pub crop_limit: u32,
}

/// 5% off centre and 2% past the circle.
impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            off_centre_limit: 50,
            crop_limit: 20,
        }
    }
}

/// A logo's geometry, in thousandths so reports stay comparable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LogoGeometry {
    /// How far the centre of the marks' bounding box sits from the viewBox's:
    /// the larger of the horizontal and vertical offsets, as thousandths of
    /// the width and height. `None` with no marks to measure.
    pub off_centre: Option<u32>,
    /// How far the farthest mark reaches past the inscribed circle, as
    /// thousandths of its radius; 0 when everything is inside.
    pub crop_overflow: Option<u32>,
    /// A filled shape covers the whole viewBox.
    pub solid_background: bool,
    /// The logo has `<text>`, which isn't measured: without the font, its
    /// extent is unknown, so the other measurements leave it out.
    pub text: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case", tag = "kind"))]
#[non_exhaustive]
pub enum RenderFailure {
    /// A DOCTYPE, which is refused rather than expanded.
    Doctype,
    Unparsable {
        message: String,
    },
}

impl std::fmt::Display for RenderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Doctype => f.write_str("has a DOCTYPE"),
            Self::Unparsable { message } => write!(f, "can't be rendered: {message}"),
        }
    }
}

/// Measures where an uncompressed SVG's marks fall. Nothing outside the
/// document is loaded: `<image>` references resolve to nothing.
pub fn measure_logo(svg: &[u8]) -> Result<LogoGeometry, RenderFailure> {
    let (doctype, text) = scan(svg);
    if doctype {
        return Err(RenderFailure::Doctype);
    }
    let options = usvg::Options {
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_data(svg, &options).map_err(|error| RenderFailure::Unparsable {
        message: error.to_string(),
    })?;
    let (width, height) = (tree.size().width(), tree.size().height());
    let mut paths = Vec::new();
    collect(tree.root(), &mut paths);
    let (backgrounds, marks): (Vec<&Path>, Vec<&Path>) = paths
        .into_iter()
        .partition(|path| covers(path, width, height));

    let bounds = marks
        .iter()
        .map(|path| path.abs_stroke_bounding_box())
        .reduce(|a, b| {
            usvg::Rect::from_ltrb(
                a.left().min(b.left()),
                a.top().min(b.top()),
                a.right().max(b.right()),
                a.bottom().max(b.bottom()),
            )
            .unwrap_or(a)
        });
    let off_centre = bounds.map(|bounds| {
        let dx = ((bounds.left() + bounds.right()) / 2.0 - width / 2.0).abs() / width;
        let dy = ((bounds.top() + bounds.bottom()) / 2.0 - height / 2.0).abs() / height;
        thousandths(dx.max(dy))
    });
    let centre = Point::from_xy(width / 2.0, height / 2.0);
    let radius = width.min(height) / 2.0;
    let crop_overflow = marks
        .iter()
        .map(|path| reach(path, centre))
        .reduce(f32::max)
        .map(|reach| thousandths(((reach - radius) / radius).max(0.0)));
    Ok(LogoGeometry {
        off_centre,
        crop_overflow,
        solid_background: !backgrounds.is_empty(),
        text,
    })
}

fn thousandths(fraction: f32) -> u32 {
    (fraction * 1000.0).round() as u32
}

/// Whether the document has a DOCTYPE, and whether it has `<text>`.
fn scan(svg: &[u8]) -> (bool, bool) {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(svg);
    let mut buffer = Vec::new();
    let mut text = false;
    loop {
        match reader.read_event_into(&mut buffer) {
            Ok(Event::DocType(_)) => return (true, text),
            Ok(Event::Start(element) | Event::Empty(element)) => {
                text |= element.local_name().as_ref() == b"text";
            }
            Ok(Event::Eof) | Err(_) => return (false, text),
            Ok(_) => {}
        }
        buffer.clear();
    }
}

fn collect<'a>(group: &'a Group, paths: &mut Vec<&'a Path>) {
    for node in group.children() {
        match node {
            Node::Group(group) => collect(group, paths),
            Node::Path(path)
                if path.is_visible() && (path.fill().is_some() || path.stroke().is_some()) =>
            {
                paths.push(path);
            }
            _ => {}
        }
    }
}

/// An opaque fill whose bounds cover the viewBox, give or take half a
/// percent: a background, which the crop is meant to cut.
fn covers(path: &Path, width: f32, height: f32) -> bool {
    let slack = width.max(height) * 0.005;
    let bounds = path.abs_bounding_box();
    path.fill().is_some_and(|fill| fill.opacity().get() >= 1.0)
        && bounds.left() <= slack
        && bounds.top() <= slack
        && bounds.right() >= width - slack
        && bounds.bottom() >= height - slack
}

/// The farthest any point of the path's outline, stroke included, gets
/// from `centre`. Curves are sampled, which is exact enough for a crop.
fn reach(path: &Path, centre: Point) -> f32 {
    const STEPS: u16 = 16;
    let transform = path.abs_transform();
    let stroke = path.stroke().map_or(0.0, |stroke| {
        let (sx, sy) = transform.get_scale();
        stroke.width().get() * sx.max(sy) / 2.0
    });
    let mut points = Vec::new();
    let mut last = Point::zero();
    for segment in path.data().segments() {
        match segment {
            PathSegment::MoveTo(p) | PathSegment::LineTo(p) => {
                points.push(p);
                last = p;
            }
            PathSegment::QuadTo(c, p) => {
                points
                    .extend((1..=STEPS).map(|i| quad(last, c, p, f32::from(i) / f32::from(STEPS))));
                last = p;
            }
            PathSegment::CubicTo(c1, c2, p) => {
                points.extend(
                    (1..=STEPS).map(|i| cubic(last, c1, c2, p, f32::from(i) / f32::from(STEPS))),
                );
                last = p;
            }
            PathSegment::Close => {}
        }
    }
    transform.map_points(&mut points);
    points
        .iter()
        .map(|p| ((p.x - centre.x).powi(2) + (p.y - centre.y).powi(2)).sqrt())
        .fold(0.0, f32::max)
        + stroke
}

fn quad(p0: Point, p1: Point, p2: Point, t: f32) -> Point {
    let u = 1.0 - t;
    Point::from_xy(
        u * u * p0.x + 2.0 * u * t * p1.x + t * t * p2.x,
        u * u * p0.y + 2.0 * u * t * p1.y + t * t * p2.y,
    )
}

fn cubic(p0: Point, p1: Point, p2: Point, p3: Point, t: f32) -> Point {
    let u = 1.0 - t;
    let (a, b, c, d) = (u * u * u, 3.0 * u * u * t, 3.0 * u * t * t, t * t * t);
    Point::from_xy(
        a * p0.x + b * p1.x + c * p2.x + d * p3.x,
        a * p0.y + b * p1.y + c * p2.y + d * p3.y,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svg(body: &str) -> Vec<u8> {
        format!(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">{body}</svg>"#)
            .into_bytes()
    }

    fn measure(body: &str) -> LogoGeometry {
        measure_logo(&svg(body)).unwrap()
    }

    const BACKGROUND: &str = r##"<rect width="100" height="100" fill="#fff"/>"##;

    #[test]
    fn a_centred_mark_on_a_background_measures_clean() {
        let geometry = measure(&format!(r#"{BACKGROUND}<circle cx="50" cy="50" r="30"/>"#));
        assert_eq!(geometry.off_centre, Some(0));
        assert_eq!(geometry.crop_overflow, Some(0));
        assert!(geometry.solid_background);
        assert!(!geometry.text);
    }

    #[test]
    fn an_offset_mark_is_off_centre() {
        let geometry = measure(r#"<circle cx="60" cy="50" r="20"/>"#);
        assert_eq!(geometry.off_centre, Some(100));
        assert!(!geometry.solid_background);
    }

    #[test]
    fn a_square_mark_to_the_edges_overflows_the_circle() {
        let geometry = measure(r#"<rect x="10" y="10" width="80" height="80"/>"#);
        // The corners are 40√2 from the centre against a radius of 50.
        assert_eq!(geometry.crop_overflow, Some(131));
        let stroked = measure(
            r##"<circle cx="50" cy="50" r="48" fill="none" stroke="#000" stroke-width="8"/>"##,
        );
        assert_eq!(stroked.crop_overflow, Some(40));
    }

    #[test]
    fn transforms_and_viewbox_scaling_are_applied() {
        let geometry = measure_logo(
            br#"<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200" viewBox="0 0 100 100"><g transform="translate(10 0)"><circle cx="50" cy="50" r="20"/></g></svg>"#,
        )
        .unwrap();
        assert_eq!(geometry.off_centre, Some(100));
    }

    #[test]
    fn a_translucent_full_rect_is_not_a_background() {
        let geometry =
            measure(r##"<rect width="100" height="100" fill="#fff" fill-opacity="0.5"/>"##);
        assert!(!geometry.solid_background);
    }

    #[test]
    fn text_is_flagged_and_nothing_else_is_measured() {
        let geometry = measure(r#"<text x="0" y="50">Example</text>"#);
        assert!(geometry.text);
        assert_eq!(geometry.off_centre, None);
    }

    #[test]
    fn doctypes_and_external_images_are_refused() {
        assert_eq!(
            measure_logo(
                br#"<!DOCTYPE svg [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg"/>"#
            ),
            Err(RenderFailure::Doctype)
        );
        let geometry = measure(r#"<image href="/etc/hosts" width="100" height="100"/>"#);
        assert_eq!(geometry.off_centre, None);
    }
}
