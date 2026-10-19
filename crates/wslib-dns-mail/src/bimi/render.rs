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
    /// An opaque fill covers all four corners of the viewBox.
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
    let text = scan(svg)?;
    let options = usvg::Options {
        image_href_resolver: usvg::ImageHrefResolver {
            resolve_data: Box::new(|_, _, _| None),
            resolve_string: Box::new(|_, _| None),
        },
        ..usvg::Options::default()
    };
    let tree = usvg::Tree::from_data(svg, &options).map_err(unparsable)?;
    let size = tree.size();
    let canvas = Canvas {
        corners: inset_corners(size.width(), size.height()),
        centre: Point::from_xy(size.width() / 2.0, size.height() / 2.0),
        radius: size.width().min(size.height()) / 2.0,
    };
    let mut shapes = Vec::new();
    collect(tree.root(), None, &canvas, &mut shapes);
    let (backgrounds, marks): (Vec<&Shape>, Vec<&Shape>) = shapes
        .iter()
        .partition(|shape| shape.is_background(&canvas));

    let off_centre = marks
        .iter()
        .filter_map(|shape| shape.bounds())
        .reduce(union)
        .map(|bounds| {
            let dx =
                ((bounds.left() + bounds.right()) / 2.0 - canvas.centre.x).abs() / size.width();
            let dy =
                ((bounds.top() + bounds.bottom()) / 2.0 - canvas.centre.y).abs() / size.height();
            thousandths(dx.max(dy))
        });
    let crop_overflow = marks
        .iter()
        .map(|shape| shape.reach(canvas.centre))
        .reduce(f32::max)
        .map(|reach| thousandths(((reach - canvas.radius) / canvas.radius).max(0.0)));
    Ok(LogoGeometry {
        off_centre,
        crop_overflow,
        solid_background: !backgrounds.is_empty(),
        text,
    })
}

fn unparsable(error: impl std::fmt::Display) -> RenderFailure {
    RenderFailure::Unparsable {
        message: error.to_string(),
    }
}

fn thousandths(fraction: f32) -> u32 {
    (fraction * 1000.0).round() as u32
}

/// Whether the document has `<text>`. A DOCTYPE is refused, and so is
/// anything the scan can't read, so usvg (which expands DTDs) never sees one.
fn scan(svg: &[u8]) -> Result<bool, RenderFailure> {
    use quick_xml::events::Event;
    let mut reader = quick_xml::Reader::from_reader(svg);
    let mut buffer = Vec::new();
    let mut text = false;
    loop {
        match reader.read_event_into(&mut buffer).map_err(unparsable)? {
            Event::DocType(_) => return Err(RenderFailure::Doctype),
            Event::Start(element) | Event::Empty(element) => {
                text |= element.local_name().as_ref() == b"text";
            }
            Event::Eof => return Ok(text),
            _ => {}
        }
        buffer.clear();
    }
}

struct Canvas {
    /// The viewBox corners, half a percent in, so a shape drawn exactly to
    /// the edge covers them.
    corners: [Point; 4],
    centre: Point,
    radius: f32,
}

fn inset_corners(width: f32, height: f32) -> [Point; 4] {
    let slack = width.max(height) * 0.005;
    let (left, top, right, bottom) = (slack, slack, width - slack, height - slack);
    [
        Point::from_xy(left, top),
        Point::from_xy(right, top),
        Point::from_xy(right, bottom),
        Point::from_xy(left, bottom),
    ]
}

/// The clip-paths a shape is drawn under, merged: the bounds of their
/// outlines, how far those reach from the centre, and whether they leave all
/// four corners showing.
#[derive(Clone, Copy)]
struct Clip {
    bounds: usvg::Rect,
    reach: f32,
    covers_corners: bool,
}

struct Shape<'a> {
    path: &'a Path,
    outline: Vec<Vec<Point>>,
    clip: Option<Clip>,
}

impl Shape<'_> {
    /// An opaque fill that, after its clip, covers every corner: a
    /// background, which the crop is meant to cut.
    fn is_background(&self, canvas: &Canvas) -> bool {
        self.path.fill().is_some_and(|fill| {
            fill.opacity().get() >= 1.0
                && canvas
                    .corners
                    .iter()
                    .all(|&corner| contains(&self.outline, corner, fill.rule()))
        }) && self.clip.is_none_or(|clip| clip.covers_corners)
    }

    fn bounds(&self) -> Option<usvg::Rect> {
        let bounds = self.path.abs_stroke_bounding_box();
        match self.clip {
            Some(clip) => bounds.intersect(&clip.bounds),
            None => Some(bounds),
        }
    }

    /// The farthest any point of the outline, stroke included, gets from
    /// `centre`. Under a clip, that's at most the clip's own reach, and at
    /// most the outline held within the clip's bounds (with any of their
    /// corners the shape covers).
    fn reach(&self, centre: Point) -> f32 {
        let stroke = self.path.stroke().map_or(0.0, |stroke| {
            let (sx, sy) = self.path.abs_transform().get_scale();
            stroke.width().get() * sx.max(sy) / 2.0
        });
        let Some(clip) = self.clip else {
            return farthest(self.outline.iter().flatten().copied(), centre) + stroke;
        };
        let (bounds, rule) = (clip.bounds, usvg::FillRule::NonZero);
        let held = self.outline.iter().flatten().map(|p| {
            Point::from_xy(
                p.x.clamp(bounds.left(), bounds.right()),
                p.y.clamp(bounds.top(), bounds.bottom()),
            )
        });
        let covered = corners(bounds)
            .into_iter()
            .filter(|&corner| contains(&self.outline, corner, rule));
        (farthest(held.chain(covered), centre) + stroke).min(clip.reach)
    }
}

fn collect<'a>(group: &'a Group, clip: Option<Clip>, canvas: &Canvas, shapes: &mut Vec<Shape<'a>>) {
    let clip = match (
        clip,
        group.clip_path().map(|path| clip_of(group, path, canvas)),
    ) {
        (Some(outer), Some(inner)) => Some(Clip {
            bounds: outer
                .bounds
                .intersect(&inner.bounds)
                .unwrap_or(inner.bounds),
            reach: outer.reach.min(inner.reach),
            covers_corners: outer.covers_corners && inner.covers_corners,
        }),
        (outer, inner) => inner.or(outer),
    };
    for node in group.children() {
        match node {
            Node::Group(group) => collect(group, clip, canvas, shapes),
            Node::Path(path)
                if path.is_visible() && (path.fill().is_some() || path.stroke().is_some()) =>
            {
                shapes.push(Shape {
                    path,
                    outline: outline(path, path.abs_transform()),
                    clip,
                });
            }
            _ => {}
        }
    }
}

/// A clip-path's outlines in canvas space. Its own clip-path, if any, is
/// ignored.
fn clip_of(group: &Group, clip: &usvg::ClipPath, canvas: &Canvas) -> Clip {
    let base = group.abs_transform().pre_concat(clip.transform());
    let mut paths = Vec::new();
    clip_paths(clip.root(), &mut paths);
    let outlines: Vec<Vec<Vec<Point>>> = paths
        .iter()
        .map(|path| outline(path, base.pre_concat(path.abs_transform())))
        .collect();
    let points = || outlines.iter().flatten().flatten();
    let (left, top, right, bottom) = points().fold(
        (f32::MAX, f32::MAX, f32::MIN, f32::MIN),
        |(left, top, right, bottom), p| {
            (left.min(p.x), top.min(p.y), right.max(p.x), bottom.max(p.y))
        },
    );
    // A clip with no outline hides everything; a point at the centre says so.
    let bounds = usvg::Rect::from_ltrb(left, top, right, bottom).unwrap_or_else(|| {
        usvg::Rect::from_xywh(canvas.centre.x, canvas.centre.y, 0.0, 0.0).expect("a point")
    });
    let covers_corners = paths.iter().zip(&outlines).any(|(path, outline)| {
        let rule = path
            .fill()
            .map_or(usvg::FillRule::NonZero, |fill| fill.rule());
        canvas
            .corners
            .iter()
            .all(|&corner| contains(outline, corner, rule))
    });
    Clip {
        bounds,
        reach: farthest(points().copied(), canvas.centre),
        covers_corners,
    }
}

fn clip_paths<'a>(group: &'a Group, paths: &mut Vec<&'a Path>) {
    for node in group.children() {
        match node {
            Node::Group(group) => clip_paths(group, paths),
            Node::Path(path) => paths.push(path),
            _ => {}
        }
    }
}

fn union(a: usvg::Rect, b: usvg::Rect) -> usvg::Rect {
    usvg::Rect::from_ltrb(
        a.left().min(b.left()),
        a.top().min(b.top()),
        a.right().max(b.right()),
        a.bottom().max(b.bottom()),
    )
    .unwrap_or(a)
}

fn corners(rect: usvg::Rect) -> [Point; 4] {
    [
        Point::from_xy(rect.left(), rect.top()),
        Point::from_xy(rect.right(), rect.top()),
        Point::from_xy(rect.right(), rect.bottom()),
        Point::from_xy(rect.left(), rect.bottom()),
    ]
}

fn farthest(points: impl IntoIterator<Item = Point>, centre: Point) -> f32 {
    points
        .into_iter()
        .map(|p| ((p.x - centre.x).powi(2) + (p.y - centre.y).powi(2)).sqrt())
        .fold(0.0, f32::max)
}

/// The path's subpaths as polygons under `transform`, curves sampled.
fn outline(path: &Path, transform: usvg::Transform) -> Vec<Vec<Point>> {
    const STEPS: u16 = 16;
    let steps = || (1..=STEPS).map(|i| f32::from(i) / f32::from(STEPS));
    let mut subpaths: Vec<Vec<Point>> = Vec::new();
    let mut last = Point::zero();
    for segment in path.data().segments() {
        match segment {
            PathSegment::MoveTo(p) => {
                subpaths.push(vec![p]);
                last = p;
            }
            PathSegment::LineTo(p) => {
                push(&mut subpaths, [p]);
                last = p;
            }
            PathSegment::QuadTo(c, p) => {
                push(&mut subpaths, steps().map(|t| quad(last, c, p, t)));
                last = p;
            }
            PathSegment::CubicTo(c1, c2, p) => {
                push(&mut subpaths, steps().map(|t| cubic(last, c1, c2, p, t)));
                last = p;
            }
            PathSegment::Close => {}
        }
    }
    for subpath in &mut subpaths {
        transform.map_points(subpath);
    }
    subpaths
}

fn push(subpaths: &mut Vec<Vec<Point>>, points: impl IntoIterator<Item = Point>) {
    if subpaths.is_empty() {
        subpaths.push(Vec::new());
    }
    subpaths.last_mut().expect("just ensured").extend(points);
}

/// Whether `point` is inside the polygons, by `rule`.
fn contains(subpaths: &[Vec<Point>], point: Point, rule: usvg::FillRule) -> bool {
    let mut winding = 0i32;
    for polygon in subpaths {
        for (i, &a) in polygon.iter().enumerate() {
            let b = polygon[(i + 1) % polygon.len()];
            if (a.y <= point.y) != (b.y <= point.y) {
                let x = a.x + (point.y - a.y) / (b.y - a.y) * (b.x - a.x);
                if x > point.x {
                    winding += if b.y > a.y { 1 } else { -1 };
                }
            }
        }
    }
    match rule {
        usvg::FillRule::NonZero => winding != 0,
        usvg::FillRule::EvenOdd => winding % 2 != 0,
    }
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
    fn a_full_size_roundel_is_a_mark_not_a_background() {
        let geometry = measure(r#"<circle cx="50" cy="50" r="50"/>"#);
        assert!(!geometry.solid_background);
        assert_eq!(geometry.crop_overflow, Some(0));
        let rounded = measure(r#"<rect width="100" height="100" rx="20"/>"#);
        assert!(!rounded.solid_background);
        let holed =
            measure(r#"<path fill-rule="evenodd" d="M0 0H100V100H0Z M-10 -10H10V10H-10Z"/>"#);
        assert!(!holed.solid_background);
    }

    #[test]
    fn an_artboard_clip_bounds_what_is_measured() {
        let geometry = measure(
            r##"<clipPath id="a"><rect width="100" height="100"/></clipPath><g clip-path="url(#a)"><rect width="100" height="100" fill="#fff"/><rect x="-10" y="40" width="120" height="20"/></g>"##,
        );
        assert!(geometry.solid_background);
        assert_eq!(geometry.off_centre, Some(0));
        // The bar, held to the artboard, ends at (0, 40): √(50² + 10²) ≈ 51.
        assert_eq!(geometry.crop_overflow, Some(20));
    }

    #[test]
    fn a_square_clipped_to_a_circle_is_a_roundel() {
        let geometry = measure(
            r##"<clipPath id="c"><circle cx="50" cy="50" r="50"/></clipPath><rect width="100" height="100" fill="#000" clip-path="url(#c)"/>"##,
        );
        assert!(!geometry.solid_background);
        assert_eq!(geometry.crop_overflow, Some(0));
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
        assert!(matches!(
            measure_logo(b"<svg xmlns='http://www.w3.org/2000/svg'><g></svg>"),
            Err(RenderFailure::Unparsable { .. })
        ));
    }
}
