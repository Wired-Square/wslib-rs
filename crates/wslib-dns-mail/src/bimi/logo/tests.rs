use super::*;

const VALID: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="0 0 500 500">
  <title>Example</title>
  <rect x="100" y="100" width="300" height="300" fill="url(#gradient)"/>
</svg>"#;

fn root(extra: &str, body: &str) -> String {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 500" version="1.2" baseProfile="tiny-ps" {extra}><title>Example</title>{body}</svg>"#
    )
}

fn rules(svg: &str) -> Vec<SvgRule> {
    validate_logo(svg.as_bytes())
        .violations
        .iter()
        .map(|v| v.rule)
        .collect()
}

#[test]
fn accepts_conformant_logo() {
    let validation = validate_logo(VALID.as_bytes());
    assert!(validation.is_conformant(), "{:?}", validation.violations);
    assert_eq!(validation.size, VALID.len());
}

#[test]
fn rejects_missing_title() {
    assert_eq!(
        rules(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1" version="1.2" baseProfile="tiny-ps"><rect/></svg>"#
        ),
        [SvgRule::Title]
    );
}

#[test]
fn rejects_script() {
    assert_eq!(
        rules(&root("", "<script>alert(1)</script>")),
        [SvgRule::ProhibitedElement]
    );
}

#[test]
fn rejects_external_image_and_href() {
    assert_eq!(
        rules(&root("", r#"<image href="https://example.com/x.png"/>"#)),
        [SvgRule::ProhibitedElement, SvgRule::ExternalReference]
    );
    assert_eq!(
        rules(&root("", r#"<a href="https://example.com"><rect/></a>"#)),
        [SvgRule::ProhibitedElement, SvgRule::ExternalReference]
    );
}

#[test]
fn rejects_external_url_ref_but_allows_internal() {
    assert_eq!(
        rules(&root("", r#"<rect fill="url(https://example.com/x)"/>"#)),
        [SvgRule::ExternalReference]
    );
    assert_eq!(rules(&root("", r#"<rect fill="url( '#grad' )"/>"#)), []);
}

#[test]
fn rejects_non_square_viewbox_and_xy() {
    let oblong = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 500 250" version="1.2" baseProfile="tiny-ps"><title>X</title></svg>"#;
    assert_eq!(rules(oblong), [SvgRule::AspectRatio]);
    assert_eq!(rules(&root(r#"x="10""#, "")), [SvgRule::RootPosition]);
}

#[test]
fn rejects_wrong_profile() {
    assert_eq!(
        rules(
            r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1" version="1.1"><title>X</title></svg>"#
        ),
        [SvgRule::Version, SvgRule::BaseProfile]
    );
}

#[test]
fn every_rule() {
    for (svg, rule) in [
        (vec![0xff, 0xfe], SvgRule::NotUtf8),
        (root("", "<rect>").into_bytes(), SvgRule::Malformed),
        (
            format!("<!DOCTYPE svg [<!ENTITY x \"y\">]>{}", root("", "")).into_bytes(),
            SvgRule::Doctype,
        ),
        (
            r#"<svg viewBox="0 0 1 1" version="1.2" baseProfile="tiny-ps"><title>X</title></svg>"#.into(),
            SvgRule::Root,
        ),
        (
            r#"<g xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1" version="1.2" baseProfile="tiny-ps"><title>X</title></g>"#.into(),
            SvgRule::Root,
        ),
        (root("", "").replace(r#"version="1.2""#, r#"version="2""#).into_bytes(), SvgRule::Version),
        (root("", "").replace("tiny-ps", "tiny").into_bytes(), SvgRule::BaseProfile),
        (root("", "").replace("<title>Example</title>", "<title> </title>").into_bytes(), SvgRule::Title),
        (root("", "").replace("<title>Example</title>", "<g><title>Nested</title></g>").into_bytes(), SvgRule::Title),
        (root(r#"y="1""#, "").into_bytes(), SvgRule::RootPosition),
        (root(r#"width="100" height="50""#, "").into_bytes(), SvgRule::AspectRatio),
        (root("", "").replace(r#"viewBox="0 0 500 500""#, r#"viewBox="0 0 0 0""#).into_bytes(), SvgRule::AspectRatio),
        (root("", "<animate/>").into_bytes(), SvgRule::ProhibitedElement),
        (root("", "<FILTER/>").into_bytes(), SvgRule::ProhibitedElement),
        (root(r#"onload="x()""#, "").into_bytes(), SvgRule::EventHandler),
        (root("", r##"<use xlink:href="javascript:x()"/>"##).into_bytes(), SvgRule::ExternalReference),
        (root("", r#"<use href="data:image/png;base64,AA"/>"#).into_bytes(), SvgRule::ExternalReference),
        (root("", r#"<rect style="@import 'https://example.com/a.css'"/>"#).into_bytes(), SvgRule::ExternalReference),
    ] {
        let found: Vec<SvgRule> = validate_logo(&svg).violations.iter().map(|v| v.rule).collect();
        assert!(found.contains(&rule), "{rule:?} in {}: {found:?}", String::from_utf8_lossy(&svg));
    }
}

#[test]
fn style_element_text_is_checked() {
    let svg = root(
        "",
        "<style>@import url(https://example.com/a.css); rect { fill: url(#ok) }</style>",
    );
    let validation = validate_logo(svg.as_bytes());
    let details: Vec<Option<&str>> = validation
        .violations
        .iter()
        .map(|v| v.detail.as_deref())
        .collect();
    assert_eq!(
        details,
        [Some("@import"), Some("url(https://example.com/a.css)")]
    );
    assert_eq!(rules(&root("", "<style/><rect fill=\"url(#ok)\"/>")), []);
}

#[test]
fn every_violation_is_reported_not_only_the_first() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" version="1.1" x="0" viewBox="0 0 2 1" onclick="x()"><script/><rect fill="url(https://example.com/x)"/></svg>"#;
    let found = rules(svg);
    for rule in [
        SvgRule::Version,
        SvgRule::BaseProfile,
        SvgRule::RootPosition,
        SvgRule::AspectRatio,
        SvgRule::EventHandler,
        SvgRule::ProhibitedElement,
        SvgRule::ExternalReference,
        SvgRule::Title,
    ] {
        assert!(found.contains(&rule), "{rule:?}: {found:?}");
    }
}

#[test]
fn entities_are_reported_and_never_expanded() {
    let bomb = r#"<!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1" version="1.2" baseProfile="tiny-ps"><title>&b;</title></svg>"#;
    let validation = validate_logo(bomb.as_bytes());
    let doctype = validation
        .violations
        .iter()
        .filter(|v| v.rule == SvgRule::Doctype)
        .count();
    assert_eq!(doctype, 2, "{:?}", validation.violations);
    assert_eq!(validation.size, bomb.len());
    assert_eq!(rules(&root("", "<text>&amp;&#65;&lt;</text>")), []);
}

#[test]
fn offsets_point_into_the_logo() {
    let svg = root("", "<script/>");
    let validation = validate_logo(svg.as_bytes());
    let offset = validation.violations[0].offset.unwrap();
    assert!(svg[offset..].starts_with("<script"), "{}", &svg[offset..]);
}

#[test]
fn violations_display_neutrally() {
    let violation = &validate_logo(root("", "<script/>").as_bytes()).violations[0];
    assert!(
        violation
            .to_string()
            .starts_with("prohibited element: script (at byte "),
        "{violation}"
    );
    assert_eq!(
        SvgRule::BaseProfile.to_string(),
        "root <svg> must declare baseProfile=\"tiny-ps\""
    );
}
