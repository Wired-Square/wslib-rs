use wslib_secret::Secret;

use crate::{Error, Op, Runner};

/// Whether `value` is an `op://` secret reference rather than a value.
pub fn is_reference(value: &str) -> bool {
    value.starts_with("op://")
}

/// Something that reads a secret reference as text: an [`Op`], or a closure in tests.
pub trait ReadReference {
    fn read_reference(&self, reference: &str) -> Result<Secret, Error>;
}

impl<F: Fn(&str) -> Result<Secret, Error>> ReadReference for F {
    fn read_reference(&self, reference: &str) -> Result<Secret, Error> {
        self(reference)
    }
}

impl<R: Runner> ReadReference for Op<R> {
    fn read_reference(&self, reference: &str) -> Result<Secret, Error> {
        self.read(reference)?.into_text()
    }
}

/// `value` itself, or what it refers to when it is a secret reference.
pub fn resolve(reader: &impl ReadReference, value: &str) -> Result<Secret, Error> {
    if is_reference(value) {
        reader.read_reference(value)
    } else {
        Ok(Secret::new(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(reference: &str) -> Result<Secret, Error> {
        match reference {
            "op://ci/forge/token" => Ok(Secret::new("s3cret")),
            _ => Err(Error::ItemNotFound(format!("{reference} isn't an item"))),
        }
    }

    #[test]
    fn a_reference_is_read() {
        assert_eq!(
            resolve(&vault, "op://ci/forge/token").unwrap().expose(),
            "s3cret"
        );
    }

    #[test]
    fn a_plain_value_is_passed_through_unread() {
        let never = |_: &str| -> Result<Secret, Error> { panic!("read a plain value") };
        assert_eq!(resolve(&never, "hunter2").unwrap().expose(), "hunter2");
    }

    #[test]
    fn a_failed_read_names_the_reference() {
        let error = resolve(&vault, "op://ci/gone/token").unwrap_err();
        assert_eq!(
            error.to_string(),
            "item not found: op://ci/gone/token isn't an item"
        );
    }
}
