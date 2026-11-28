# Changelog

## 0.1.0

- `Chain`: an error and each cause its `source()` gives, displayed as one
  line with `: ` between layers. A cause is left out when it says nothing,
  or when the line so far is that cause or ends with `: ` and it, so an
  error that writes its cause and also returns it reads once.
