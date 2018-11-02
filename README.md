# HazExpired

HazExpired is a Go package that provides simple functions to check if a remote system has expired certificates within it's chain.

## Usage

```go
import hazexpired

check, err := hazexpired.Expired("example.com:443")
if err != nil {
  // do something
}

if check {
  // do something because the certificate is expired
}
```
