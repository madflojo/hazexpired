# HazExpired

HazExpired is a Go package that provides simple functions to check if a remote system has expired certificates within it's chain.

[![Build Status](https://travis-ci.org/madflojo/hazexpired.svg?branch=master)](https://travis-ci.org/madflojo/hazexpired)

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

For more detailed usage please consult the [GoDocs](https://godoc.org/github.com/madflojo/hazexpired)
