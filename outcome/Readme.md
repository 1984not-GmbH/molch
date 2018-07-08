master branch unit test status: Linux & MacOS: [![Build Status](https://travis-ci.org/ned14/outcome.svg?branch=master)](https://travis-ci.org/ned14/outcome) Windows: [![Build status](https://ci.appveyor.com/api/projects/status/q8s29koot2v3nity/branch/master?svg=true)](https://ci.appveyor.com/project/ned14/outcome/branch/master)

develop branch unit test status: Linux & MacOS: [![Build Status](https://travis-ci.org/ned14/outcome.svg?branch=develop)](https://travis-ci.org/ned14/outcome) Windows: [![Build status](https://ci.appveyor.com/api/projects/status/q8s29koot2v3nity/branch/develop?svg=true)](https://ci.appveyor.com/project/ned14/outcome/branch/develop)

CTest dashboard: http://my.cdash.org/index.php?project=Boost.Outcome

Documentation: https://ned14.github.io/outcome/


## Purpose of this library

Outcome is a C++14 library for reporting and handling function failures. It can be used as a substitute for, or a complement to, the exception handling mechanism.

One use case is for contexts where using C++ exception handling is unsuitable for different reasons:

 * The high relative cost of throwing and catching a C++ exception.
 * Making some or all control paths explicitly detailed to aid code correctness auditing, as opposed to having hidden control paths caused by exceptions potentially thrown from any place.
 * Company policy to compile with exceptions disabled.
 * Maintaining a code base that was never designed with exception-safety in mind.
 * Parts of the programs/frameworks that themselves implement exception handling and cannot afford to use exceptions, like propagating failure reports across threads, tasks, fibers…


## Usage as a single header file

Outcome v2 comes in single header file form. This is regenerated per commit. To fetch
on Linux:

```
wget https://github.com/ned14/outcome/raw/develop/single-header/outcome.hpp
```

On BSD and OS X:

```
fetch https://github.com/ned14/outcome/raw/develop/single-header/outcome.hpp
```

On Windows, simply download the raw file from above and place it wherever it suits you.

## Pre Boost entry todo:

 - [x] Raise ABI compliance checker on CI.
 - [ ] Fix up the .natvis file, and permanently solve the permuting SHA issue.
 - [ ] Fix up the C interface to use `status_code`.

## Commits and tags in this git repository can be verified using:
<pre>
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mDMEVvMacRYJKwYBBAHaRw8BAQdAp+Qn6djfxWQYtAEvDmv4feVmGALEQH/pYpBC
llaXNQe0WE5pYWxsIERvdWdsYXMgKHMgW3VuZGVyc2NvcmVdIHNvdXJjZWZvcmdl
IHthdH0gbmVkcHJvZCBbZG90XSBjb20pIDxzcGFtdHJhcEBuZWRwcm9kLmNvbT6I
eQQTFggAIQUCVvMacQIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRCELDV4
Zvkgx4vwAP9gxeQUsp7ARMFGxfbR0xPf6fRbH+miMUg2e7rYNuHtLQD9EUoR32We
V8SjvX4r/deKniWctvCi5JccgfUwXkVzFAk=
=puFk
-----END PGP PUBLIC KEY BLOCK-----
</pre>

</center>
