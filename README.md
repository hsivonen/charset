# charset

[![crates.io](https://meritbadge.herokuapp.com/charset)](https://crates.io/crates/charset)
[![docs.rs](https://docs.rs/charset/badge.svg)](https://docs.rs/charset/)
[![Apache-2.0 OR MIT dual-licensed](https://img.shields.io/badge/license-Apache%202%20%2F%20MIT-blue.svg)](https://github.com/hsivonen/charset/blob/master/COPYRIGHT)

`charset` is a wrapper around [`encoding_rs`][1] that provides
(non-streaming) decoding for character encodings that occur in _email_ by
providing decoding for [UTF-7][2] in addition to the encodings defined by
the [Encoding Standard][3] (and provided by `encoding_rs`).

_Note:_ Do _not_ use this crate for consuming _Web_ content. For security
reasons, consumers of Web content are [_prohibited_][4] from supporting
UTF-7. Use `encoding_rs` directly when consuming Web content.

The set of encodings consisting of UTF-7 and the encodings defined in the
Encoding Standard is believed to be appropriate for consuming email,
because that's the set of encodings supported by [Thunderbird][5].
Furthermore, UTF-7 support is believed to be necessary based on the
experience of the Firefox OS email client. In fact, while the UTF-7
implementation in this crate is independent of Thunderbird's UTF-7
implementation, Thunderbird uses `encoding_rs` to decode the other
encodings. The set of _labels_/_aliases_ recognized by this crate
matches those recognized by Thunderbird 60.0. Prior versions of
Thunderbird as well as version 60.4 and later recognize more labels.
Support for those is a TODO item for this crate.

Known compatibility limitations (shared with Thunderbird and known from
Thunderbird bug reports):

 * JavaMail may use non-standard labels for legacy encodings such that
   the labels aren't recognized by this crate even if the encodings
   themselves would be supported. (Fixed in Thunderbird 60.4 but not
   in this crate.)
 * Some ancient Usenet posting in Chinese may not be decodable, because
   this crate does not support HZ.
 * Some emails sent in Chinese by Sun's email client for CDE on Solaris
   around the turn of the millennium may not decodable, because this
   crate does not support ISO-2022-CN.
 * Some emails sent in Korean by IBM/Lotus Notes may not be decodable,
   because this crate does not support ISO-2022-KR.

This crate intentionally does not support encoding content into legacy
encodings. When sending email, _always_ use UTF-8. This is, just call
`.as_bytes()` on `&str` and label the content as `UTF-8`.

[1]: https://crates.io/crates/encoding_rs/
[2]: https://tools.ietf.org/html/rfc2152
[3]: https://encoding.spec.whatwg.org/
[4]: https://html.spec.whatwg.org/#character-encodings
[5]: https://thunderbird.net/

## Licensing

Apache-2.0 OR MIT; please see the file named
[COPYRIGHT](https://github.com/hsivonen/charset/blob/master/COPYRIGHT).

## API Documentation

Generated [API documentation](https://docs.rs/charset/) is available
online.

## Security Considerations

Again, this crate is for _email_. Please do _NOT_ use it for _Web_
content.

Never try to perform any security analysis on the undecoded data in
ASCII-incompatible encodings and in UTF-7 in particular. Always decode
first and analyze after. UTF-7 allows even characters that don't have to
be represented as base64 to be represented as base64. Also, for consistency
with Thunderbird, the UTF-7 decoder in this crate allows e.g. ASCII
controls to be represented without base64 encoding even when the spec
says they should be base64-encoded.

This implementation is non-constant-time by design. An attacker who
can observe input length and the time it takes to decode it can make
guesses about relative proportions of characters from different ranges.
Guessing the proportion of ASCII vs. non-ASCII should be particularly
feasible.

## Serde support

The cargo features `serde` enables Serde support for `Charset`.

## Minimum Rust Version

The MSRV depends on the `encoding_rs` and `base64` dependencies; not on this
crate. This crate does not undergo semver bumps for `base64` semver bumps.

## Disclaimer

This is a personal project. It has a Mozilla copyright notice, because
I copied and pasted from encoding_rs. You should not try to read anything
more into Mozilla's name appearing.

## Release Notes

### 0.1.3

* Update `base64` to 0.13.0.

### 0.1.2

* Implemented `From<&'static Encoding>` for `Charset`.
* Added optional Serde support.

### 0.1.1

* Added `decode_ascii()`.
* Added `decode_latin1()`.

### 0.1.0

Initial release.