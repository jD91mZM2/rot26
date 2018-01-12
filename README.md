# [rot26](http://rot26.org/) [![Crates.io](https://img.shields.io/crates/v/rot26.svg)]()

> ROT13 ("rotate by 13 places", sometimes hyphenated ROT-13) is a letter substitution cipher that replaces a letter with the letter 13 letters after it in the alphabet.
> Instead of only rotating 13 places, ROT26 rotates twice as many characters in the alphabet and is therefore twice as secure.

Pure rust rewrite of the rot26 algorithm.  
Even maintains support for rot13 and *any* rot, with friendly helpful comments advising you to just stick to rot26.

> ROT26 encryption & decryption is very complex and requires a powerful, purpose-built super-computer to perform all the calculations... which we have created.
> So, to encourage more developers to use ROT26 in their mobile, web and PC software applications we are offering a very easy to use and totally free ROT26 encryption and decryption REST web service.

This is no longer true.  
That and all the following are features now possible thanks to Rust:

 - Complete unicode support. Disregards any non-alphabetical symbols! (was probably possible before actually)
 - Unit tests.

# Examples

Simply call `rot26::encrypt` on any string. For example:

```Rust
rot26::encrypt("hello") // returns "hello"
```

to decrypt, use `rot26::decrypt`

```Rust
rot26::decrypt("hello") // returns "hello"
```
