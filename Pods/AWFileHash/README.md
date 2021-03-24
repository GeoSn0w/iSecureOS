# AWFileHash

[![CI Status](https://travis-ci.org/leetal/AWFileHash.svg?branch=master)](https://travis-ci.org/leetal/AWFileHash)
[![Version](https://img.shields.io/cocoapods/v/AWFileHash.svg?style=flat)](http://cocoadocs.org/docsets/AWFileHash)
[![License](https://img.shields.io/cocoapods/l/AWFileHash.svg?style=flat)](http://cocoadocs.org/docsets/AWFileHash)
[![Platform](https://img.shields.io/cocoapods/p/AWFileHash.svg?style=flat)](http://cocoadocs.org/docsets/AWFileHash)

A security library that supports md5, sha1 and sha512 hashes. Performs all calculations chunked to reduce memory impact (does not apply to PHAsset as of now).

Returns a hex of the result.

## Requirements

iOS5+ is required. If using cocoapods, min version in podfile is iOS7. For PHAsset support iOS8+ is required.

## Usage/Examples
```objectivec
// Filepath (file accessible on disk)
NSString *_filePath = ...
NSString *md5 = [AWFileHash md5HashOfFileAtPath:_filePath]

// NSData
NSData *_data = [NSData dataWithBytes:"AWFileHash" length:10];
NSString *md5 = [AWFileHash md5HashOfData:_data];

// ALAssetRepresentation
ALAsset *_asset = ...
ALAssetRepresentation *_assetRep = [_asset defaultRepresentation];
NSString *md5 = [AWFileHash md5HashOfALAssetRepresentation:_assetRep];
```

For SHA1 or SHA512 support, just replace the "md5" in the names to "sha1" or "sha512".

## Installation

Make sure to include AWFileHash.h where you want to use the lib.

### Cocoapods
AWFileHash is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

    pod "AWFileHash"

### Manual
Download the .zip, unpack it and draw the files "AWFileHash.{m,h}" into XCode. Make sure to add them to your target bundle also.

## TODO

* Add support for PHAsset (need to find a way to stream bytes to AWFileHash)
* Add md5 categories for NSString & NSData
* Add proper documentation
* Add more tests that conform to the standards

## Definitions

Specifications: 
* MD5: [http://www.ietf.org/rfc/rfc1321.txt]
* SHA1 & SHA512: [http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf] 

## Author

Alexander Widerberg, widerbergaren [at] gmail.com

## License

AWFileHash is available under the MIT license. See the LICENSE file for more info.
