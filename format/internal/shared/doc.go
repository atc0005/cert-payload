// Package shared is an internal package that provides common/shared utility
// code for all payload format versions. This code is not intended for
// external use and no guarantees are made for compatibility between library
// releases.
package shared

// Q: Rename package to `assert` ?
//
// A: Probably not. While `shared` is not a great package name as a
// measurement against best practices, it works well here since we're sharing
// common logic (as much as we can) between different format versions.
