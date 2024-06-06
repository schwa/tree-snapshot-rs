# tree-snapshot

A simple tool to take a snapshot of a directory tree and save it to a file.

The snapshot is a .csv file that is sorted by the path of each file in the directory tree. Each record in the output has fields for metadata and optionally a SHA256 hash of the file contents. Xattr metadata are also saved in the snapshot - and their contents are also hashed.

## Purpose

This tool is useful for creating a snapshot of a directory tree that can be used to compare against another snapshot to determine if any files have been added, removed, or changed.

## Installation

```sh
cargo install tree-snapshot
```

## Usage

```sh
tree-snapshot <directory> --output <output-file>
```

## License

MIT
