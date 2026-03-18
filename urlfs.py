#!/usr/bin/env python3

import errno
import hashlib
import json
import mimetypes
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import PurePosixPath
from typing import Dict, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fuse import FUSE, FuseOSError, Operations


def utc_now() -> int:
    return int(time.time())


def parse_http_datetime(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(parsedate_to_datetime(value).timestamp())
    except Exception:
        return None


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class ManifestEntry:
    path: str
    url: str


@dataclass
class HttpMetadata:
    size: Optional[int] = None
    mtime: Optional[int] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    accept_ranges: bool = False
    content_type: Optional[str] = None
    fetched_at: int = field(default_factory=utc_now)


class Manifest:
    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path
        self.files: Dict[str, ManifestEntry] = {}
        self.directories: Set[str] = {"/"}
        self.children: Dict[str, Set[str]] = {"/": set()}
        self._load()

    def _normalize_file_path(self, path: str) -> str:
        p = PurePosixPath("/" + path.lstrip("/"))
        norm = str(p)
        if norm == "/":
            raise ValueError("file path cannot be root")
        return norm

    def _ensure_dir(self, path: str) -> None:
        if path not in self.directories:
            self.directories.add(path)
            self.children.setdefault(path, set())

    def _add_child(self, parent: str, name: str) -> None:
        self.children.setdefault(parent, set()).add(name)

    def _load(self) -> None:
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        entries = raw.get("entries")
        if not isinstance(entries, list):
            raise ValueError("manifest must contain an 'entries' list")

        for item in entries:
            if not isinstance(item, dict):
                raise ValueError("each manifest entry must be an object")
            path = item.get("path")
            url = item.get("url")
            if not path or not url:
                raise ValueError("each entry must include 'path' and 'url'")

            norm_path = self._normalize_file_path(path)
            if norm_path in self.files:
                raise ValueError(f"duplicate manifest path: {norm_path}")

            self.files[norm_path] = ManifestEntry(path=norm_path, url=url)

            parts = PurePosixPath(norm_path).parts
            current = "/"
            for part in parts[1:-1]:
                next_dir = current.rstrip("/") + "/" + part if current != "/" else "/" + part
                self._ensure_dir(next_dir)
                self._add_child(current, part)
                current = next_dir

            parent = str(PurePosixPath(norm_path).parent)
            if parent == ".":
                parent = "/"
            self._ensure_dir(parent)
            self._add_child(parent, PurePosixPath(norm_path).name)

    def is_file(self, path: str) -> bool:
        return path in self.files

    def is_dir(self, path: str) -> bool:
        return path in self.directories

    def listdir(self, path: str):
        if path not in self.directories:
            raise KeyError(path)
        return sorted(self.children.get(path, set()))

    def url_for(self, path: str) -> str:
        return self.files[path].url


class MetadataCache:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, HttpMetadata] = {}

    def get(self, path: str) -> Optional[HttpMetadata]:
        meta = self.cache.get(path)
        if not meta:
            return None
        if utc_now() - meta.fetched_at > self.ttl_seconds:
            return None
        return meta

    def put(self, path: str, meta: HttpMetadata) -> None:
        meta.fetched_at = utc_now()
        self.cache[path] = meta

    def peek(self, path: str) -> Optional[HttpMetadata]:
        return self.cache.get(path)


class ContentCache:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _data_path(self, path: str) -> str:
        key = sha256_text(path)
        return os.path.join(self.cache_dir, key + ".bin")

    def _meta_path(self, path: str) -> str:
        key = sha256_text(path)
        return os.path.join(self.cache_dir, key + ".json")

    def load(self, path: str) -> Tuple[Optional[bytes], Optional[dict]]:
        data_path = self._data_path(path)
        meta_path = self._meta_path(path)
        if not (os.path.exists(data_path) and os.path.exists(meta_path)):
            return None, None
        try:
            with open(data_path, "rb") as f:
                data = f.read()
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            return data, meta
        except Exception:
            return None, None

    def save(self, path: str, data: bytes, meta: dict) -> None:
        data_path = self._data_path(path)
        meta_path = self._meta_path(path)
        tmp_data = data_path + ".tmp"
        tmp_meta = meta_path + ".tmp"

        with open(tmp_data, "wb") as f:
            f.write(data)
        with open(tmp_meta, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        os.replace(tmp_data, data_path)
        os.replace(tmp_meta, meta_path)


class HTTPClient:
    USER_AGENT = "httpfs-fuse/1.0"

    def _open(self, req: Request, timeout: int = 30):
        req.add_header("User-Agent", self.USER_AGENT)
        return urlopen(req, timeout=timeout)

    def head(self, url: str) -> HttpMetadata:
        req = Request(url, method="HEAD")
        with self._open(req, timeout=15) as resp:
            headers = resp.headers
            size = headers.get("Content-Length")
            return HttpMetadata(
                size=int(size) if size and size.isdigit() else None,
                mtime=parse_http_datetime(headers.get("Last-Modified")),
                etag=headers.get("ETag"),
                last_modified=headers.get("Last-Modified"),
                accept_ranges="bytes" in headers.get("Accept-Ranges", "").lower(),
                content_type=headers.get_content_type() if hasattr(headers, "get_content_type") else headers.get("Content-Type"),
            )

    def get_range(self, url: str, offset: int, size: int) -> bytes:
        end = offset + size - 1
        req = Request(url)
        req.add_header("Range", f"bytes={offset}-{end}")
        with self._open(req, timeout=30) as resp:
            return resp.read()

    def get_full(self, url: str, etag: Optional[str] = None, last_modified: Optional[str] = None):
        req = Request(url)
        if etag:
            req.add_header("If-None-Match", etag)
        if last_modified:
            req.add_header("If-Modified-Since", last_modified)

        try:
            with self._open(req, timeout=60) as resp:
                headers = resp.headers
                data = resp.read()
                meta = HttpMetadata(
                    size=len(data),
                    mtime=parse_http_datetime(headers.get("Last-Modified")),
                    etag=headers.get("ETag"),
                    last_modified=headers.get("Last-Modified"),
                    accept_ranges="bytes" in headers.get("Accept-Ranges", "").lower(),
                    content_type=headers.get_content_type() if hasattr(headers, "get_content_type") else headers.get("Content-Type"),
                )
                return 200, data, meta
        except HTTPError as e:
            if e.code == 304:
                return 304, None, None
            raise


class HttpManifestFS(Operations):
    def __init__(
        self,
        manifest_path: str,
        cache_dir: str,
        metadata_ttl: int = 300,
        dir_mtime: Optional[int] = None,
    ):
        self.manifest = Manifest(manifest_path)
        self.metadata_cache = MetadataCache(ttl_seconds=metadata_ttl)
        self.content_cache = ContentCache(cache_dir=cache_dir)
        self.http = HTTPClient()
        self.fd = 0
        self.dir_mode = stat.S_IFDIR | 0o555
        self.file_mode = stat.S_IFREG | 0o444
        self.dir_mtime = dir_mtime or utc_now()

    def _norm(self, path: str) -> str:
        p = str(PurePosixPath("/" + path.lstrip("/")))
        return p

    def _assert_exists(self, path: str) -> None:
        if not self.manifest.is_file(path) and not self.manifest.is_dir(path):
            raise FuseOSError(errno.ENOENT)

    def _guess_mtime(self, path: str) -> int:
        meta = self.metadata_cache.peek(path)
        if meta and meta.mtime:
            return meta.mtime
        return utc_now()

    def _get_metadata(self, path: str) -> HttpMetadata:
        cached = self.metadata_cache.get(path)
        if cached:
            return cached

        url = self.manifest.url_for(path)
        try:
            meta = self.http.head(url)
        except Exception:
            old = self.metadata_cache.peek(path)
            if old:
                return old
            meta = HttpMetadata(size=None, mtime=utc_now(), accept_ranges=False)

        if meta.mtime is None:
            meta.mtime = utc_now()

        self.metadata_cache.put(path, meta)
        return meta

    def _refresh_full_content_if_needed(self, path: str) -> bytes:
        url = self.manifest.url_for(path)
        cached_data, cached_meta = self.content_cache.load(path)

        etag = cached_meta.get("etag") if cached_meta else None
        last_modified = cached_meta.get("last_modified") if cached_meta else None

        try:
            status, data, meta = self.http.get_full(url, etag=etag, last_modified=last_modified)
            if status == 304 and cached_data is not None and cached_meta is not None:
                self.metadata_cache.put(
                    path,
                    HttpMetadata(
                        size=cached_meta.get("size"),
                        mtime=cached_meta.get("mtime"),
                        etag=cached_meta.get("etag"),
                        last_modified=cached_meta.get("last_modified"),
                        accept_ranges=cached_meta.get("accept_ranges", False),
                        content_type=cached_meta.get("content_type"),
                    ),
                )
                return cached_data

            if status == 200 and data is not None and meta is not None:
                if meta.mtime is None:
                    meta.mtime = utc_now()

                self.content_cache.save(
                    path,
                    data,
                    {
                        "size": meta.size,
                        "mtime": meta.mtime,
                        "etag": meta.etag,
                        "last_modified": meta.last_modified,
                        "accept_ranges": meta.accept_ranges,
                        "content_type": meta.content_type,
                    },
                )
                self.metadata_cache.put(path, meta)
                return data
        except Exception:
            if cached_data is not None:
                return cached_data
            raise FuseOSError(errno.EIO)

        if cached_data is not None:
            return cached_data

        raise FuseOSError(errno.EIO)

    def getattr(self, path, fh=None):
        path = self._norm(path)
        self._assert_exists(path)

        if self.manifest.is_dir(path):
            return {
                "st_mode": self.dir_mode,
                "st_nlink": 2,
                "st_size": 0,
                "st_ctime": self.dir_mtime,
                "st_mtime": self.dir_mtime,
                "st_atime": utc_now(),
            }

        meta = self._get_metadata(path)
        return {
            "st_mode": self.file_mode,
            "st_nlink": 1,
            "st_size": meta.size or 0,
            "st_ctime": meta.mtime or utc_now(),
            "st_mtime": meta.mtime or utc_now(),
            "st_atime": utc_now(),
        }

    def readdir(self, path, fh):
        path = self._norm(path)
        if not self.manifest.is_dir(path):
            raise FuseOSError(errno.ENOENT)
        return [".", "..", *self.manifest.listdir(path)]

    def open(self, path, flags):
        path = self._norm(path)
        if not self.manifest.is_file(path):
            raise FuseOSError(errno.EISDIR if self.manifest.is_dir(path) else errno.ENOENT)

        access_mode = flags & os.O_ACCMODE
        if access_mode != os.O_RDONLY:
            raise FuseOSError(errno.EROFS)

        self.fd += 1
        return self.fd

    def read(self, path, size, offset, fh):
        path = self._norm(path)
        if not self.manifest.is_file(path):
            raise FuseOSError(errno.ENOENT)

        if size <= 0:
            return b""

        meta = self._get_metadata(path)
        url = self.manifest.url_for(path)

        if meta.accept_ranges:
            try:
                return self.http.get_range(url, offset, size)
            except HTTPError:
                pass
            except URLError:
                pass
            except Exception:
                pass

        data = self._refresh_full_content_if_needed(path)
        return data[offset:offset + size]

    def access(self, path, mode):
        path = self._norm(path)
        self._assert_exists(path)

        if mode & os.W_OK:
            raise FuseOSError(errno.EROFS)
        return 0

    def readlink(self, path):
        raise FuseOSError(errno.EINVAL)

    def statfs(self, path):
        return {
            "f_bsize": 4096,
            "f_frsize": 4096,
            "f_blocks": 0,
            "f_bfree": 0,
            "f_bavail": 0,
            "f_files": len(self.manifest.files) + len(self.manifest.directories),
            "f_ffree": 0,
            "f_favail": 0,
            "f_flag": os.ST_RDONLY if hasattr(os, "ST_RDONLY") else 1,
            "f_namemax": 255,
        }

    def write(self, path, data, offset, fh):
        raise FuseOSError(errno.EROFS)

    def truncate(self, path, length, fh=None):
        raise FuseOSError(errno.EROFS)

    def create(self, path, mode, fi=None):
        raise FuseOSError(errno.EROFS)

    def unlink(self, path):
        raise FuseOSError(errno.EROFS)

    def mkdir(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def rmdir(self, path):
        raise FuseOSError(errno.EROFS)

    def rename(self, old, new):
        raise FuseOSError(errno.EROFS)

    def chmod(self, path, mode):
        raise FuseOSError(errno.EROFS)

    def chown(self, path, uid, gid):
        raise FuseOSError(errno.EROFS)

    def utimens(self, path, times=None):
        raise FuseOSError(errno.EROFS)

    def flush(self, path, fh):
        return 0

    def release(self, path, fh):
        return 0

    def fsync(self, path, fdatasync, fh):
        return 0


def default_cache_dir() -> str:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return os.path.join(xdg, "httpfs-fuse")
    return os.path.join(os.path.expanduser("~"), ".cache", "httpfs-fuse")


def usage(argv0: str) -> None:
    print(
        f"Usage: {argv0} <manifest.json> <mountpoint> [--cache-dir DIR] [--metadata-ttl SECONDS]",
        file=sys.stderr,
    )


def parse_args(argv):
    if len(argv) < 3:
        usage(argv[0])
        sys.exit(1)

    manifest_path = argv[1]
    mountpoint = argv[2]
    cache_dir = default_cache_dir()
    metadata_ttl = 300

    i = 3
    while i < len(argv):
        arg = argv[i]
        if arg == "--cache-dir":
            i += 1
            if i >= len(argv):
                raise SystemExit("--cache-dir requires a value")
            cache_dir = argv[i]
        elif arg == "--metadata-ttl":
            i += 1
            if i >= len(argv):
                raise SystemExit("--metadata-ttl requires a value")
            metadata_ttl = int(argv[i])
        else:
            raise SystemExit(f"unknown argument: {arg}")
        i += 1

    return manifest_path, mountpoint, cache_dir, metadata_ttl


def main():
    manifest_path, mountpoint, cache_dir, metadata_ttl = parse_args(sys.argv)

    fs = HttpManifestFS(
        manifest_path=manifest_path,
        cache_dir=cache_dir,
        metadata_ttl=metadata_ttl,
    )

    FUSE(
        fs,
        mountpoint,
        foreground=True,
        ro=True,
        nothreads=True,
    )


if __name__ == "__main__":
    main()