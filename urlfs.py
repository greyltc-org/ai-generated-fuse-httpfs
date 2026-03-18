#!/usr/bin/env python3

import errno
import hashlib
import json
import os
import stat
import sys
import tempfile
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
    headers: Dict[str, str] = field(default_factory=dict)


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
            headers = item.get("headers", {})

            if not path or not url:
                raise ValueError("each entry must include 'path' and 'url'")
            if not isinstance(headers, dict):
                raise ValueError(f"headers for {path!r} must be an object")

            normalized_headers: Dict[str, str] = {}
            for k, v in headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise ValueError(f"headers for {path!r} must be string:string")
                normalized_headers[k] = v

            norm_path = self._normalize_file_path(path)
            if norm_path in self.files:
                raise ValueError(f"duplicate manifest path: {norm_path}")

            self.files[norm_path] = ManifestEntry(
                path=norm_path,
                url=url,
                headers=normalized_headers,
            )

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

    def entry_for(self, path: str) -> ManifestEntry:
        return self.files[path]


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


class DiskContentCache:
    """
    Stores each file as:
      <key>.bin   full downloaded content
      <key>.json  associated metadata
    """
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _key(self, path: str) -> str:
        return sha256_text(path)

    def data_path(self, path: str) -> str:
        return os.path.join(self.cache_dir, self._key(path) + ".bin")

    def meta_path(self, path: str) -> str:
        return os.path.join(self.cache_dir, self._key(path) + ".json")

    def load_meta(self, path: str) -> Optional[dict]:
        mp = self.meta_path(path)
        if not os.path.exists(mp):
            return None
        try:
            with open(mp, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def save_meta(self, path: str, meta: dict) -> None:
        mp = self.meta_path(path)
        tmp = mp + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f)
        os.replace(tmp, mp)

    def has_data(self, path: str) -> bool:
        return os.path.exists(self.data_path(path))

    def read_slice(self, path: str, offset: int, size: int) -> bytes:
        dp = self.data_path(path)
        with open(dp, "rb") as f:
            f.seek(offset)
            return f.read(size)

    def begin_stream_write(self, path: str) -> str:
        dp = self.data_path(path)
        parent = os.path.dirname(dp)
        os.makedirs(parent, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=os.path.basename(dp) + ".", suffix=".part", dir=parent)
        os.close(fd)
        return tmp_path

    def commit_stream_write(self, tmp_path: str, path: str) -> None:
        os.replace(tmp_path, self.data_path(path))

    def remove_tmp(self, tmp_path: str) -> None:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass


class HTTPClient:
    USER_AGENT = "httpfs-fuse/2.0"

    def _apply_headers(self, req: Request, headers: Optional[Dict[str, str]]) -> None:
        req.add_header("User-Agent", self.USER_AGENT)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

    def _open(self, req: Request, timeout: int = 30):
        return urlopen(req, timeout=timeout)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpMetadata:
        req = Request(url, method="HEAD")
        self._apply_headers(req, headers)
        with self._open(req, timeout=20) as resp:
            h = resp.headers
            size = h.get("Content-Length")
            return HttpMetadata(
                size=int(size) if size and size.isdigit() else None,
                mtime=parse_http_datetime(h.get("Last-Modified")),
                etag=h.get("ETag"),
                last_modified=h.get("Last-Modified"),
                accept_ranges="bytes" in h.get("Accept-Ranges", "").lower(),
                content_type=h.get_content_type() if hasattr(h, "get_content_type") else h.get("Content-Type"),
            )

    def get_range(self, url: str, offset: int, size: int, headers: Optional[Dict[str, str]] = None) -> bytes:
        end = offset + size - 1
        req = Request(url)
        self._apply_headers(req, headers)
        req.add_header("Range", f"bytes={offset}-{end}")
        with self._open(req, timeout=60) as resp:
            return resp.read()

    def conditional_get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ):
        req = Request(url)
        self._apply_headers(req, headers)
        if etag:
            req.add_header("If-None-Match", etag)
        if last_modified:
            req.add_header("If-Modified-Since", last_modified)

        try:
            resp = self._open(req, timeout=120)
            return 200, resp
        except HTTPError as e:
            if e.code == 304:
                return 304, None
            raise


class HttpManifestFS(Operations):
    def __init__(
        self,
        manifest_path: str,
        cache_dir: str,
        metadata_ttl: int = 300,
        stream_chunk_size: int = 1024 * 1024,
    ):
        self.manifest = Manifest(manifest_path)
        self.metadata_cache = MetadataCache(ttl_seconds=metadata_ttl)
        self.content_cache = DiskContentCache(cache_dir=cache_dir)
        self.http = HTTPClient()
        self.fd = 0
        self.dir_mode = stat.S_IFDIR | 0o555
        self.file_mode = stat.S_IFREG | 0o444
        self.dir_mtime = utc_now()
        self.stream_chunk_size = max(64 * 1024, int(stream_chunk_size))

    def _norm(self, path: str) -> str:
        return str(PurePosixPath("/" + path.lstrip("/")))

    def _assert_exists(self, path: str) -> None:
        if not self.manifest.is_file(path) and not self.manifest.is_dir(path):
            raise FuseOSError(errno.ENOENT)

    def _entry(self, path: str) -> ManifestEntry:
        return self.manifest.entry_for(path)

    def _metadata_from_cache_meta(self, meta: dict) -> HttpMetadata:
        return HttpMetadata(
            size=meta.get("size"),
            mtime=meta.get("mtime"),
            etag=meta.get("etag"),
            last_modified=meta.get("last_modified"),
            accept_ranges=meta.get("accept_ranges", False),
            content_type=meta.get("content_type"),
        )

    def _get_metadata(self, path: str) -> HttpMetadata:
        cached = self.metadata_cache.get(path)
        if cached:
            return cached

        entry = self._entry(path)
        try:
            meta = self.http.head(entry.url, headers=entry.headers)
        except Exception:
            disk_meta = self.content_cache.load_meta(path)
            if disk_meta:
                meta = self._metadata_from_cache_meta(disk_meta)
            else:
                meta = HttpMetadata(size=None, mtime=utc_now(), accept_ranges=False)

        if meta.mtime is None:
            meta.mtime = utc_now()

        self.metadata_cache.put(path, meta)
        return meta

    def _stream_download_to_cache(self, path: str) -> None:
        entry = self._entry(path)
        old_meta = self.content_cache.load_meta(path)

        etag = old_meta.get("etag") if old_meta else None
        last_modified = old_meta.get("last_modified") if old_meta else None

        try:
            status, resp = self.http.conditional_get(
                entry.url,
                headers=entry.headers,
                etag=etag,
                last_modified=last_modified,
            )
        except Exception:
            if self.content_cache.has_data(path):
                return
            raise FuseOSError(errno.EIO)

        if status == 304:
            if old_meta:
                self.metadata_cache.put(path, self._metadata_from_cache_meta(old_meta))
            return

        if status != 200 or resp is None:
            if self.content_cache.has_data(path):
                return
            raise FuseOSError(errno.EIO)

        tmp_path = self.content_cache.begin_stream_write(path)
        total = 0
        try:
            with resp:
                h = resp.headers
                with open(tmp_path, "wb") as out:
                    while True:
                        chunk = resp.read(self.stream_chunk_size)
                        if not chunk:
                            break
                        out.write(chunk)
                        total += len(chunk)

                meta = {
                    "size": total,
                    "mtime": parse_http_datetime(h.get("Last-Modified")) or utc_now(),
                    "etag": h.get("ETag"),
                    "last_modified": h.get("Last-Modified"),
                    "accept_ranges": "bytes" in h.get("Accept-Ranges", "").lower(),
                    "content_type": h.get_content_type() if hasattr(h, "get_content_type") else h.get("Content-Type"),
                }

            self.content_cache.commit_stream_write(tmp_path, path)
            self.content_cache.save_meta(path, meta)
            self.metadata_cache.put(path, self._metadata_from_cache_meta(meta))
        except Exception:
            self.content_cache.remove_tmp(tmp_path)
            if self.content_cache.has_data(path):
                return
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

        entry = self._entry(path)
        meta = self._get_metadata(path)

        if meta.accept_ranges:
            try:
                return self.http.get_range(
                    entry.url,
                    offset,
                    size,
                    headers=entry.headers,
                )
            except HTTPError:
                pass
            except URLError:
                pass
            except Exception:
                pass

        if not self.content_cache.has_data(path):
            self._stream_download_to_cache(path)

        disk_meta = self.content_cache.load_meta(path)
        if disk_meta:
            current_meta = self._metadata_from_cache_meta(disk_meta)
            self.metadata_cache.put(path, current_meta)

        return self.content_cache.read_slice(path, offset, size)

    def access(self, path, mode):
        path = self._norm(path)
        self._assert_exists(path)
        if mode & os.W_OK:
            raise FuseOSError(errno.EROFS)
        return 0

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
        f"Usage: {argv0} <manifest.json> <mountpoint> [--cache-dir DIR] [--metadata-ttl SECONDS] [--stream-chunk-size BYTES]",
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
    stream_chunk_size = 1024 * 1024

    i = 3
    while i < len(argv):
        arg = argv[i]
        if arg == "--cache-dir":
            i += 1
            cache_dir = argv[i]
        elif arg == "--metadata-ttl":
            i += 1
            metadata_ttl = int(argv[i])
        elif arg == "--stream-chunk-size":
            i += 1
            stream_chunk_size = int(argv[i])
        else:
            raise SystemExit(f"unknown argument: {arg}")
        i += 1

    return manifest_path, mountpoint, cache_dir, metadata_ttl, stream_chunk_size


def main():
    manifest_path, mountpoint, cache_dir, metadata_ttl, stream_chunk_size = parse_args(sys.argv)

    fs = HttpManifestFS(
        manifest_path=manifest_path,
        cache_dir=cache_dir,
        metadata_ttl=metadata_ttl,
        stream_chunk_size=stream_chunk_size,
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
