#!/usr/bin/env python3

import errno
import hashlib
import json
import logging
import os
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pyfuse3
import trio


log = logging.getLogger("httpfs")


def utc_now_ns() -> int:
    return time.time_ns()


def utc_now_s() -> int:
    return int(time.time())


def parse_http_datetime_ns(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return int(parsedate_to_datetime(value).timestamp() * 1_000_000_000)
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
    mtime_ns: Optional[int] = None
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    accept_ranges: bool = False
    content_type: Optional[str] = None
    fetched_at: int = field(default_factory=utc_now_s)


class Manifest:
    def __init__(self, manifest_path: str):
        self.manifest_path = manifest_path
        self.files: Dict[str, ManifestEntry] = {}
        self.directories: Set[str] = {"/"}
        self.children: Dict[str, List[str]] = {"/": []}
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
            self.children[path] = []

    def _add_child(self, parent: str, name: str) -> None:
        if name not in self.children[parent]:
            self.children[parent].append(name)
            self.children[parent].sort()

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

            normalized_headers = {}
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

    def entry_for(self, path: str) -> ManifestEntry:
        return self.files[path]

    def listdir(self, path: str) -> List[str]:
        return list(self.children.get(path, []))


class MetadataCache:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, HttpMetadata] = {}

    def get(self, path: str) -> Optional[HttpMetadata]:
        meta = self.cache.get(path)
        if not meta:
            return None
        if utc_now_s() - meta.fetched_at > self.ttl_seconds:
            return None
        return meta

    def peek(self, path: str) -> Optional[HttpMetadata]:
        return self.cache.get(path)

    def put(self, path: str, meta: HttpMetadata) -> None:
        meta.fetched_at = utc_now_s()
        self.cache[path] = meta


class DiskContentCache:
    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _key(self, path: str) -> str:
        return sha256_text(path)

    def data_path(self, path: str) -> str:
        return os.path.join(self.cache_dir, self._key(path) + ".bin")

    def meta_path(self, path: str) -> str:
        return os.path.join(self.cache_dir, self._key(path) + ".json")

    def has_data(self, path: str) -> bool:
        return os.path.exists(self.data_path(path))

    def read_slice(self, path: str, offset: int, size: int) -> bytes:
        with open(self.data_path(path), "rb") as f:
            f.seek(offset)
            return f.read(size)

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

    def begin_stream_write(self, path: str) -> str:
        dp = self.data_path(path)
        os.makedirs(os.path.dirname(dp), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix=os.path.basename(dp) + ".", suffix=".part", dir=os.path.dirname(dp)
        )
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
    USER_AGENT = "httpfs-pyfuse3/1.0"

    def _apply_headers(self, req: Request, headers: Optional[Dict[str, str]]) -> None:
        req.add_header("User-Agent", self.USER_AGENT)
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpMetadata:
        req = Request(url, method="HEAD")
        self._apply_headers(req, headers)
        with urlopen(req, timeout=20) as resp:
            h = resp.headers
            size = h.get("Content-Length")
            return HttpMetadata(
                size=int(size) if size and size.isdigit() else None,
                mtime_ns=parse_http_datetime_ns(h.get("Last-Modified")),
                etag=h.get("ETag"),
                last_modified=h.get("Last-Modified"),
                accept_ranges="bytes" in h.get("Accept-Ranges", "").lower(),
                content_type=h.get_content_type() if hasattr(h, "get_content_type") else h.get("Content-Type"),
            )

    def get_range(self, url: str, offset: int, size: int, headers: Optional[Dict[str, str]] = None) -> bytes:
        req = Request(url)
        self._apply_headers(req, headers)
        req.add_header("Range", f"bytes={offset}-{offset + size - 1}")
        with urlopen(req, timeout=60) as resp:
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
            resp = urlopen(req, timeout=120)
            return 200, resp
        except HTTPError as e:
            if e.code == 304:
                return 304, None
            raise


class InodeTable:
    def __init__(self, manifest: Manifest):
        self.path_to_inode: Dict[str, int] = {"/": pyfuse3.ROOT_INODE}
        self.inode_to_path: Dict[int, str] = {pyfuse3.ROOT_INODE: "/"}
        self.parent_inode: Dict[int, int] = {}
        self.name_bytes: Dict[int, bytes] = {}
        next_inode = pyfuse3.ROOT_INODE + 1

        all_paths = sorted(list(manifest.directories | set(manifest.files.keys())))
        for path in all_paths:
            if path == "/":
                continue
            ino = next_inode
            next_inode += 1
            self.path_to_inode[path] = ino
            self.inode_to_path[ino] = path

            parent = str(PurePosixPath(path).parent)
            if parent == ".":
                parent = "/"
            self.parent_inode[ino] = self.path_to_inode[parent]
            self.name_bytes[ino] = PurePosixPath(path).name.encode()

    def inode_for_path(self, path: str) -> int:
        return self.path_to_inode[path]

    def path_for_inode(self, inode: int) -> str:
        return self.inode_to_path[inode]


class HttpManifestFS(pyfuse3.Operations):
    enable_writeback_cache = False

    def __init__(self, manifest_path: str, cache_dir: str, metadata_ttl: int = 300, stream_chunk_size: int = 1024 * 1024):
        super().__init__()
        self.manifest = Manifest(manifest_path)
        self.inodes = InodeTable(self.manifest)
        self.metadata_cache = MetadataCache(metadata_ttl)
        self.content_cache = DiskContentCache(cache_dir)
        self.http = HTTPClient()
        self.dir_mtime_ns = utc_now_ns()
        self.stream_chunk_size = max(64 * 1024, int(stream_chunk_size))
        self._lookup_counts: Dict[int, int] = {}

    def _entry(self, path: str) -> ManifestEntry:
        return self.manifest.entry_for(path)

    def _metadata_from_cache_meta(self, meta: dict) -> HttpMetadata:
        return HttpMetadata(
            size=meta.get("size"),
            mtime_ns=meta.get("mtime_ns"),
            etag=meta.get("etag"),
            last_modified=meta.get("last_modified"),
            accept_ranges=meta.get("accept_ranges", False),
            content_type=meta.get("content_type"),
        )

    async def _get_metadata(self, path: str) -> HttpMetadata:
        cached = self.metadata_cache.get(path)
        if cached:
            return cached

        entry = self._entry(path)

        def do_head():
            return self.http.head(entry.url, headers=entry.headers)

        try:
            meta = await trio.to_thread.run_sync(do_head)
        except Exception:
            disk_meta = self.content_cache.load_meta(path)
            if disk_meta:
                meta = self._metadata_from_cache_meta(disk_meta)
            else:
                meta = HttpMetadata(size=None, mtime_ns=utc_now_ns(), accept_ranges=False)

        if meta.mtime_ns is None:
            meta.mtime_ns = utc_now_ns()

        self.metadata_cache.put(path, meta)
        return meta

    async def _stream_download_to_cache(self, path: str) -> None:
        entry = self._entry(path)
        old_meta = self.content_cache.load_meta(path)
        etag = old_meta.get("etag") if old_meta else None
        last_modified = old_meta.get("last_modified") if old_meta else None

        def open_response():
            return self.http.conditional_get(
                entry.url,
                headers=entry.headers,
                etag=etag,
                last_modified=last_modified,
            )

        try:
            status, resp = await trio.to_thread.run_sync(open_response)
        except Exception:
            if self.content_cache.has_data(path):
                return
            raise pyfuse3.FUSEError(errno.EIO)

        if status == 304:
            if old_meta:
                self.metadata_cache.put(path, self._metadata_from_cache_meta(old_meta))
            return

        if status != 200 or resp is None:
            if self.content_cache.has_data(path):
                return
            raise pyfuse3.FUSEError(errno.EIO)

        tmp_path = self.content_cache.begin_stream_write(path)

        def stream_to_disk():
            total = 0
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
                "mtime_ns": parse_http_datetime_ns(h.get("Last-Modified")) or utc_now_ns(),
                "etag": h.get("ETag"),
                "last_modified": h.get("Last-Modified"),
                "accept_ranges": "bytes" in h.get("Accept-Ranges", "").lower(),
                "content_type": h.get_content_type() if hasattr(h, "get_content_type") else h.get("Content-Type"),
            }
            return meta

        try:
            meta = await trio.to_thread.run_sync(stream_to_disk)
            self.content_cache.commit_stream_write(tmp_path, path)
            self.content_cache.save_meta(path, meta)
            self.metadata_cache.put(path, self._metadata_from_cache_meta(meta))
        except Exception:
            self.content_cache.remove_tmp(tmp_path)
            if self.content_cache.has_data(path):
                return
            raise pyfuse3.FUSEError(errno.EIO)

    def _entry_attributes(self, inode: int, path: str, meta: Optional[HttpMetadata] = None) -> pyfuse3.EntryAttributes:
        attr = pyfuse3.EntryAttributes()
        now_ns = utc_now_ns()

        attr.st_ino = inode
        attr.generation = 0
        attr.entry_timeout = 60.0
        attr.attr_timeout = 60.0
        attr.st_uid = os.getuid()
        attr.st_gid = os.getgid()
        attr.st_rdev = 0
        attr.st_blksize = 4096

        if self.manifest.is_dir(path):
            attr.st_mode = stat.S_IFDIR | 0o555
            attr.st_nlink = 2
            attr.st_size = 0
            attr.st_blocks = 0
            attr.st_atime_ns = now_ns
            attr.st_mtime_ns = self.dir_mtime_ns
            attr.st_ctime_ns = self.dir_mtime_ns
            return attr

        if meta is None:
            meta = HttpMetadata(size=0, mtime_ns=now_ns)

        size = meta.size or 0
        mtime_ns = meta.mtime_ns or now_ns
        attr.st_mode = stat.S_IFREG | 0o444
        attr.st_nlink = 1
        attr.st_size = size
        attr.st_blocks = (size + 511) // 512
        attr.st_atime_ns = now_ns
        attr.st_mtime_ns = mtime_ns
        attr.st_ctime_ns = mtime_ns
        return attr

    async def lookup(self, parent_inode: int, name: bytes, ctx=None) -> pyfuse3.EntryAttributes:
        parent_path = self.inodes.path_for_inode(parent_inode)
        child_path = str(PurePosixPath(parent_path) / name.decode()) if parent_path != "/" else "/" + name.decode()

        if not self.manifest.is_file(child_path) and not self.manifest.is_dir(child_path):
            raise pyfuse3.FUSEError(errno.ENOENT)

        inode = self.inodes.inode_for_path(child_path)
        self._lookup_counts[inode] = self._lookup_counts.get(inode, 0) + 1

        meta = await self._get_metadata(child_path) if self.manifest.is_file(child_path) else None
        return self._entry_attributes(inode, child_path, meta)

    async def getattr(self, inode: int, ctx=None) -> pyfuse3.EntryAttributes:
        path = self.inodes.path_for_inode(inode)
        meta = await self._get_metadata(path) if self.manifest.is_file(path) else None
        return self._entry_attributes(inode, path, meta)

    async def opendir(self, inode: int, ctx):
        path = self.inodes.path_for_inode(inode)
        if not self.manifest.is_dir(path):
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        return inode

    async def readdir(self, fh: int, start_id: int, token: pyfuse3.ReaddirToken):
        path = self.inodes.path_for_inode(fh)
        entries = self.manifest.listdir(path)

        for idx, name in enumerate(entries[start_id:], start=start_id + 1):
            child_path = str(PurePosixPath(path) / name) if path != "/" else "/" + name
            inode = self.inodes.inode_for_path(child_path)
            meta = await self._get_metadata(child_path) if self.manifest.is_file(child_path) else None
            attr = self._entry_attributes(inode, child_path, meta)
            if not pyfuse3.readdir_reply(token, name.encode(), attr, idx):
                return

    async def open(self, inode: int, flags: int, ctx) -> pyfuse3.FileInfo:
        path = self.inodes.path_for_inode(inode)
        if not self.manifest.is_file(path):
            raise pyfuse3.FUSEError(errno.EISDIR)

        accmode = flags & os.O_ACCMODE
        if accmode != os.O_RDONLY:
            raise pyfuse3.FUSEError(errno.EROFS)

        fi = pyfuse3.FileInfo(fh=inode)
        fi.keep_cache = False
        fi.direct_io = False
        return fi

    async def read(self, fh: int, off: int, size: int) -> bytes:
        path = self.inodes.path_for_inode(fh)
        entry = self._entry(path)
        meta = await self._get_metadata(path)

        if meta.accept_ranges:
            def do_range():
                return self.http.get_range(entry.url, off, size, headers=entry.headers)

            try:
                return await trio.to_thread.run_sync(do_range)
            except Exception:
                pass

        if not self.content_cache.has_data(path):
            await self._stream_download_to_cache(path)

        disk_meta = self.content_cache.load_meta(path)
        if disk_meta:
            self.metadata_cache.put(path, self._metadata_from_cache_meta(disk_meta))

        def do_read():
            return self.content_cache.read_slice(path, off, size)

        return await trio.to_thread.run_sync(do_read)

    async def access(self, inode: int, mode: int, ctx) -> bool:
        if mode & os.W_OK:
            raise pyfuse3.FUSEError(errno.EROFS)
        return True

    async def release(self, fh: int) -> None:
        return

    async def releasedir(self, fh: int) -> None:
        return

    async def forget(self, inode_list):
        for item in inode_list:
            inode = item.inode
            nlookup = item.nlookup
            cur = self._lookup_counts.get(inode, 0)
            new = max(0, cur - nlookup)
            if new == 0:
                self._lookup_counts.pop(inode, None)
            else:
                self._lookup_counts[inode] = new

    async def statfs(self, ctx) -> pyfuse3.StatvfsData:
        st = pyfuse3.StatvfsData()
        st.f_bsize = 4096
        st.f_frsize = 4096
        st.f_blocks = 0
        st.f_bfree = 0
        st.f_bavail = 0
        st.f_files = len(self.manifest.files) + len(self.manifest.directories)
        st.f_ffree = 0
        st.f_favail = 0
        st.f_namemax = 255
        return st


def default_cache_dir() -> str:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return os.path.join(xdg, "httpfs-pyfuse3")
    return os.path.join(os.path.expanduser("~"), ".cache", "httpfs-pyfuse3")


def parse_args(argv):
    if len(argv) < 3:
        raise SystemExit(
            f"Usage: {argv[0]} <manifest.json> <mountpoint> [--cache-dir DIR] [--metadata-ttl SECONDS] [--stream-chunk-size BYTES]"
        )

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


async def main():
    logging.basicConfig(level=logging.INFO)

    manifest_path, mountpoint, cache_dir, metadata_ttl, stream_chunk_size = parse_args(sys.argv)

    operations = HttpManifestFS(
        manifest_path=manifest_path,
        cache_dir=cache_dir,
        metadata_ttl=metadata_ttl,
        stream_chunk_size=stream_chunk_size,
    )

    fuse_options = set(pyfuse3.default_options)
    fuse_options.add("fsname=http_manifest_pyfuse3")
    fuse_options.add("ro")

    pyfuse3.init(operations, mountpoint, fuse_options)
    try:
        await pyfuse3.main()
    finally:
        pyfuse3.close(unmount=True)


if __name__ == "__main__":
    trio.run(main)