#!/usr/bin/env bash

THIS_MNT_DIR=/tmp/test_urlfs/httpmnt
THIS_CACHE_DIR=/tmp/test_urlfs/httpmntcache

mkdir -p "${THIS_MNT_DIR}"
mkdir -p "${THIS_CACHE_DIR}"

# set up the manifest
cat <<EOF > example_manifest.json
{
  "entries": [
    {
      "path": "docs/example.html",
      "url": "https://kernel.org/"
    },
    {
      "path": "static/robots.txt",
      "url": "https://www.robotstxt.org/robots.txt"
    },
    {
      "path": "data/sample.json",
      "url": "https://httpbin.org/json"
    }
  ]
}
EOF

# this is blocking
./urlfs.py example_manifest.json "${THIS_MNT_DIR}" --cache-dir "${THIS_CACHE_DIR}" --metadata-ttl 600

# so then in another shell, do:
find "${THIS_MNT_DIR}" -maxdepth 4 -type f | sort
cat "${THIS_MNT_DIR}"/static/robots.txt
head -c 200 "${THIS_MNT_DIR}"/docs/example.html
jq .slideshow.slides[0].title "${THIS_MNT_DIR}"/data/sample.json
find "${THIS_MNT_DIR}" -maxdepth 4 -exec ls -alh {} \;
tree -hug "${THIS_MNT_DIR}"

fusermount3 -u "${THIS_MNT_DIR}"