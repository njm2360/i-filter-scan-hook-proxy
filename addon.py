import re
import httpx
import asyncio
from mitmproxy import ctx, http


def _patch_transfer_encoding() -> None:
    import mitmproxy.net.http.validate as _v

    _orig = _v.parse_transfer_encoding

    def _patched(value):
        raw = (
            value.decode("ascii", errors="replace")
            if isinstance(value, bytes)
            else value
        )
        normalized = re.sub(r"[\t ]*,[\t ]*", ",", raw.lower().strip())
        unique = list(dict.fromkeys(p for p in normalized.split(",") if p))
        deduplicated = ",".join(unique)
        if deduplicated in _v._HTTP_1_1_TRANSFER_ENCODINGS:
            return deduplicated
        return _orig(value)

    _v.parse_transfer_encoding = _patched


_patch_transfer_encoding()


POLL_INTERVAL_SEC = 5
MAX_WAIT_SEC = 180
IFILTER_CLIENT_KWARGS = dict(
    verify=False,
    trust_env=False,
    follow_redirects=True,
    timeout=30,
)

IFILTER_DISPOSITION = "i-FILTER-Scan-Result.html"
SCANNING_URL_SUFFIX = ".avsbscanning"
COMPLETE_MARKER = "解析が完了しました"


def _extract_scanning_url(html: str) -> str | None:
    match = re.search(
        r'<meta\s[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*URL=([^"\'>\s]+)',
        html,
        re.IGNORECASE,
    )
    if match:
        url = match.group(1).strip()
        if SCANNING_URL_SUFFIX in url:
            return url
    return None


def _extract_download_url(html: str) -> str | None:
    for match in re.finditer(
        r'href=["\']([^"\']+trickle\.cgi[^"\']+)["\']', html, re.IGNORECASE
    ):
        url = match.group(1)
        if SCANNING_URL_SUFFIX not in url:
            return url
    return None


async def _poll_and_download(scanning_url: str) -> tuple[bytes, httpx.Headers] | None:
    waited = 0
    async with httpx.AsyncClient(**IFILTER_CLIENT_KWARGS) as client:
        while waited < MAX_WAIT_SEC:
            try:
                resp = await client.get(scanning_url)
                html = resp.text

                if COMPLETE_MARKER in html:
                    download_url = _extract_download_url(html)
                    if download_url:
                        ctx.log.info(
                            f"[i-FILTER] Scan complete, Downloading: {download_url}"
                        )
                        dl = await client.get(download_url)
                        dl.raise_for_status()
                        return dl.content, dl.headers
                    ctx.log.warn("[i-FILTER] Can not get Download URL. Retry.")
                else:
                    ctx.log.info(
                        f"[i-FILTER] Scanning… ({waited}s / Max {MAX_WAIT_SEC}s)"
                    )

            except httpx.HTTPStatusError as e:
                ctx.log.error(
                    f"[i-FILTER] Download error (HTTP {e.response.status_code}): {e.request.url}"
                )
                return None
            except httpx.RequestError as e:
                ctx.log.warn(f"[i-FILTER] Scan result polling error: {repr(e)}")

            await asyncio.sleep(POLL_INTERVAL_SEC)
            waited += POLL_INTERVAL_SEC

    ctx.log.error(f"[i-FILTER] Timeout exceed ({MAX_WAIT_SEC}s): {scanning_url}")
    return None


class IFilterAddon:
    def responseheaders(self, flow: http.HTTPFlow) -> None:
        disposition = flow.response.headers.get("content-disposition", "")
        if IFILTER_DISPOSITION not in disposition:
            flow.response.stream = True

    async def response(self, flow: http.HTTPFlow) -> None:
        body = flow.response.get_text(strict=False)
        if body is None:
            return
        scanning_url = _extract_scanning_url(body)
        if not scanning_url:
            return

        ctx.log.info(
            f"[i-FILTER] Scan detect: {flow.request.pretty_url}\n"
            f"           Scan result URL: {scanning_url}"
        )

        result = await _poll_and_download(scanning_url)
        if not result:
            return

        file_bytes, headers = result
        detected_ct = headers.get("content-type", "application/octet-stream")

        flow.response.status_code = 200
        flow.response.headers["content-type"] = detected_ct
        flow.response.headers["content-disposition"] = headers.get(
            "content-disposition", ""
        )
        flow.response.headers.pop("transfer-encoding", None)
        flow.response.headers.pop("content-encoding", None)
        flow.response.content = file_bytes

        ctx.log.info(
            f"[i-FILTER] Response replace completed: {len(file_bytes):,} bytes ({detected_ct})"
        )


addons = [IFilterAddon()]
