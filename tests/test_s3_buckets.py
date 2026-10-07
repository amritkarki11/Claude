"""s3_buckets: passive regex extraction, HEAD existence classification,
public-listing detection, and root-domain anchoring."""
import httpx

from agent.http import HttpClient
from agent.recon.s3_buckets import (
    discover_s3_buckets,
    extract_from_text,
    passive_candidates,
    permutations,
    probe_bucket,
    root_domain_name,
)

LISTING_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>leaky-bucket</Name></ListBucketResult>"
)
ACCESS_DENIED_XML = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<Error><Code>AccessDenied</Code></Error>"
)


# ---------- root domain anchoring ----------

def test_root_domain_strips_subdomains():
    assert root_domain_name("platform.stage.pureid.ai") == "pureid"
    assert root_domain_name("pureid.ai") == "pureid"
    assert root_domain_name("api.example.co.uk") == "example"


def test_permutations_are_the_curated_list():
    assert permutations("acme") == [
        "acme", "acme-dev", "acme-prod", "acme-staging", "acme-backup",
        "acme-assets", "acme-data", "acme-uploads", "acme-media",
        "acme-static", "acme-files", "acme-export",
    ]


# ---------- passive extraction ----------

def test_extract_vhost_style():
    assert extract_from_text("asset at https://acme-assets.s3.amazonaws.com/logo.png") == {"acme-assets"}


def test_extract_regional_vhost_style():
    text = "see acme-backups.s3.eu-west-1.amazonaws.com/dump.sql"
    assert extract_from_text(text) == {"acme-backups"}


def test_extract_path_style():
    text = 'fetch("https://s3.us-east-1.amazonaws.com/acme-uploads/file.csv")'
    assert extract_from_text(text) == {"acme-uploads"}


def test_passive_candidates_merges_and_dedupes_across_texts():
    texts = [
        "ref https://acme-assets.s3.amazonaws.com/a.js and acme-assets.s3.amazonaws.com/b.js again",
        "other acme-data.s3.ap-south-1.amazonaws.com/x",
        "no s3 refs here at all",
    ]
    assert passive_candidates(texts) == ["acme-assets", "acme-data"]


def test_passive_candidates_empty_when_no_refs():
    assert passive_candidates(["plain text", "", "still nothing"]) == []


# ---------- active probing: existence classification ----------

def _transport(statuses: dict[str, int], listing: dict[str, str] | None = None) -> httpx.MockTransport:
    listing = listing or {}

    def handler(req: httpx.Request) -> httpx.Response:
        name = req.url.host.split(".s3.amazonaws.com")[0]
        status = statuses.get(name, 404)
        if req.method == "HEAD":
            return httpx.Response(status)
        # GET: only reached for names probe_bucket already decided "exist"
        return httpx.Response(status, text=listing.get(name, ACCESS_DENIED_XML))

    return httpx.MockTransport(handler)


async def test_probe_bucket_classifies_200_403_404(tmp_path):
    statuses = {"exists-ok": 200, "exists-private": 403, "missing": 404}
    async with HttpClient(transport=_transport(statuses), log_path=tmp_path / "l.jsonl") as c:
        ok = await probe_bucket(c, "exists-ok")
        private = await probe_bucket(c, "exists-private")
        missing = await probe_bucket(c, "missing")

    assert ok["exists"] is True
    assert private["exists"] is True
    assert missing["exists"] is False
    assert "error" not in ok and "error" not in private and "error" not in missing


# ---------- active probing: public-listing detection ----------

async def test_probe_bucket_detects_public_listing(tmp_path):
    statuses = {"leaky-bucket": 200, "private-bucket": 200}
    listing = {"leaky-bucket": LISTING_XML, "private-bucket": ACCESS_DENIED_XML}
    async with HttpClient(transport=_transport(statuses, listing), log_path=tmp_path / "l.jsonl") as c:
        leaky = await probe_bucket(c, "leaky-bucket")
        private = await probe_bucket(c, "private-bucket")

    assert leaky["exists"] is True and leaky["public_listable"] is True
    assert private["exists"] is True and private["public_listable"] is False


async def test_probe_bucket_never_gets_a_nonexistent_bucket(tmp_path):
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.method)
        return httpx.Response(404)

    async with HttpClient(transport=httpx.MockTransport(handler), log_path=tmp_path / "l.jsonl") as c:
        probe = await probe_bucket(c, "nope")

    assert probe["exists"] is False and probe["public_listable"] is False
    assert calls == ["HEAD"]  # no GET fired for a 404


async def test_probe_bucket_reports_failure_not_silence(tmp_path):
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    async def boom(request):
        raise httpx.ConnectTimeout("timed out")

    async with HttpClient(transport=httpx.MockTransport(boom), log_path=tmp_path / "l.jsonl") as c:
        probe = await probe_bucket(c, "down")

    assert probe["exists"] is None
    assert probe["error"] == "ConnectTimeout"


# ---------- end-to-end merge ----------

async def test_discover_s3_buckets_merges_passive_and_active(tmp_path):
    texts = ["see https://acme-assets.s3.amazonaws.com/x.js"]
    statuses = {"acme-assets": 200, "acme": 403}
    listing = {"acme-assets": LISTING_XML}

    async with HttpClient(transport=_transport(statuses, listing), log_path=tmp_path / "l.jsonl") as c:
        result = await discover_s3_buckets(c, "platform.stage.acme.com", texts=texts)

    by_name = {b["name"]: b for b in result.buckets}
    assert by_name["acme-assets"]["source"] == "passive"
    assert by_name["acme-assets"]["exists"] is True
    assert by_name["acme-assets"]["public_listable"] is True
    assert by_name["acme"]["source"] == "active"
    assert by_name["acme"]["exists"] is True
    assert by_name["acme"]["public_listable"] is False
    assert by_name["acme-dev"]["exists"] is False  # not in `statuses` -> 404
    assert result.errors == []
    assert result.summary["confirmed"] == 2
    assert result.summary["public_listable"] == 1
